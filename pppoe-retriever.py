#!/usr/bin/env python3


import logging
import random
from argparse import ArgumentParser, ArgumentTypeError
from typing import Any, Optional

from rich import print
from rich.align import Align
from rich.console import Console
from rich.padding import Padding as RichPadding
from rich.panel import Panel
from rich.text import Text
from scapy.all import (
    PPP,
    Dot1Q,
    Ether,
    Padding,
    PPP_LCP_Auth_Protocol_Option,
    PPP_LCP_Configure,
    PPP_PAP_Request,
    PPPoE,
    PPPoED,
    PPPoED_Tags,
    PPPoETag,
    RandString,
    get_if_hwaddr,
    sendp,
    sniff,
)

__version__ = "1.2.0"

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)


class Retriever:
    # PPPoE Discovery Codes (RFC 2516)
    CODE_PADI = 9
    CODE_PADO = 7
    CODE_PADR = 25
    CODE_PADS = 101
    CODE_PADT = 167

    # PPPoE Tag Types (RFC 2516)
    TAG_SERVICE_NAME = 257
    TAG_AC_NAME = 258
    TAG_HOST_UNIQ = 259
    TAG_AC_COOKIE = 260

    @classmethod
    def _code_name(cls, code: int) -> str:
        """Get human-readable name for PPPoE discovery code."""
        names = {
            cls.CODE_PADI: "PADI",
            cls.CODE_PADO: "PADO",
            cls.CODE_PADR: "PADR",
            cls.CODE_PADS: "PADS",
            cls.CODE_PADT: "PADT",
        }
        return names.get(code, f"Unknown({code})")

    def __init__(
        self,
        interface: str,
        vlan: Optional[int],
        search_range: int,
        verbose: bool = False,
        timeout: Optional[int] = None,
    ) -> None:
        self.interface = interface
        self.vlan = vlan
        self.username: Optional[str] = None
        self.password: Optional[str] = None
        self.generated_host_unique: Optional[bytes] = None
        self.verbose = verbose
        self.vlan_dict = {i: i.to_bytes(16, "big") for i in range(search_range)}

        if self.verbose:
            logger.info(f"Starting capture on interface: {interface}")
            logger.info(f"VLAN: {vlan if vlan else 'auto-discover'}")
            logger.info(f"Search range: {search_range}")

        sniff(
            prn=self.handle_eth_frame,
            iface=self.interface,
            lfilter=lambda pkg: pkg.haslayer(PPP) or pkg.haslayer(PPPoED),
            stop_filter=lambda pkg: pkg.haslayer(PPP_PAP_Request),
            store=0,
            timeout=timeout,
        )

    def handle_eth_frame(self, packet: Any) -> None:
        """Handle incoming Ethernet frames and process PPPoE packets."""
        if PPPoED in packet:
            code = packet[PPPoED].code
            code_name = self._code_name(code)

            if self.verbose:
                vlan = packet[Dot1Q].vlan if Dot1Q in packet else "none"
                logger.info(f"Received PPPoE packet: {code_name} (VLAN: {vlan})")

            # If PADI packet reply with PADO
            if code == self.CODE_PADI:
                if self.verbose:
                    logger.info("Sending PADO response(s)...")
                if self.vlan:
                    self.send_pado_packet(
                        packet, self.interface, self.vlan, bytes(RandString(16))
                    )
                else:
                    for vlan_id, ac_cookie in self.vlan_dict.items():
                        self.send_pado_packet(
                            packet, self.interface, vlan_id, ac_cookie
                        )

            # If PADR packet reply with PADS
            if code == self.CODE_PADR:
                if self.verbose:
                    logger.info("Received PADR, sending PADS...")
                response_ac_cookie = ""
                for tag in packet[PPPoED_Tags].tag_list:
                    if tag.tag_type == self.TAG_AC_COOKIE:
                        response_ac_cookie = tag.tag_value
                for vlan_id, ac_cookie in self.vlan_dict.items():
                    if bytes(ac_cookie) == response_ac_cookie:
                        self.vlan = vlan_id

                if self.verbose:
                    logger.info(f"Matched VLAN: {self.vlan}")
                self.send_pads_packet(packet, self.interface, self.vlan)

        elif PPPoE in packet:
            session_id = packet[PPPoE].sessionid
            if self.verbose:
                logger.info(
                    f"Received PPP session packet: session_id=0x{session_id:04x}"
                )

            # If PADS then configure PPP_LCP
            if PPP_LCP_Configure in packet and packet[PPP_LCP_Configure].code == 1:
                if self.verbose:
                    logger.info("Received LCP Configure-Request, sending response...")
                self.establish_ppp_lcp_config(packet, self.interface, self.vlan)

            # If PPP_PAP_Request store credentials
            elif PPP_PAP_Request in packet:
                self.username = packet[PPP_PAP_Request].username.decode()
                self.password = packet[PPP_PAP_Request].password.decode()
                if self.verbose:
                    logger.info("Credentials captured!")
                    logger.info(f"Username: {self.username}")
                    logger.info("Password: [REDACTED]")

    def send_pado_packet(
        self, pagi_packet: Any, interface: str, vlan: int, ac_cookie: bytes
    ) -> None:
        """Send PPPoE PADO (Active Discovery Offer) packet in response to PADI."""
        src_mac = get_if_hwaddr(interface)

        if self.generated_host_unique is None:
            host_unique: bytes = bytes(RandString(16))
            if PPPoED_Tags in pagi_packet:
                for tag in pagi_packet[PPPoED_Tags].tag_list:
                    if tag.tag_type == self.TAG_HOST_UNIQ:
                        host_unique = tag.tag_value
                        break
                else:
                    logger.warning(
                        "Host-Uniq tag not found in PADI packet, using generated value"
                    )
            self.generated_host_unique = host_unique
        else:
            host_unique = self.generated_host_unique

        pado_packet = (
            Ether(src=src_mac, dst=pagi_packet[Ether].src)
            / Dot1Q(prio=0, vlan=vlan)
            / PPPoED(code=self.CODE_PADO)
            / PPPoED_Tags(
                tag_list=[
                    PPPoETag(tag_type=self.TAG_SERVICE_NAME, tag_value=""),
                    PPPoETag(
                        tag_type=self.TAG_AC_NAME, tag_value="MyAccessConcentrator"
                    ),
                    PPPoETag(tag_type=self.TAG_AC_COOKIE, tag_value=ac_cookie),
                    PPPoETag(tag_type=self.TAG_HOST_UNIQ, tag_value=host_unique),
                ]
            )
        )

        sendp(pado_packet, iface=interface, verbose=False)

    def send_pads_packet(self, padr_packet: Any, interface: str, vlan: int) -> None:
        """Send PPPoE PADS (Active Discovery Session-confirmation) packet in response to PADR."""
        if self.generated_host_unique is not None:
            host_unique = self.generated_host_unique
        else:
            host_unique = bytes(RandString(16))
            logger.warning(
                "Host-Uniq tag not found in PADR packet, using generated value"
            )

        ac_cookie = b""
        if PPPoED_Tags in padr_packet:
            has_ac_cookie = False
            for tag in padr_packet[PPPoED_Tags].tag_list:
                if tag.tag_type == self.TAG_AC_COOKIE:
                    ac_cookie = tag.tag_value
                    has_ac_cookie = True
            if not has_ac_cookie:
                logger.warning(
                    "AC-Cookie tag not found in PADR packet, using empty value"
                )

        packet = (
            Ether(src=padr_packet[Ether].dst, dst=padr_packet[Ether].src)
            / Dot1Q(prio=0, vlan=vlan)
            / PPPoED(code=self.CODE_PADS, sessionid=random.randint(1, 0xFFFF))
            / PPPoED_Tags(
                tag_list=[
                    PPPoETag(tag_type=self.TAG_SERVICE_NAME, tag_value=""),
                    PPPoETag(tag_type=self.TAG_AC_COOKIE, tag_value=ac_cookie),
                    PPPoETag(tag_type=self.TAG_HOST_UNIQ, tag_value=host_unique),
                ]
            )
        )

        # Send PADS packet
        sendp(packet, iface=interface, verbose=False)

    def establish_ppp_lcp_config(
        self, pads_packet: Any, interface: str, vlan: int
    ) -> None:
        """Establish PPP LCP configuration by responding to LCP Configure-Request."""
        config_ack_packet = (
            Ether(src=pads_packet[Ether].dst, dst=pads_packet[Ether].src)
            / Dot1Q(prio=0, vlan=vlan)
            / PPPoE(sessionid=pads_packet[PPPoE].sessionid)
            / PPP()
            / PPP_LCP_Configure(
                code=2,
                id=pads_packet[PPP_LCP_Configure].id,
                options=pads_packet[PPP_LCP_Configure].options,
            )
            / Padding(load=b"\x00" * 20)
        )

        sendp(config_ack_packet, iface=interface, verbose=False)

        config_packet = (
            Ether(src=pads_packet[Ether].dst, dst=pads_packet[Ether].src)
            / (
                Dot1Q(prio=0, vlan=pads_packet[Dot1Q].vlan)
                if Dot1Q in pads_packet
                else Dot1Q(prio=0, vlan=24)
            )
            / PPPoE(sessionid=pads_packet[PPPoE].sessionid)
            / PPP()
            / PPP_LCP_Configure(
                code=1,
                id=35,
                options=[
                    PPP_LCP_Auth_Protocol_Option(),
                ],
            )
            / Padding(load=b"\x00" * 26)
        )

        # Send PPP_LCP configuration packet
        sendp(config_packet, iface=interface, verbose=False)


def main() -> None:
    """Main entry point for the PPPoE credential retriever."""
    parser = ArgumentParser(
        description="Retrieves the PPPoE credentials from ISP-locked down routers."
    )

    parser.add_argument(
        "-i", "--interface", type=str, required=True, help="interface to monitor on"
    )
    parser.add_argument("-l", "--vlan", type=int, default=None, help="ethernet VLAN ID")
    parser.add_argument(
        "-r",
        "--range",
        type=int,
        const=4096,
        default=50,
        nargs="?",
        help="range of VLAN ID's to try with (must be between 1 and 4096), this will be ignored if --vlan argument is provided",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=None,
        help="timeout in seconds for capturing (default: unlimited)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="enable verbose logging of all PPPoE packets",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
        help="show version",
    )

    args = parser.parse_args()

    # Range argument checking
    if args.range < 1 or args.range > 4096:
        raise ArgumentTypeError(
            f"Range must be between 1 and 4096. Given: {args.range}"
        )

    console = Console()
    rtrv = None

    status_message = f"Monitoring interface {args.interface} for PPPoE connection"
    if args.timeout:
        status_message += f" (timeout: {args.timeout}s)"
    if args.verbose:
        logger.info("Verbose mode enabled")

    with console.status(status_message, spinner="dots"):
        rtrv = Retriever(
            args.interface,
            args.vlan,
            args.range,
            verbose=args.verbose,
            timeout=args.timeout,
        )

    if rtrv.username is None or rtrv.password is None:
        error_msg = "Failed to capture PPPoE credentials"
        if args.timeout:
            error_msg += f" (timeout after {args.timeout}s)"
        error_msg += "\n\nTry running with --verbose to see what's happening."
        if not args.vlan:
            error_msg += "\nYou can also try specifying a VLAN with -l <vlan_id>"
        console.print(f"[bold red]Error:[/bold red] {error_msg}")
        return

    result_message = f"Username: {rtrv.username}\nPassword: {rtrv.password}"

    if not args.vlan:
        result_message += f"\n\n\nYou may need the VLAN configuration to complete the setup of your new router.\n\nVLAN: {rtrv.vlan}"

    panel = Panel(
        RichPadding(Align.center(Text(result_message, justify="center")), (4, 2)),
        title="[bold red]PPPoE Credentials",
        subtitle="[italic underline]Author[reset]: [underline blue link https://guillermodotn.github.io]guillermodotn",
    )

    print(panel)


if __name__ == "__main__":
    try:
        main()
    except ArgumentTypeError as e:
        print(e)
