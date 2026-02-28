#!/usr/bin/env python3


import logging
import random
from argparse import ArgumentParser, ArgumentTypeError

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

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)


class Retriever:
    PPPOE_CODES = {
        9: "PADI",
        7: "PADO",
        25: "PADR",
        101: "PADS",
        167: "PADT",
    }

    def __init__(self, interface, vlan, search_range, verbose=False, timeout=None):
        self.interface = interface
        self.vlan = vlan
        self.username = None
        self.password = None
        self.generated_host_unique = None
        self.verbose = verbose
        self.vlan_dict = {
            i: i.to_bytes(16, "big") for i in range(search_range)
        }  # Range of possible VLAN_ID's (4096, 12 bits).

        if self.verbose:
            logger.info(f"Starting capture on interface: {interface}")
            logger.info(f"VLAN: {vlan if vlan else 'auto-discover'}")
            logger.info(f"Search range: {search_range}")

        # Replace 'lo' with the appropriate loopback interface on your system
        sniff(
            prn=self.handle_eth_frame,
            iface=self.interface,
            lfilter=lambda pkg: pkg.haslayer(PPP) or pkg.haslayer(PPPoED),
            stop_filter=lambda pkg: pkg.haslayer(PPP_PAP_Request),
            store=0,
            timeout=timeout,
        )

    def handle_eth_frame(self, packet):
        if PPPoED in packet:
            code = packet[PPPoED].code
            code_name = self.PPPOE_CODES.get(code, f"Unknown({code})")

            if self.verbose:
                vlan = packet[Dot1Q].vlan if Dot1Q in packet else "none"
                logger.info(f"Received PPPoE packet: {code_name} (VLAN: {vlan})")

            # If PADI packet reply with PADO
            if code == 9:
                if self.verbose:
                    logger.info("Sending PADO response(s)...")
                if self.vlan:
                    self.send_pado_packet(
                        packet, self.interface, self.vlan, RandString(16)
                    )
                else:
                    for vlan_id, ac_cookie in self.vlan_dict.items():
                        self.send_pado_packet(
                            packet, self.interface, vlan_id, ac_cookie
                        )

            # If PADR packet reply with PADS
            if code == 25:
                if self.verbose:
                    logger.info("Received PADR, sending PADS...")
                # Retrieve the VLAN ID
                response_ac_cookie = ""
                for tag in packet[PPPoED_Tags].tag_list:
                    if tag.tag_type == 260:  # AC_Cookie Tag
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
                self.stablish_ppp_lcp_config(packet, self.interface, self.vlan)

            # If PPP_PAP_Request store credentials
            elif PPP_PAP_Request in packet:
                self.username = packet[PPP_PAP_Request].username.decode()
                self.password = packet[PPP_PAP_Request].password.decode()
                if self.verbose:
                    logger.info("Credentials captured!")
                    logger.info(f"Username: {self.username}")
                    logger.info("Password: [REDACTED]")

    def send_pado_packet(self, pagi_packet, interface, vlan, ac_cookie):
        # Extract the mac address of the interface
        src_mac = get_if_hwaddr(interface)

        # Get Host-Uniq tag value (generate random if not present, reuse if already generated)
        if self.generated_host_unique is None:
            host_unique = RandString(16)
            if PPPoED_Tags in pagi_packet:
                for tag in pagi_packet[PPPoED_Tags].tag_list:
                    if tag.tag_type == 259:  # Host-Uniq Tag
                        host_unique = tag.tag_value
                        break
                else:
                    logger.warning(
                        "Host-Uniq tag not found in PADI packet, using generated value"
                    )
            self.generated_host_unique = host_unique
        else:
            host_unique = self.generated_host_unique

        # Create of PADO packet
        pado_packet = (
            Ether(src=src_mac, dst=pagi_packet[Ether].src)
            / Dot1Q(prio=0, vlan=vlan)
            / PPPoED(code=7)
            / PPPoED_Tags(
                tag_list=[
                    PPPoETag(tag_type=257, tag_value=""),
                    PPPoETag(tag_type=258, tag_value="MyAccessConcentrator"),
                    PPPoETag(tag_type=260, tag_value=ac_cookie),
                    PPPoETag(tag_type=259, tag_value=host_unique),
                ]
            )
        )

        # Send PADO packet
        sendp(pado_packet, iface=interface, verbose=False)

    def send_pads_packet(self, padr_packet, interface, vlan):
        # Get Host-Uniq and AC-Cookie tag values (reuse generated if available)
        if self.generated_host_unique is not None:
            host_unique = self.generated_host_unique
        else:
            host_unique = RandString(16)
            logger.warning(
                "Host-Uniq tag not found in PADR packet, using generated value"
            )

        ac_cookie = b""
        if PPPoED_Tags in padr_packet:
            has_ac_cookie = False
            for tag in padr_packet[PPPoED_Tags].tag_list:
                if tag.tag_type == 260:  # AC-Cookie Tag
                    ac_cookie = tag.tag_value
                    has_ac_cookie = True
            if not has_ac_cookie:
                logger.warning(
                    "AC-Cookie tag not found in PADR packet, using empty value"
                )

        # Create PADS packet
        packet = (
            Ether(src=padr_packet[Ether].dst, dst=padr_packet[Ether].src)
            / Dot1Q(prio=0, vlan=vlan)
            / PPPoED(code=101, sessionid=random.randint(1, 0xFFFF))
            / PPPoED_Tags(
                tag_list=[
                    PPPoETag(tag_type=257, tag_value=""),
                    PPPoETag(tag_type=260, tag_value=ac_cookie),
                    PPPoETag(tag_type=259, tag_value=host_unique),
                ]
            )
        )

        # Send PADS packet
        sendp(packet, iface=interface, verbose=False)

    def stablish_ppp_lcp_config(self, pads_packet, interface, vlan):
        # Ether / Dot1Q / PPPoE / PPP / LCP Configure-Request / Padding

        config_ack_packet = (
            Ether(src=pads_packet[Ether].dst, dst=pads_packet[Ether].src)
            / Dot1Q(prio=0, vlan=vlan)
            /
            # Generate a random integer between 1 and 65535
            PPPoE(sessionid=pads_packet[PPPoE].sessionid)
            / PPP()
            / PPP_LCP_Configure(
                code=2,
                id=pads_packet[PPP_LCP_Configure].id,
                options=pads_packet[PPP_LCP_Configure].options,
            )
            / Padding(load=b"\x00" * 20)
        )

        # Send PPP_LCP config acknowledgment packet
        sendp(config_ack_packet, iface=interface, verbose=False)

        config_packet = (
            Ether(src=pads_packet[Ether].dst, dst=pads_packet[Ether].src)
            / (
                Dot1Q(prio=0, vlan=pads_packet[Dot1Q].vlan)
                if Dot1Q in pads_packet
                else Dot1Q(prio=0, vlan=24)
            )
            /
            # Generate a random integer between 1 and 65535
            PPPoE(sessionid=pads_packet[PPPoE].sessionid)
            / PPP()
            /
            # id requires 0 <= number <= 255
            PPP_LCP_Configure(
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


def main():
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
        "--version", action="version", version="%(prog)s 1.1.0", help="show version"
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
    if args.v:
        logger.info("Verbose mode enabled")

    with console.status(status_message, spinner="dots"):
        rtrv = Retriever(
            args.interface,
            args.vlan,
            args.range,
            verbose=args.v,
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
