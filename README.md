# PPPoE Retriever

**pppoe-retriever** is a Python package designed to retrieve PPPoE (Point-to-Point Protocol over Ethernet) credentials from routers that are restricted or locked down by ISPs (Internet Service Providers). This tool is particularly useful for those who need to manage or reconfigure network settings but encounter difficulties accessing credentials due to ISP-imposed restrictions.

## Features

- **Retrieve PPPoE Credentials**: Extract PPPoE usernames and passwords from routers that are typically locked down by ISPs.
- **Support for Multiple Routers**: Works with various router models and ISPs, with support for additional models to be added in future updates.
- **User-Friendly**: Simple command-line interface (CLI) for ease of use.
- **Cross platform**: Works on Windows, Linux and MacOS
- **Self contain**: No installation or setup needed, Python frozen binaries available to download.

## Installation

> Besides the frozen binaries you can find this package on PyPi.

Recomended intall with pipx
```sh
pipx install pppoe-retriever
```

## Usage

1. Connect the router WAN port to you computer using a Ethernet cable.
2. Identify the interface you have connected the router.
3. Download `pppoe-retrieval` package or frozen binary for your architecture.
4. Run the program and wait a couple of minutes for the router to initiate a PPPoED.

## Tested devices

If you have tested this tool on a device that is not listed below, please consider submitting an update with your new entry or creating an issue with the details of the device.


| Model               | ISP            | Firmware Version |
|---------------------|----------------|------------------|
| lowi-h500s          | lowi           | 1.0.0            |

