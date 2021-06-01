import argparse

import dns.message
import dns.name
import dns.query
import dns.rdata
import dns.rdataclass
import dns.rdatatype

FORMATS = [("A", "{name} has address {address}"),
           ("AAAA", "{name} has IPv6 address {address}")]

ROOT_SERVERS = ("198.41.0.4",
                "199.9.14.201",
                "192.33.4.12",
                "199.7.91.13",
                "192.203.230.10",
                "192.5.5.241",
                "192.112.36.4",
                "198.97.190.53",
                "192.36.148.17",
                "192.58.128.30",
                "193.0.14.129",
                "199.7.83.42",
                "202.12.27.33")

# simple domain in memory cache
domain_cache = {}


# return dictionary with A and AAAA ip
def get_results(name: str) -> dict:
    full_response = {}
    target_name: dns.name = dns.name.from_text(name)
    # find A
    response = find(target_name, dns.rdatatype.A)
    ipv4_rec = []
    for answers in response.answer:
        ipv4_name = answers.name
        for answer in answers:
            if answer.rdtype == 1:  # A record
                ipv4_rec.append({"name": ipv4_name, "address": str(answer)})
    # find AAAA
    response = find(target_name, dns.rdatatype.AAAA)
    ipv6_rec = []
    for answers in response.answer:
        ipv6_name = answers.name
        for answer in answers:
            if answer.rdtype == 28:  # AAAA record
                ipv6_rec.append({"name": ipv6_name, "address": str(answer)})

    full_response["A"] = ipv4_rec
    full_response["AAAA"] = ipv6_rec
    return full_response


def find(target_name: dns.name.Name,
         qtype: dns.rdata.Rdata.rdtype) -> dns.message.Message:
    split = str(target_name).split(".")
    domain = split[len(split) - 2]
    if domain not in domain_cache:
        domain_cache[domain] = {}

    for root_server in ROOT_SERVERS:
        if root_server in domain_cache[domain]:
            response = domain_cache[domain][root_server]
        else:
            response = make_request(target_name, qtype, root_server)
            domain_cache[domain][root_server] = response
        if response:
            if response.answer:
                return response
            elif response.additional:
                for additional in response.additional:
                    if additional.rdtype != 1:
                        continue
                    for add in additional:
                        new_response = find_recursive(target_name,
                                                      qtype, str(add))
                        if new_response:
                            return new_response
    return None


def make_request(target_name: dns.name.Name,
                 qtype: dns.rdata.Rdata, ipAddr: str) -> dns.message.Message:
    outbound_query = dns.message.make_query(target_name, qtype)
    try:
        response = dns.query.udp(outbound_query, ipAddr, 3)
    except Exception as e:
        response = None

    return response


def find_recursive(target_name: dns.name.Name,
                   qtype: dns.rdata.Rdata,
                   ipAddr: str) -> dns.message.Message:
    response = make_request(target_name, qtype, ipAddr)
    if response:
        if response.answer:
            return response
        elif response.additional:
            for additional in response.additional:
                if additional.rdtype != 1:
                    continue
                for add in additional:
                    ip = str(add)
                    new_response = find_recursive(target_name, qtype, ip)
                    if new_response:
                        return new_response
    return response


def print_results(results: dict) -> None:
    for rtype, fmt_str in FORMATS:
        for result in results.get(rtype):
            print(fmt_str.format(**result))


def main():
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument("name", nargs="+",
                                 help="DNS name(s) to look up")

    program_args = argument_parser.parse_args()
    for a_domain_name in program_args.name:
        result = get_results(a_domain_name)
        if result != -1:
            print_results(result)


if __name__ == "__main__":
    main()
