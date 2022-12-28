import socket
from random import choice

ROOT_DOMAIN_IP = choice([
    '198.41.0.4',
    '199.9.14.201',
    '192.33.4.12',
    '199.7.91.13',
    '192.203.230.10'
])


class Cache:
    def __init__(self):
        self._dic = {}

    def add(self, question, data):
        self._dic[self._get_key(question)] = data

    def get(self, question):
        return self._dic[self._get_key(question)] if self.contains(question) else None

    def contains(self, question):
        return self._get_key(question) in self._dic

    def _get_key(self, question):
        return question.FQDN() + question.type.decode()


CACHE = Cache()


def byte_to_bits(byte):
    return bin(ord(byte))[2:].rjust(8, '0')


class Header:
    def __init__(self, byte_data):
        self.byte_data = byte_data

        self.id = b'\x00\x00'
        self.flags = self.Flags('1', '0000', '0', '0', '0', '0', '000', '0010')
        self.QDCOUNT = self.ANCOUNT = self.NSCOUNT = self.ARCOUNT = b'\x00\x00'

        if byte_data is not None:
            self.id = self.byte_data[:2]
            self._set_counts()
            self._set_flags()

    def _set_counts(self):
        self.QDCOUNT = self.byte_data[4:6]
        self.ANCOUNT = self.byte_data[6:8]
        self.NSCOUNT = self.byte_data[8:10]
        self.ARCOUNT = self.byte_data[10:12]

    def _set_flags(self):
        flags = self.byte_data[2:4]
        byte1 = bytes(flags[:1])
        byte2 = bytes(flags[1:])
        bits1 = byte_to_bits(byte1)
        bits2 = byte_to_bits(byte2)

        self.flags = self.Flags(qr=bits1[0], opcode=bits1[1:5], aa=bits1[5], tc=bits1[6], rd=bits1[7],
                                ra=bits2[0], z=bits2[1:4], rcode=bits2[4:])

    def to_bytes(self):
        return self.id + self.flags.to_bytes() + \
               self.QDCOUNT + self.ANCOUNT + self.NSCOUNT + self.ARCOUNT

    class Flags:
        def __init__(self, qr, opcode, aa, tc, rd, ra, z, rcode):
            self.qr = qr
            self.opcode = opcode
            self.aa = aa
            self.tc = tc
            self.rd = rd
            self.ra = ra
            self.z = z
            self.rcode = rcode

        def to_bytes(self):
            return int(self.qr + self.opcode + self.aa + self.tc + self.rd, 2).to_bytes(1, byteorder='big') + \
                   int(self.ra + self.z + self.rcode, 2).to_bytes(1, byteorder='big')


class Question:
    def __init__(self, byte_data):
        self.byte_data = byte_data
        self.domains = []
        self.type = self._class = b'\x00\x01'

        self.next_byte_n = 0

        if byte_data is not None:
            self._set()

    def _set(self):
        domain_part = ''
        domain_parts = []

        count = 0
        length = 0
        new_part = True
        total_bytes = 0

        for byte in self.byte_data[12:]:
            total_bytes += 1
            if byte == 0:
                break

            if new_part:
                new_part = False
                length = byte
                continue

            domain_part += chr(byte)
            count += 1

            if count == length:
                domain_parts.append(domain_part)
                domain_part = ''
                count = 0
                new_part = True

        self.domains = domain_parts
        self.type = self.byte_data[12 + total_bytes: 12 + total_bytes + 2]
        self._class = self.byte_data[12 + total_bytes + 2: 12 + total_bytes + 4]
        self.next_byte_n = 12 + total_bytes + 4

    def convert_domains_to_bytes(self):
        result = bytes()
        for domain in self.domains:
            result += bytes([len(domain)])
            result += domain.encode()
        result += bytes([0])
        return result

    def to_bytes(self):
        return self.convert_domains_to_bytes() + self.type + self._class

    def FQDN(self):
        return '.'.join(self.domains)


class Authority:
    def __init__(self, byte_data, start_byte_n, count):
        self.byte_data = byte_data
        self.start_byte_n = start_byte_n
        self.count = count
        self.next_byte_n = 0

        self.next_servers = []

        self._set()

    def _set(self):
        total_bytes = 0
        times_skip = 0
        current_count = 0
        rdlength = bytes()
        processing_name = True

        current_name_server_part_count = 0
        current_server_parts = []
        current_server_part = ''
        current_pointer = False

        for byte in self.byte_data[self.start_byte_n:]:
            total_bytes += 1
            if times_skip > 0:
                times_skip -= 1
                continue
            if current_count == self.count:
                break

            if processing_name:
                if byte == 192:  # b'\xc0'
                    times_skip = 9
                    processing_name = False
                elif byte == 0:
                    times_skip = 8
                    processing_name = False
                else:
                    times_skip = byte
                continue

            if len(rdlength) == 2:
                if byte == 0 or current_pointer:
                    if current_pointer:
                        current_pointer = False
                        current_server_parts.append(self.process_name_server_pointer(byte))
                    current_count += 1
                    processing_name = True
                    rdlength = bytes()
                    self.next_servers.append('.'.join(current_server_parts))
                    current_server_parts = []
                    continue
                if byte == 192:
                    current_pointer = True
                    continue

                if current_name_server_part_count == 0:
                    current_name_server_part_count = byte
                    continue
                current_name_server_part_count -= 1

                current_server_part += chr(byte)

                if current_name_server_part_count == 0:
                    current_server_parts.append(current_server_part)
                    current_server_part = ''
            else:
                rdlength += bytes([byte])

        self.next_byte_n = self.start_byte_n + total_bytes - 1

    def process_name_server_pointer(self, start_byte_n):
        server_parts = []
        current_pointer = False
        current_server_part = ''
        current_server_part_count = 0

        for byte in self.byte_data[start_byte_n:]:
            if byte == 0 or current_pointer:
                if current_pointer:
                    server_parts.append(self.process_name_server_pointer(byte))
                return '.'.join(server_parts)
            if byte == 192:
                current_pointer = True
                continue

            if current_server_part_count == 0:
                current_server_part_count = byte
                continue
            current_server_part_count -= 1

            current_server_part += chr(byte)

            if current_server_part_count == 0:
                server_parts.append(current_server_part)
                current_server_part = ''


class Additional:
    def __init__(self, byte_data, start_byte_n):
        self.byte_data = byte_data
        self.start_byte_n = start_byte_n

        self.next_ips = []

        self._set()

    def _set(self):
        times_skip = 0
        rdlength = bytes()
        processing_name = True
        cur_ip = []

        for byte in self.byte_data[self.start_byte_n:]:
            if times_skip > 0:
                times_skip -= 1
                continue

            if processing_name:
                if byte == 192:  # b'\xc0'
                    times_skip = 9
                    processing_name = False
                elif byte == 0:
                    times_skip = 8
                    processing_name = False
                else:
                    times_skip = byte
                continue

            if len(rdlength) == 2:
                if int.from_bytes(rdlength, byteorder='big') > 4:
                    times_skip = int.from_bytes(rdlength, byteorder='big') - 1
                    rdlength = bytes()
                    processing_name = True
                    continue
                cur_ip.append(str(byte))
                if len(cur_ip) == 4:
                    self.next_ips.append('.'.join(cur_ip))
                    cur_ip = []
                    processing_name = True
                    rdlength = bytes()
            else:
                rdlength += bytes([byte])


class Answer:
    def __init__(self, byte_data, start_byte_n):
        self.byte_data = byte_data
        self.start_byte_n = start_byte_n
        self.ip = None

        self._set()

    def _set(self):
        parts = []
        for byte in self.byte_data[self.start_byte_n + 12:self.start_byte_n + 16]:
            parts.append(str(byte))
        self.ip = '.'.join(parts)


def send_query(header, question, ip):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    sock.sendto(header.to_bytes() + question.to_bytes(), (ip, 53))
    try:
        data, _ = sock.recvfrom(4096)
        return data
    except Exception:
        return None


class ResponseBuilder:
    def __init__(self, data):
        self.orig_byte_data = data

        self.sites_stack = []
        self.ips_stack = []
        self.visited_ips = set()

        self.queried_anew = False

    def query_domains(self, byte_data, start_ip=ROOT_DOMAIN_IP):
        orig_header = Header(byte_data)
        orig_question = Question(byte_data)

        cached = CACHE.get(orig_question)
        if cached is not None:
            return cached

        first = True

        while True:
            if first:
                first = False
                destination = start_ip
            else:
                if len(self.ips_stack) == 0:
                    return None
                destination = self.ips_stack.pop()
                if destination in self.visited_ips:
                    continue
                self.visited_ips.add(destination)

            data = send_query(orig_header, orig_question, destination)

            if data is None:
                continue

            header = Header(data)
            question = Question(data)

            if header.flags.rcode == '0011':  # Non-Existent Domain
                CACHE.add(question, data)
                return data

            if int.from_bytes(header.ANCOUNT, byteorder='big') > 0:
                CACHE.add(question, data)
                if self.queried_anew:
                    self.queried_anew = False
                    return self.query_domains(self.orig_byte_data, Answer(data, question.next_byte_n).ip)
                return data

            authority = Authority(data, question.next_byte_n, int.from_bytes(header.NSCOUNT, byteorder='big'))
            additional = Additional(data, authority.next_byte_n)

            for i in reversed(additional.next_ips):
                if i not in self.visited_ips:
                    self.ips_stack.append(i)
            self.sites_stack += reversed(authority.next_servers)

            if int.from_bytes(header.ARCOUNT, byteorder='big') == 0:
                if len(self.ips_stack) > 0:
                    continue

                if len(self.sites_stack) > 0:
                    self.queried_anew = True
                    new_site_query = self.create_new_site_query(orig_header, orig_question, self.sites_stack.pop())
                    return self.query_domains(new_site_query)
                else:
                    return None

    def create_new_site_query(self, header, question, site):
        question.domains = site.split('.')
        return header.to_bytes() + question.to_bytes()

    def build(self):
        return self.query_domains(self.orig_byte_data)


def build_unsupported_response(byte_data, from_domains=None):
    if from_domains is None:
        from_domains = []
    header = Header(byte_data)
    header.flags.rcode = '0010'
    question = Question(byte_data)
    if byte_data is None:
        question.domains = from_domains

    return header.to_bytes() + question.to_bytes()


def main():
    while True:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('127.0.0.1', 53))
        data, addr = sock.recvfrom(512)

        question = Question(data)

        if len(question.domains) == 0:
            sock.sendto(build_unsupported_response(None, []), addr)
            sock.close()
            continue

        if question.type not in [b'\x00\x01', b'\x00\x0c', b'\x00\x0f']:  # Только A, PTR, MX
            sock.sendto(build_unsupported_response(data), addr)
            sock.close()
            continue

        response = ResponseBuilder(data).build()
        if response is None:
            sock.sendto(build_unsupported_response(None, question.domains), addr)
        else:
            sock.sendto(response, addr)

        sock.close()


if __name__ == '__main__':
    main()
