import string

LOWERCASE_OFFSET = ord("a")
ALPHABET = string.ascii_lowercase[:16]

def b16_encode(plain):
	enc = ""
	for c in plain:
		binary = "{0:08b}".format(ord(c))
		enc += ALPHABET[int(binary[:4], 2)]
		enc += ALPHABET[int(binary[4:], 2)]
	return enc


def b16_decode(enc):
	plain = ""
	for i in range(0, len(enc), 2):
		binary = "{0:04b}".format(ALPHABET.index(enc[i]))
		binary += "{0:04b}".format(ALPHABET.index(enc[i + 1]))
		plain += chr(int(binary, 2))
	return plain

def shift(c, k):
	t1 = ord(c) - LOWERCASE_OFFSET
	t2 = ord(k) - LOWERCASE_OFFSET
	return ALPHABET[(t1 + t2) % len(ALPHABET)]

def shift_back(c, k):
	t1 = ord(c) - LOWERCASE_OFFSET
	t2 = ord(k) - LOWERCASE_OFFSET
	return ALPHABET[(t1 - t2) % len(ALPHABET)]

encoded_string = "mlnklfnknljflfmhjimkmhjhmljhjomhmmjkjpmmjmjkjpjojgjmjpjojojnjojmmkmlmijimhjmmj"

for key in ALPHABET:
	dec = ""
	for c in encoded_string:
		dec += shift_back(c, key)
	# print(dec)
	flag = b16_decode(dec)
	if flag.isascii() and flag.isprintable():
		print(flag)
