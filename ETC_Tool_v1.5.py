import socket     #pip install sockets
import whois     #pip install python-whois
from colorama import Back, Fore, Style     #pip install colorama
import threading     #pip install threaded
from queue import Queue     #pip install queuelib
import webbrowser
from scapy.all import *     #pip install scapy

def fIP():
    domain_fIP=input(Fore.YELLOW+"\nWrite domain: "+Fore.WHITE)
    print(Fore.RED+"\nIP is: ",socket.gethostbyname(domain_fIP))

def info():
    domain_info=input(Fore.YELLOW+"\nWrite domain: "+Fore.WHITE)
    whois_info = whois.whois(domain_info)
    for key, value in whois_info.items():
        print(Fore.RED+"\n",key,":", value)

def get_port_name(port_number):
    port_name = socket.getservbyport(port_number)
    if port_name is None:
        port_name = "Unknown"
    return port_name

def port_scanner():
    host = input(Fore.YELLOW+"\nEnter the host name or IP address: "+Fore.WHITE)
    start_port = int(input(Fore.YELLOW+"\nEnter the start port number: "+Fore.WHITE))
    end_port = int(input(Fore.YELLOW+"\nEnter the end port number: "+Fore.WHITE))
    for port in range(start_port, end_port + 1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((host, port))
            port_name = get_port_name(port)
            print(Fore.RED+"\nPort {} ({}) is open".format(port, port_name))
            sock.close()
        except socket.error:
            pass  

def shift_left_key():
    inp=input(Fore.YELLOW+'\nEnter plain text: '+Fore.WHITE).lower()
    key=int(input(Fore.YELLOW+'\nEnter number of key: '+Fore.WHITE))
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    text=list(inp)
    array=['a','b','c','d','e','f','g','h','i','j','k','l','m','n',
             'o','p','q','r','s','t','u','v','w','x','y','z']
    result =''
    if key in range(1,26):
        array = array[+key:] + array[:+key]
        for letter in text:
            result += array[alphabet.find(letter)]
    else:
        print(Fore.RED+'Error key...')
    print(Fore.RED+'\nEncryption is: ',result)

def AES_encryption():
    plaintext = input(Fore.YELLOW+'\nEnter text by HEX: '+Fore.WHITE)
    valid_pt_block = valid_block_size(plaintext.lower())
    plaintext_matrix = key_and_text_to_matrix(plaintext.lower())

    key = input(Fore.YELLOW+'\nEnter key by HEX: '+Fore.WHITE)
    valid_k_block = valid_block_size(key.lower())
    key_matrix = key_and_text_to_matrix(key.lower())

    cipher_text = aes_encryption(plaintext_matrix, key_matrix)
    print(Fore.RED+'____________________________________________________________________________________________________________')
    print(Fore.RED+'\nEncrypted Text: ', cipher_text)
    print(Fore.RED+'\n____________________________________________________________________________________________________________')

def hx1(v1):
    hex_v1 = {'0': '0000', '1': '0001', '2': '0010', '3': '0011',
               '4': '0100', '5': '0101', '6': '0110', '7': '0111',
               '8': '1000', '9': '1001', 'a': '1010', 'b': '1011',
               'c': '1100', 'd': '1101', 'e': '1110', 'f': '1111'}
    msg_len = len(v1)
    final = ''
    for i in range(0, msg_len):
        final = final + hex_v1[v1[i]]
    return final


def hx2(v1):
    bin_v1 = {'0000': '0', '0001': '1', '0010': '2', '0011': '3',
               '0100': '4', '0101': '5', '0110': '6', '0111': '7',
               '1000': '8', '1001': '9', '1010': 'a', '1011': 'b',
               '1100': 'c', '1101': 'd', '1110': 'e', '1111': 'f'}
    msg_len = len(v1)
    lst = []
    final = ''
    count = 0
    i = 0
    while count != msg_len:
        lst = lst + [v1[count:count + 4]]
        final = final + bin_v1[lst[i]]
        i = i + 1
        count = count + 4

    return final


def substitution_box(rc):
    hex_v1 = {'0': '0', '1': '1', '2': '2', '3': '3',
               '4': '4', '5': '5', '6': '6', '7': '7',
               '8': '8', '9': '9', 'a': '10', 'b': '11',
               'c': '12', 'd': '13', 'e': '14', 'f': '15'}

    s_box = [['63', '7c', '77', '7b', 'f2', '6b', '6f', 'c5', '30', '01', '67', '2b', 'fe', 'd7', 'ab', '76'],
                      ['ca', '82', 'c9', '7d', 'fa', '59', '47', 'f0', 'ad', 'd4', 'a2', 'af', '9c', 'a4', '72', 'c0'],
                      ['b7', 'fd', '93', '26', '36', '3f', 'f7', 'cc', '34', 'a5', 'e5', 'f1', '71', 'd8', '31', '15'],
                      ['04', 'c7', '23', 'c3', '18', '96', '05', '9a', '07', '12', '80', 'e2', 'eb', '27', 'b2', '75'],
                      ['09', '83', '2c', '1a', '1b', '6e', '5a', 'a0', '52', '3b', 'd6', 'b3', '29', 'e3', '2f', '84'],
                      ['53', 'd1', '00', 'ed', '20', 'fc', 'b1', '5b', '6a', 'cb', 'be', '39', '4a', '4c', '58', 'cf'],
                      ['d0', 'ef', 'aa', 'fb', '43', '4d', '33', '85', '45', 'f9', '02', '7f', '50', '3c', '9f', 'a8'],
                      ['51', 'a3', '40', '8f', '92', '9d', '38', 'f5', 'bc', 'b6', 'da', '21', '10', 'ff', 'f3', 'd2'],
                      ['cd', '0c', '13', 'ec', '5f', '97', '44', '17', 'c4', 'a7', '7e', '3d', '64', '5d', '19', '73'],
                      ['60', '81', '4f', 'dc', '22', '2a', '90', '88', '46', 'ee', 'b8', '14', 'de', '5e', '0b', 'db'],
                      ['e0', '32', '3a', '0a', '49', '06', '24', '5c', 'c2', 'd3', 'ac', '62', '91', '95', 'e4', '79'],
                      ['e7', 'c8', '37', '6d', '8d', 'd5', '4e', 'a9', '6c', '56', 'f4', 'ea', '65', '7a', 'ae', '08'],
                      ['ba', '78', '25', '2e', '1c', 'a6', 'b4', 'c6', 'e8', 'dd', '74', '1f', '4b', 'bd', '8b', '8a'],
                      ['70', '3e', 'b5', '66', '48', '03', 'f6', '0e', '61', '35', '57', 'b9', '86', 'c1', '1d', '9e'],
                      ['e1', 'f8', '98', '11', '69', 'd9', '8e', '94', '9b', '1e', '87', 'e9', 'ce', '55', '28', 'df'],
                      ['8c', 'a1', '89', '0d', 'bf', 'e6', '42', '68', '41', '99', '2d', '0f', 'b0', '54', 'bb', '16']]

    substitution = s_box[int(hex_v1[rc[0]])][int(hex_v1[rc[1]])]
    return substitution


def xor(left, right):
    final = ''
    l_len = len(left)
    for i in range(0, l_len):
        if left[i] == right[i]:
            final = final + '0'
        elif left[i] != right[i]:
            final = final + '1'
    return final


def col_to_row(v1):
    row = []
    for i in range(0, 4):
        col = []
        for j in range(0, 4):
            col = col + [v1[j][i]]
        row = row + [col]
        
    return row


def row_to_col(v1):
    col = []
    for i in range(0, 4):
        row = []
        for j in range(0, 4):
            row = row + [v1[j][i]]
        col = col + [row]
    return col

def substitute_byte(state):
    row = []
    for i in range(0, 4):
        col = []
        for j in range(0, 4):
            col = col + [substitution_box(state[i][j])]
        row = row + [col]
    return row

def shift_row(sub_bytes):
    state_array = []

    first = sub_bytes[0]
    state_array = state_array + [first]

    second = [sub_bytes[1][1]] + [sub_bytes[1][2]] + [sub_bytes[1][3]] + [sub_bytes[1][0]]
    state_array = state_array + [second]

    third = [sub_bytes[2][2]] + [sub_bytes[2][3]] + [sub_bytes[2][0]] + [sub_bytes[2][1]]
    state_array = state_array + [third]

    four = [sub_bytes[3][3]] + [sub_bytes[3][0]] + [sub_bytes[3][1]] + [sub_bytes[3][2]]
    state_array = state_array + [four]

    return state_array

def multiply_by_02(inp):
    bin_v1 = hx1(inp[0]) + hx1(inp[1])
    final = ''
    if bin_v1[0] == '1':

        bin_v1 = bin_v1[1:len(bin_v1)] + '0'

        final = xor(bin_v1, hx1('1b'))
    elif bin_v1[0] == '0':
        final = bin_v1[1:len(bin_v1)] + '0'

    return final

def multiply_by_03(inp):
    mix = multiply_by_02(inp)
    final = xor(mix, hx1(inp))

    return final

def row0(row):
    xor01 = xor(multiply_by_02(row[0]), multiply_by_03(row[1]))
    xor23 = xor(hx1(row[2]), hx1(row[3]))
    final_xor = xor(xor01, xor23)

    return hx2(final_xor)

def row1(row):
    xor01 = xor(hx1(row[0]), multiply_by_02(row[1]))
    xor23 = xor(multiply_by_03(row[2]), hx1(row[3]))
    final_xor = xor(xor01, xor23)

    return hx2(final_xor)

def row2(row):
    xor01 = xor(hx1(row[0]), hx1(row[1]))
    xor23 = xor(multiply_by_02(row[2]), multiply_by_03(row[3]))
    final_xor = xor(xor01, xor23)

    return hx2(final_xor)

def row3(row):
    xor01 = xor(multiply_by_03(row[0]), hx1(row[1]))
    xor23 = xor(multiply_by_02(row[3]), hx1(row[2]))
    final_xor = xor(xor01, xor23)

    return hx2(final_xor)


def mix_col(s_row):
    final_row = []
    for i in range(0, 4):
        tmp_row = [row0(s_row[i])] + [row1(s_row[i])] + [row2(s_row[i])] + [row3(s_row[i])]
        final_row = final_row + [tmp_row]

    return final_row


def key_expansion(s_key, rnd):
    keys = []
    

    for pos in range(0, 4):
        if pos == 0:
            first_col = []
            tmp = s_key[3]
            t_len = len(tmp)

            for i in range(1, t_len):
                first_col = first_col + [tmp[i]]
            first_col = first_col + [tmp[0]]
            col = []

            f_len = len(first_col)
            for i in range(0, f_len):
                col = col + [substitution_box(first_col[i])]

            tmp_key = []
            for i in range(0, 4):
                sub_key = xor(hx1(s_key[0][i]), hx1(rnd[i]))
                sub_key1 = xor(sub_key, hx1(col[i]))
                tmp_key = tmp_key + [str(hx2(sub_key1))]

            keys = keys + [tmp_key]

        elif pos > 0:
            first_col = []

            for i in range(0, 4):
                sub_key = xor(hx1(s_key[pos][i]), hx1(keys[pos - 1][i]))
                first_col = first_col + [str(hx2(sub_key))]

            keys = keys + [first_col]
 
    return keys


def add_round(plain_text, keys):
    row = []
    for i in range(0, 4):
        col = []
        for j in range(0, 4):
            tmp = xor(hx1(keys[i][j]), hx1(plain_text[i][j]))
            col = col + [hx2(tmp)]
        row = row + [col]

    return col_to_row(row)

def valid_block_size(msg):
    msg_len = len(msg)
    final = msg
    if msg_len > 32:
        print(Fore.RED+'\nNot a valid size block, Exceeding Block size!')
        final = final[0:32]
        print(Fore.RED+'\nafter pading: ', final,'\n')
        print(Fore.RED+'\n____________________________________________________________________________________________________________')
        return final
    elif msg_len % 32 != 0:
        print(Fore.RED+'\nNot a valid size block')
        for i in range(abs(32 - (msg_len % 32))):
            final = final + '0'
        print(Fore.RED+'\nafter pading: ', final,'\n')
        print(Fore.RED+'____________________________________________________________________________________________________________')
        return final
    else:
        print(Fore.RED+'\nvalid size block\n')
        print(Fore.RED+'\n____________________________________________________________________________________________________________')
    return msg


def key_and_text_to_matrix(key_string):
    arr = [['00' for _ in range(4)] for _ in range(4)]
    row = 0
    col = 0
    for i in range(0, len(key_string), 2):
        if row < 4 and col < 4:
            if len(key_string[i:i + 2]) == 1:
                arr[row][col] = key_string[i:i + 2] + '0'
            else:
                arr[row][col] = key_string[i:i + 2]
            col = col + 1
            if col > 3:
                row = row + 1
                col = 0
   
    return arr


rnd_const = [['01', '00', '00', '00'], ['02', '00', '00', '00'], ['04', '00', '00', '00'], ['08', '00', '00', '00'],
             ['10', '00', '00', '00'], ['20', '00', '00', '00'], ['40', '00', '00', '00'], ['80', '00', '00', '00'],
             ['1b', '00', '00', '00'], ['36', '00', '00', '00']]


def aes_encryption(plain_text, aes_key):
    add_round_key = add_round(plain_text, aes_key)
    sub_byte = substitute_byte(add_round_key)
    shift_rows = shift_row(sub_byte)
    mix_column = mix_col(row_to_col(shift_rows))
    add_round_key = add_round(mix_column, key_expansion(aes_key, rnd_const[0]))
    aes_key = key_expansion(aes_key, rnd_const[0])
    
    for i in range(1, 9):
        tmp_key = key_expansion(aes_key, rnd_const[i])
        aes_key = tmp_key
        print(Fore.RED+'\naes key',i,': ',str(aes_key).replace('[','').replace(']','').replace(',','').replace("'",''),'\n')
        sub_byte = substitute_byte(add_round_key)
        print(Fore.RED+'sub byte',i,': ',str(sub_byte).replace('[','').replace(']','').replace(',','').replace("'",''),'\n')
        shift_rows = shift_row(sub_byte)
        print(Fore.RED+'shift rows',i,': ',str(shift_rows).replace('[','').replace(']','').replace(',','').replace("'",''),'\n')
        mix_column = mix_col(row_to_col(shift_rows))
        print(Fore.RED+'mix column',i,': ',str(mix_column).replace('[','').replace(']','').replace(',','').replace("'",''),'\n')
        add_round_key = add_round(mix_column, aes_key)
        print(Fore.RED+'adding the round key',i,': ',str(add_round_key).replace('[','').replace(']','').replace(',','').replace("'",''),'\n')
        print(Fore.RED+'____________________________________________________________________________________________________________')
        
    sub_byte = substitute_byte(add_round_key)
    print(Fore.RED+'\nsub byte : ',str(sub_byte).replace('[','').replace(']','').replace(',','').replace("'",''))
    shift_rows = row_to_col(shift_row(sub_byte))
    print(Fore.RED+'\nshift rows : ',str(shift_rows).replace('[','').replace(']','').replace(',','').replace("'",''))
    tmp_key = key_expansion(aes_key, rnd_const[9])
    print(Fore.RED+'\nkey : ', str(tmp_key).replace('[','').replace(']','').replace(',','').replace("'",''))
    aes_key = tmp_key
    print(Fore.RED+'\naes key : ',str(aes_key).replace('[','').replace(']','').replace(',','').replace("'",''))
    add_round_key = add_round(shift_rows, aes_key)
    print(Fore.RED+'\nadding the round key :',str(add_round_key).replace('[','').replace(']','').replace(',','').replace("'",''),'\n')

    cipher = ''
    for row in range(0, len(add_round_key)):
        for col in range(0, 4):
            cipher = cipher + add_round_key[col][row]
    return cipher

def hex2bin(s):
	mp = {'0': "0000",
		'1': "0001",
		'2': "0010",
		'3': "0011",
		'4': "0100",
		'5': "0101",
		'6': "0110",
		'7': "0111",
		'8': "1000",
		'9': "1001",
		'A': "1010",
		'B': "1011",
		'C': "1100",
		'D': "1101",
		'E': "1110",
		'F': "1111"}
	bin = ""
	for i in range(len(s)):
		bin = bin + mp[s[i]]
	return bin

def bin2hex(s):
	mp = {"0000": '0',
		"0001": '1',
		"0010": '2',
		"0011": '3',
		"0100": '4',
		"0101": '5',
		"0110": '6',
		"0111": '7',
		"1000": '8',
		"1001": '9',
		"1010": 'A',
		"1011": 'B',
		"1100": 'C',
		"1101": 'D',
		"1110": 'E',
		"1111": 'F'}
	hex = ""
	for i in range(0, len(s), 4):
		ch = ""
		ch = ch + s[i]
		ch = ch + s[i + 1]
		ch = ch + s[i + 2]
		ch = ch + s[i + 3]
		hex = hex + mp[ch]

	return hex

def bin2dec(binary):

	binary1 = binary
	decimal, i, n = 0, 0, 0
	while(binary != 0):
		dec = binary % 10
		decimal = decimal + dec * pow(2, i)
		binary = binary//10
		i += 1
	return decimal

def dec2bin(num):
	res = bin(num).replace("0b", "")
	if(len(res) % 4 != 0):
		div = len(res) / 4
		div = int(div)
		counter = (4 * (div + 1)) - len(res)
		for i in range(0, counter):
			res = '0' + res
	return res

def permute(k, arr, n):
	permutation = ""
	for i in range(0, n):
		permutation = permutation + k[arr[i] - 1]
	return permutation

def shift_left(k, nth_shifts):
	s = ""
	for i in range(nth_shifts):
		for j in range(1, len(k)):
			s = s + k[j]
		s = s + k[0]
		k = s
		s = ""
	return k

def xor(a, b):
	ans = ""
	for i in range(len(a)):
		if a[i] == b[i]:
			ans = ans + "0"
		else:
			ans = ans + "1"
	return ans

initial_perm = [58, 50, 42, 34, 26, 18, 10, 2,
				60, 52, 44, 36, 28, 20, 12, 4,
				62, 54, 46, 38, 30, 22, 14, 6,
				64, 56, 48, 40, 32, 24, 16, 8,
				57, 49, 41, 33, 25, 17, 9, 1,
				59, 51, 43, 35, 27, 19, 11, 3,
				61, 53, 45, 37, 29, 21, 13, 5,
				63, 55, 47, 39, 31, 23, 15, 7]

exp_d = [32, 1, 2, 3, 4, 5, 4, 5,
		6, 7, 8, 9, 8, 9, 10, 11,
		12, 13, 12, 13, 14, 15, 16, 17,
		16, 17, 18, 19, 20, 21, 20, 21,
		22, 23, 24, 25, 24, 25, 26, 27,
		28, 29, 28, 29, 30, 31, 32, 1]

per = [16, 7, 20, 21,
	29, 12, 28, 17,
	1, 15, 23, 26,
	5, 18, 31, 10,
	2, 8, 24, 14,
	32, 27, 3, 9,
	19, 13, 30, 6,
	22, 11, 4, 25]

sbox = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
		[0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
		[4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
		[15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

		[[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
		[3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
		[0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
		[13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

		[[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
		[13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
		[13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
		[1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

		[[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
		[13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
		[10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
		[3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

		[[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
		[14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
		[4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
		[11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

		[[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
		[10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
		[9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
		[4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

		[[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
		[13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
		[1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
		[6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

		[[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
		[1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
		[7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
		[2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]

final_perm = [40, 8, 48, 16, 56, 24, 64, 32,
			39, 7, 47, 15, 55, 23, 63, 31,
			38, 6, 46, 14, 54, 22, 62, 30,
			37, 5, 45, 13, 53, 21, 61, 29,
			36, 4, 44, 12, 52, 20, 60, 28,
			35, 3, 43, 11, 51, 19, 59, 27,
			34, 2, 42, 10, 50, 18, 58, 26,
			33, 1, 41, 9, 49, 17, 57, 25]


def encrypt(pt, rkb, rk):
	pt = hex2bin(pt)
	pt = permute(pt, initial_perm, 64)
	print(Fore.RED+"\nAfter initial permutation: ", bin2hex(pt))
	left = pt[0:32]
	right = pt[32:64]
	for i in range(0, 16):
		right_expanded = permute(right, exp_d, 48)
		xor_x = xor(right_expanded, rkb[i])
		sbox_str = ""
		for j in range(0, 8):
			row = bin2dec(int(xor_x[j * 6] + xor_x[j * 6 + 5]))
			col = bin2dec(
				int(xor_x[j * 6 + 1] + xor_x[j * 6 + 2] + xor_x[j * 6 + 3] + xor_x[j * 6 + 4]))
			val = sbox[j][row][col]
			sbox_str = sbox_str + dec2bin(val)
		sbox_str = permute(sbox_str, per, 32)
		result = xor(left, sbox_str)
		left = result
		if(i != 15):
			left, right = right, left
		print(Fore.RED+"\nRound ", i + 1, ": ", left + right, "\n\nkey ",i , ": ", hex2bin(rk[i]),'\n________________________________________________________________________________________')
	combine = left + right
	cipher_text = permute(combine, final_perm, 64)
	return cipher_text

def DES_encryption():
    pt = input(Fore.YELLOW+'\nPlain text by HEX 16 Bit: '+Fore.WHITE)
    key = input(Fore.YELLOW+'\nKey by HEX 16 Bit: '+Fore.WHITE)
    key = hex2bin(key)
    keyp = [57, 49, 41, 33, 25, 17, 9,
            1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4]
    key = permute(key, keyp, 56)
    shift_table = [1, 1, 2, 2,
                2, 2, 2, 2,
                1, 2, 2, 2,
                2, 2, 2, 1]
    key_comp = [14, 17, 11, 24, 1, 5,
                3, 28, 15, 6, 21, 10,
                23, 19, 12, 4, 26, 8,
                16, 7, 27, 20, 13, 2,
                41, 52, 31, 37, 47, 55,
                30, 40, 51, 45, 33, 48,
                44, 49, 39, 56, 34, 53,
                46, 42, 50, 36, 29, 32]
    left = key[0:28] 
    right = key[28:56]
    rkb = []
    rk = []
    for i in range(0, 16):
        left = shift_left(left, shift_table[i])
        right = shift_left(right, shift_table[i])
        combine_str = left + right
        round_key = permute(combine_str, key_comp, 48)
        rkb.append(round_key)
        rk.append(bin2hex(round_key))
    print(Fore.RED+"\nEncryption: ")
    cipher_text = bin2hex(encrypt(pt, rkb, rk))
    print(Fore.RED+"\nCipher Text : ", cipher_text)
    print(Fore.RED+'\n________________________________________________________________________________________')
    print(Fore.RED+"\nDecryption: ")
    rkb_rev = rkb[::-1]
    rk_rev = rk[::-1]
    text = bin2hex(encrypt(cipher_text, rkb_rev, rk_rev))
    print(Fore.RED+"\nPlain Text : ", text)

def waildmask_calculator():
     waildmaskarray=['','','','']
     print(Fore.RED+'\n Your mask is: 0.0.0.0')
     x1=int(input(Fore.YELLOW+'\nFirst byte: '+Fore.WHITE))
     print(Fore.RED+'\n Your mask is: ',x1,'.0.0.0')
     x2=int(input(Fore.YELLOW+'\nSecond byte: '+Fore.WHITE))
     print(Fore.RED+'\n Your mask is: ',x1,'.',x2,'.0.0')
     x3=int(input(Fore.YELLOW+'\nTherd byte: '+Fore.WHITE))
     print(Fore.RED+'\n Your mask is: ',x1,'.',x2,'.',x3,'.0')
     x4=int(input(Fore.YELLOW+'\nForth byte: '+Fore.WHITE))
     print(Fore.RED+'\n Your mask is: ',x1,'.',x2,'.',x3,'.',x4)
     array=[x1,x2,x3,x4]
     for i in range(len(array)):
        waildmaskarray[i]=255-array[i]
     waildmask=''
     for i in range(len(waildmaskarray)):
        if(i < 3):
            waildmask += str(waildmaskarray[i]) + "."
        else:
            waildmask += str(waildmaskarray[i])
     print(Fore.RED+'\nWaildmask is: ',waildmask)

def traceroute():
     print(Fore.RED+'\nmaximum of 30 hops')
     hostname = input(Fore.YELLOW+"\nWrite IP or domain : "+Fore.WHITE)
     for i in range(1, 30):
        pkt = IP(dst=hostname, ttl=i) / UDP(dport=33434)
        reply = sr1(pkt, verbose=0)
        if reply is None:
            break
        elif reply.type == 3:
            print (Fore.RED+"\nYour target hop %d: " % i , reply.src)
            break
        else:
            print (Fore.RED+"\nHop %d: " % i , reply.src)

def decimal_to_binary(decimal_number):
  if decimal_number == 0:
    return '0'
  else:
    remainder = decimal_number % 2
    quotient = decimal_number // 2
    return decimal_to_binary(quotient) + str(remainder)

def IPbinary():
    IP=['','','','']
    print(Fore.RED+'\n Your IP is: 0.0.0.0')
    x1=int(input(Fore.YELLOW+'\nFirst byte: '+Fore.WHITE))
    print(Fore.RED+'\n Your IP is: ',x1,'.0.0.0')
    x2=int(input(Fore.YELLOW+'\nSecond byte: '+Fore.WHITE))
    print(Fore.RED+'\n Your IP is: ',x1,'.',x2,'.0.0')
    x3=int(input(Fore.YELLOW+'\nTherd byte: '+Fore.WHITE))
    print(Fore.RED+'\n Your IP is: ',x1,'.',x2,'.',x3,'.0')
    x4=int(input(Fore.YELLOW+'\nForth byte: '+Fore.WHITE))
    print(Fore.RED+'\n Your IP is: ',x1,'.',x2,'.',x3,'.',x4)
    array=[x1,x2,x3,x4]
    for i in range(len(array)):
        IP[i]= decimal_to_binary(array[i])
        byte=''
        for i in range(len(IP)):
            if(i < 3):
                byte += str(IP[i]) + "."
            else:
                byte += str(IP[i])
    print(Fore.RED+'\nIP is: ',byte)

def about_us():
    webbrowser.open("https://etclub-ksu.netlify.app/")

def main():
    while(True):
        print(Fore.BLUE +"""
              

  ██████████     ███     ██████████        ███      ▄██████▄   ▄██████▄ ▄▄▄        
  ███    ███ ▀█████████▄ ███    ███   ▀█████████▄ ███    ███ ███    ███ ███       
  ███    █▀     ▀███▀▀██ ███    █▀       ▀███▀▀██ ███    ███ ███    ███ ███       
 ▄███▄▄▄         ███   ▀ ███              ███   ▀ ███    ███ ███    ███ ███       
 ▀███▀▀▀         ███     ███              ███     ███    ███ ███    ███ ███       
  ███    █▄      ███     ███    █▄        ███     ███    ███ ███    ███ ███       
  ███    ███     ████    ███    ███       ███     ███    ███ ███    ███ ███    ▄█
  ██████████     █████▄  ██████████       █████▄   ████████▀  ████████▀ █████████       
        """)
        print(Fore.RED+"    Developed by: "+Fore.GREEN+"ETC members."+Fore.RED+"        v1.5\n")
        print(Fore.GREEN+"    ["+Fore.WHITE+"01"+Fore.GREEN+"]"+Fore.CYAN+" Find domain IP")
        print(Fore.GREEN+"    ["+Fore.WHITE+"02"+Fore.GREEN+"]"+Fore.CYAN+" Find domain info")
        print(Fore.GREEN+"    ["+Fore.WHITE+"03"+Fore.GREEN+"]"+Fore.CYAN+" Port Scanner")
        print(Fore.GREEN+"    ["+Fore.WHITE+"04"+Fore.GREEN+"]"+Fore.CYAN+" Shift left with key")
        print(Fore.GREEN+"    ["+Fore.WHITE+"05"+Fore.GREEN+"]"+Fore.CYAN+" AES encryption")
        print(Fore.GREEN+"    ["+Fore.WHITE+"06"+Fore.GREEN+"]"+Fore.CYAN+" DES encryption")
        print(Fore.GREEN+"    ["+Fore.WHITE+"07"+Fore.GREEN+"]"+Fore.CYAN+" Waildmask calculator")
        print(Fore.GREEN+"    ["+Fore.WHITE+"08"+Fore.GREEN+"]"+Fore.CYAN+" Trace route")
        print(Fore.GREEN+"    ["+Fore.WHITE+"09"+Fore.GREEN+"]"+Fore.CYAN+" IP to binary")
        print(Fore.GREEN+"    ["+Fore.WHITE+"99"+Fore.GREEN+"]"+Fore.CYAN+" About US")
        print(Fore.GREEN+"    ["+Fore.WHITE+"00"+Fore.GREEN+"]"+Fore.CYAN+" Exit")
        chose=input(Fore.YELLOW+'\nEnter number: '+Fore.WHITE)
        if(chose == '1' or chose == '01'):
            fIP()
        elif(chose == '2' or chose == '02'):
            info()
        elif(chose == '3' or chose == '03'):
             port_scanner()
        elif(chose == '4' or chose == '04'):
            shift_left_key()
        elif(chose == '5' or chose == '05'):
            AES_encryption()
        elif(chose == '6' or chose == '06'):
             DES_encryption()
        elif(chose == '7' or chose == '07'):
             waildmask_calculator()
        elif(chose == '8' or chose == '08'):
             traceroute()
        elif(chose == '9' or chose == '09'):
             IPbinary()
        elif(chose == '99'):
            about_us()
        elif(chose == '0' or chose == '00'):
            exit()
        else:
            print(Fore.RED+"\nWrong input...")

main()