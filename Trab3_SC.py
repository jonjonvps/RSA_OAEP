import random
import math
import sys
import hashlib
from random import randrange

# Funcao para escrever no arquivo de texo
def write(message, ms2):
  file = open("texto.txt", "a")
  msg = ms2 + ': '+ message + '\n\n'
  file.write(msg)
  file.close()

# funcao que vai ler da arquivo de texto as informacoes que precisa para descriptar
def read(arquivo):
  with open(arquivo) as file:
    for i in file:
      #print('i = ',i)
      if 'R:' in i:
        r = int(i[3:]) 
      elif 'lenMsg:' in i:
        lenMsg = int(i[8:])
      elif 'assinatura:' in i:
        sing = i[12:-1]
      elif 'base64:' in i:
        base64 = i[8:-1]
    
  file.close()
  
  return r, lenMsg, sing, base64

  

# Funcao que transforma a mensagen para base64
def base64_encode(msg):
  i = 0
  encode_base64 = ''
  sing = ''
  # Tabela que servirá de mapa para consulta
  base64table = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
  pd1 = 0

  # Realiza um padding caso o tamanho da mensagem seja multiplo de 3
  # Adicionando 'A' na mensagem, e '=' na variavel sing
  padding = len(msg) % 3
  if padding != 0:
    while padding < 3:
      msg += "A"
      sing += '='
      padding += 1
      pd1 += 1


  while i < len(msg):
    treechar = 0
    # Pega três caracteres por vez
    for j in range(0,3,1):
      
      # transforma o char da mensagem para int de acordo com a tabela ASCII
      n = ord(msg[i])
      i += 1
  
      # concatena os tres char juntos, fazendo shift adicionando 16 zeros no primeiro, 8 
      # no segundo, e nenhum no ultimo, creindo blocos de 24 bits
      treechar += n << 8 * (2-j)
    
    # consverte o bloco para base64, para isso ele realiza os sift para pegar blocos 
    # de seis em seis bits e realizar a operacao com AND com 64 transformando para base64
    encode_base64 += base64table[ (treechar >> 18) & 63 ] + base64table[ (treechar >> 12) & 63 ] + base64table[ (treechar  >> 6) & 63 ] + base64table[ treechar  & 63 ]
  # adiciona o paddind
  if padding != 0:
    encode_base64 = encode_base64[:-pd1]
    encode_base64 += sing  

  return encode_base64

# Processo inverso do base64_encode
def base64_decode(msg):
  i = 0
  decoded_base64 = ''
  base64table = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
  
  # Trocando os padding para 'A' e pegar a quantidade de '=', para saber o quanto descarta no final
  padding = 0
  padding = msg.count('=')
  msg = msg.replace('=','A')
  
  # pegar de 4 cahr por vez
  while i < len(msg):
    fourchar = 0
    for j in range(0,4,1):
      # cacatena os quatro char, realizando o mesmo processo de base64_encode, para obter os blocos
      # de 24 novamente, pesquisando na tabela
      fourchar += base64table.index( msg[i] ) << (18 - j * 6)
      i += 1
    
    # converte o bloco para ASCII novamente, realizando o mesmo processo de base64_encode
    decoded_base64 += chr( (fourchar >> 16 ) & 255 ) + chr( (fourchar >> 8 ) & 255 ) + chr( fourchar & 255 )

  
  # Removendo os padding
  decoded_base64 = decoded_base64[:len( decoded_base64 ) - padding]
  
  return decoded_base64

# Utilizamos o teste Miller-Rabin, com o intuito de através de testes probabilísticos 
# nós sabermos se um número num é primo de maneira eficiente.
def miller_rabin(num):
  # Teste para veificar se o número é par
  if num % 2 == 0:
      return False

  # Calculando o valor de w e q 
  # w é um contador para saber quantas vezes q foi dividido pela metade
  # q é transformado em par e dividido pela metade até até chegar em um número ímpar
  w = 0
  q = num - 1
  while q & 1 == 0:
    w += 1
    q //= 2
  
  # Quantidade de vezes que o teste será rodado para saber se o número é primo
  for _ in range(40):
    o = randrange(2, num - 1)
    x = pow(o, q, num)
    if x != 1 and x != num - 1:
      j = 1
      while j < w and x != num - 1:
          x = pow(x, 2, num)
          if x == 1:
              return False
          j += 1
      if x != num - 1:
          return False
  return True

# Gera numeros de 1024 bits, e eh mandado para verificar se eh primo
def generator():
  num = random.getrandbits(1024)
  while(miller_rabin(num) != True):
    num = random.getrandbits(1024)
  
  return num

# Gera um numero aleatorio de 2 até phi de n, e verifica se o MDC dele e do phi de n eh 1
def generator_E(num):
  e = random.randrange(2,num) 
  while(math.gcd(e,num) != 1):
    e = random.randrange(2,num) 

  return e

# Realiza a operacao para descobrir o D.
def generator_D(e,phiN):
  u = [1,0,phiN]
  v = [0,1,e]

  while(v[2] != 0):
    q = math.floor(u[2]//v[2])
    temp1 = u[0] - q * v[0]
    temp2 = u[1] - q * v[1]
    temp3 = u[2] - q * v[2]

    u[0],u[1],u[2] = v[0],v[1],v[2]
    v[0],v[1],v[2] = temp1, temp2, temp3
  
  if u[2] < 0:
    return u[1] + phiN
  else:
    return u[1]

# Converte um inteiro não negativo para uma string de 8 bits
def i2osp(integer: int, size: int = 4):
  return "".join([chr((integer >> (8 * i)) & 0xFF) for i in reversed(range(size))])

# É uma função de gerar uma máscara definida na Chave Pública de criptografia padrão
# definindo a mensagem e o tamanho para definar a mascara
def Mask_generation_function(text, length):
  cont = 0
  mask = ""
  while len(mask) < length:
    C = i2osp(cont, 4)
    hash = hashlib.new("sha3_512", text.encode())
    mask += hash.hexdigest()
    cont += 1
  return mask[:length]

# Decodificação da RSA usando OAEP
def RSA_OAEP_decoding(msg, lenMsg, n, d, r):
  
  k0 = int(math.ceil(r.bit_length() / 8))
  lenN = int(math.ceil(n.bit_length()/ 8))
  k1 = lenN - 2 * k0 - lenMsg - 2


  des_before_unpadding = pow(int(msg,16),d,n)

  X = (pow(2, 8 * (k0 + k1 + lenMsg + 1)) - 1) & des_before_unpadding

  Y = (pow(2, 8 * k0) - 1) & (des_before_unpadding >> 8 * (k0 + k1 + lenMsg + 1))

  # volta para o r original Y XOR H(X)
  r_decifras = int(Mask_generation_function(hex(X)[2:], k0), 16) ^ Y

  if r != r_decifras:
    return False

  # Volta para a mensagem com padding, msgpad = X XOR G(r)
  msg_padding = int(Mask_generation_function(hex(r_decifras)[2:], k0 + k1 + lenMsg + 1), 16) ^ X

  # volta ao estado inicial
  decrypt = (pow(2, 8 * lenMsg) - 1) & msg_padding 

  return hex(decrypt)[2:]


# Codificacao da RSA usando OAEP
def RSA_OAEP_encoding(msg, n, e, r):
  # Pega os valores em bytes
  lenMsg = len(msg)// 2
  lenN = int(math.ceil(n.bit_length() / 8))

  k0 = int(math.ceil(r.bit_length() / 8))
  # Calculando K1 para saber o tamanho do padding de 0
  k1 = lenN - 2 * k0 - lenMsg - 2

  # Verifica se 0 k1 eh negativo
  if k1 < 0:
    return False

    
  if sys.version_info < (3, 6):
    import sha3
  
  # transforma a mensagem para hash SHA3
  hash_msg = hashlib.new("sha3_512", msg.encode())
  hash_msg = hash_msg.hexdigest()

  # coloca o numero de 0 para adicionar na padding
  pad0 = '0' * k1 * 2

  padding = int(hash_msg + pad0 + '01' + msg, 16)

  # G expando o r para o tamanho da chave n, para realizar o xor com o padding.
  G = int(Mask_generation_function(hex(r)[2:], k0 + k1 + lenMsg + 1),16)
  X = padding ^ G

  # H reduz o tamanho d X para o tamanho de k0, para realizar o xor com o r
  H = int(Mask_generation_function(hex(X)[2:], k0),16)
  Y = r ^ H

  # junta o Y e o X
  crypto = '00' + hex(Y)[2:] + hex(X)[2:]

  crypto = int(crypto, 16)
  
  # realiza o criptografia RSA
  crypto = hex(pow(crypto, e, n))

  return crypto[2:]

# funcao que cria a assinatura do emissor, usando o texto original
# criando um hash para ele e criptografa com RSA, e transformando para base 64
def signature(msg,d,n):
  hash_msg = hashlib.new("sha3_512", msg.encode())
  hash_msg = hash_msg.hexdigest()
  #print('msg signature = ',msg)
  # Eh usado a chave privada, pois somente o emissor pode assinar ela
  # e evita que outras pode assinar por ele
  signature = hex(pow(int(hash_msg,16), d, n))
  signature_base64 = base64_encode(signature)
  return signature_base64

# Funcao de verificacao de assinatura onde o receptor verifica 
# se a assinatura eh mesmo que o hash da mensagen descriptografado
def verification(msg,signature64,e,n):
  #print('msg = ',msg)
  hash_msg = hashlib.new("sha3_512", msg.encode())
  hash_msg = hash_msg.hexdigest()

  signature_h = base64_decode(signature64)
  # descriptografa a assinatura que estava criptografado em RSA
  signature = hex(pow(int(signature_h,16), e, n))

  if hash_msg == signature[2:]:
    return True
  else:
    return False



def main():
  #------------------------------------------------
  # bloco que vai gerar as chaves da pessoa A e da pessoa B
  
  # limpa o arquivo de texto
  open('texto.txt', 'w').close()

  p_A = generator()
  q_A = generator()


  write(str(p_A),'P_A')
  write(str(q_A),'Q_A')

  p_B = generator()
  q_B = generator()

  write(str(p_B),'P_B')
  write(str(q_B),'Q_B')

  n_A = p_A*q_A
  n_B = p_B*q_B

  write(str(n_A),'N_A')
  write(str(n_B),'N_B')
  
  phiN_A = (p_A-1)*(q_A-1)
  phiN_B = (p_B-1)*(q_B-1)

  write(str(phiN_A),'PHIN_A')
  write(str(phiN_B),'phiN_A')  

  e_A = generator_E(phiN_A)
  e_B = generator_E(phiN_B)

  write(str(e_A),'E_A')
  write(str(e_B),'E_A')

  d_A = generator_D(e_A,phiN_A)
  d_B = generator_D(e_B,phiN_B)

  write(str(d_A),'D_A')
  write(str(d_B),'D_B')
  write('---------------------\n\n\n','-')
  #------------------------------------------------
  # bloco que criptografa, parte do emissor

  msg = input('Pessoa A digite uma mensagem: ')

  men = msg.encode('utf-8').hex()

  lenMsg = len(men) // 2
  len_str = str(lenMsg)
  write(len_str,'lenMsg')
  r = random.getrandbits(512)
  r_str = str(r)
  write(r_str,'R')

  # a pessoa A vai fazer a assinatura com sua chave privada
  sign64 = signature(men,d_A,n_A)
  write(sign64,'assinatura')

  # a pessoa A vai criptografar com a chave publica da pessoa B
  crypto = RSA_OAEP_encoding(men, n_B, e_B, r) 

  # codificar para base64
  text_base64 = base64_encode(crypto)
  write(text_base64,'base64')
  write('---------------------\n\n\n','-')

  #------------------------------------------------
  # bloco que descriptografa, parte de receptor

  # Recebe do arquivo .txt as informacoes necessaria para descriptografar
  r, lenMsg, sign64, textbase64 = read("texto.txt")

  # decodifica o texto da base64 para o normal
  textbase64 = base64_decode(textbase64)

  # manda descriptografar a mensagem com RSA OAEP
  descrypto = RSA_OAEP_decoding(textbase64,lenMsg, n_B, d_B, r)

  msg_descrypto = bytes.fromhex(descrypto).decode('utf-8')
  print('\nMensagem descriptografado pela pessoa B: ',msg_descrypto)

  # Parte que verifica se a assinatura esta correta
  if(verification(descrypto,sign64,e_A,n_A) == True):
    print('\n_________________Verificação correta!_________________\n')

  else:
    print('\n_________________Verificação incorreta!_________________\n')

  

  # Parte em que a pessoa B vai enviar a resposta para pessoa A
  #------------------------------------------------
  
  # bloco que criptografa, parte do emissor

  msg = input('Pessoa B digite uma mensagem: ')

  men = msg.encode('utf-8').hex()

  lenMsg = len(men) // 2
  len_str = str(lenMsg)
  write(len_str,'lenMsg')
  r = random.getrandbits(512)
  r_str = str(r)
  write(r_str,'R')
  # a pessoa B vai fazer a assinatura com sua chave privada
  sign64 = signature(men,d_B,n_B)
  write(sign64,'assinatura')

  # a pessoa B vai criptografar com a chave publica da pessoa A
  crypto = RSA_OAEP_encoding(men, n_A, e_A, r) 

  text_base64 = base64_encode(crypto)
  write(text_base64,'base64')

  #------------------------------------------------
  # bloco que descriptografa, parte de receptor

  # Recebe do arrquivo .txt as informacoes necessaria para descriptografar
  r, lenMsg, sign64, textbase64 = read("texto.txt")

  # decotifica o texto da base64 para o normal
  textbase64 = base64_decode(textbase64)

  # manda descriptografar a mensagem com RSA OAEP
  descrypto = RSA_OAEP_decoding(textbase64,lenMsg, n_A, d_A, r)

  msg_descrypto = bytes.fromhex(descrypto).decode('utf-8')
  print('\nMensagem descriptografado pela pessoa A: ',msg_descrypto)

  # Parte que verifica se a assinatura esta correta
  if(verification(descrypto,sign64,e_B,n_B) == True):
    print('\n_________________Verificação correta!_________________\n')
    #print('---------------------------------------------------\n')
  else:
    print('\n_________________Verificação incorreta!_________________\n')
    #print('---------------------------------------------------\n')
  
  #------------------------------------------------  

if __name__ == '__main__':
  main()