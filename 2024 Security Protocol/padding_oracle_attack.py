from socket import socket, AF_INET, SOCK_STREAM
from threading import Thread
import time
import hashlib
import hmac

BUFFER_SIZE = 65536 # 수정 금지
#프로토콜 정의
protocol={0:"ClientHello",
          1:"ServerHello",
          2:"Certificate",
          3:"ServerHelloDone",
          4:"ClientKeyExcnage",
          5:"ChangeCipherSpec",
          6:"Finished",
          255:"Error code", 
          254:"ECHO Mode", 
          253:"Data Decryption Mode"}
protocol_str={"ClientHello":0,
            "ServerHello":1,
            "Certificate":2,
            "ServerHelloDone":3,
            "ClientKeyExcnage":4,
            "ChangeCipherSpec":5,
            "Finished":6,
            "Error code":255,
            "ECHO Mode":254,
            "Data Decryption Mode":253}

#for debug
#주고 받은 데이터를 출력하기 위한 디버깅용 함수
def print_packet(additional,data,enc=False):
    if enc:
        print (f"{additional} (raw)", data)
        print (f"{additional} (hex)", data.hex())
    else:
        print("♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡")
        protocol={0:"ClientHello",1:"ServerHello",2:"Certificate",3:"ServerHelloDone",4:"ClientKeyExcnage",5:"ChangeCipherSpec",6:"Finished",255:"Error code", 254:"ECHO Mode", 253:"Data Encryption Mode", 252:"Data Decryption Mode"}
        p = data[0]
        msg_len = int.from_bytes(data[1:5],"little")
        msg = data[5:5+msg_len]
        mac = data[5+msg_len:]
        ret = {"protocol":protocol[p], "Message_len":msg_len,"Message(bytes)":msg,"Message(Hex)":msg.hex(),"MAC":mac}
        import pprint
        print(f"{additional}")
        pprint.pprint(ret)   
        print("♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡\n\n\n")

    

#MINI TLS start
def start_mini_tls(server:socket):


    # 구현필요
    # 송신 (send_data 함수 사용)
    # 통신1. 난수 생성1. client_random = 
    # 통신1. Clienthello 송신(client_random)
    client_random = gen_random(32)

    if(len(client_random) != 32):
        print("메시지 길이 오류, 통신 종료")
        return 
    
    send_data(server, 0, client_random)
    
    # 수신 (get_data 함수 사용)
    # 통신2. ServerHello 수신(서버 난수) server_random = 
    #
    protocol, length, server_random = get_data(server)
    if(protocol != 1):
        print("protocol 값이 1이 아닙니다.")
        return 

    if(len(server_random) != 32):
        print("server random값이 32바이트가 아닙니다.")
        return 


    # 통신3. Certificate 수신(서버 인증서) #base64 인코딩 되어있으며, 디코딩없이 그대로 사용 가능 RSA_Encrypt 함수 사용 cp =  RSA_Encrypt(pub,pt)
    #
    certificate = get_data(server)[2]

 
    # 통신4. ServerHelloDone 수신()
    protocol, length, hello = get_data(server)

    if(protocol != 3 ):
        print("protocol 값이 3이 아닙니다.")
        return 
    

    if(hello!= b'\x01'):
        print("hello값이 1이 아닙니다.")
        return
    
    # 송신 (send_data 함수 사용)
    # 통신5. 난수 생성2. PreMasterSecret = 
    PreMasterSecret = gen_random(32)
    # 통신5. 생성한 난수를 서버의 인증서로 암호화 Encrypted_PreMasterSecret =  RSA_Encrypt(pub,PreMasterSecret)
    Encrypted_PreMasterSecret =  RSA_Encrypt(certificate, PreMasterSecret)
    # 통신5. ClientKeyExchange 송신(Encrypted_PreMasterSecret)
    send_data(server, 4, Encrypted_PreMasterSecret)
    # - PreMasterSecret, client_random, server_random을 활용한 MasterSecret 생성
    #    Hint.   HKDF(PreMasterSecret,"master secret",client_random,server_random,48)
    MasterSecret = HKDF(PreMasterSecret,"master secret",client_random,server_random,48)
    # - MasterSecret을 활용한 KEYBLOB 생성
    #    Hint.   HKDF(MasterSecret,"key expansion",client_random,server_random,96)
    BLOB = HKDF(MasterSecret,"key expansion",client_random,server_random,96)
    # - KEYBLOB 분리 (Client_MAC_KEY, Server_MAC_KEY, Client_Cipher_KEY, Server_Cipher_KEY, Client_Cipher_IV, Server_Cipher_IV)
    Client_MAC_KEY = BLOB[0:16]         #클라이언트가 보내는 메시지의 MAC값 계산용 키
    Server_MAC_KEY = BLOB[16:32]        #서버가 보내는 메시지의 MAC값 계산용 키

    Client_Cipher_KEY = BLOB[32:48]     #클라이언트가 메시지를 보낼 때 사용하는 암호화 키
    Server_Cipher_KEY = BLOB[48:64]     #서버가 메시지를 보낼 때 사용하는 암호화 키

    Client_Cipher_IV = BLOB[64:80]      #클라이언트가 메시지를 보낼 때 사용하는 IV
    Server_Cipher_IV = BLOB[80:96]      #서버가 메시지를 보낼 때 사용하는 IV
   
    

    

    # 통신6. ChangeCipherSepc 송신(0x1)
    send_data(server, 5, b'\x01')

    # 통신7. Finished 송신(0x1) 
    send_data(server, 6, b'\x01')
    
    # 수신 (get_data 함수 사용)
    # 통신8. ChangeCipherSpec 수신(0x1)

    protocol, length, spec = get_data(server)
    if(protocol != 5):
        print("protocol 값이 5이 아닙니다.")
        return 

    if(spec!= b'\x01'):
        print("spec값이 1이 아닙니다")
        return

    # 통신9. Finished 송신(0x1) 
    protocol, length, finish = get_data(server)
    if(protocol != 6):
        print("protocol 값이 6이 아닙니다.")
        return 

    if(finish!= b'\x01'):
        print("finish값이 1이 아닙니다")
        return
    
    # 핸드셰이크 종료
    print("♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡")
    print("Client Random: {}".format(client_random.hex()))
    print("Server Random: {}".format(server_random.hex()))
    print("PreMasterSecret: {}".format(PreMasterSecret.hex()))
    print("MasterSecret: {}".format(MasterSecret.hex()))
    print("BLOB: {}".format(BLOB.hex()))
    print("♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡")
    #ECHO_CLIENT(server,Client_MAC_KEY,Server_MAC_KEY,Client_Cipher_KEY,Server_Cipher_KEY,Client_Cipher_IV,Server_Cipher_IV)

    #DATA_DECRYPTION_CLIENT를 변수로 받기
    decrypted_key = DATA_DECRYPTION_CLIENT(server,Client_MAC_KEY,Server_MAC_KEY,Client_Cipher_KEY,Server_Cipher_KEY,Client_Cipher_IV,Server_Cipher_IV)
    decrypted_key = bytes.fromhex(decrypted_key[:48])

    #이미지 복호화 함수
    image_decrypt(decrypted_key)


#패딩 오라클 공격
def DATA_DECRYPTION_CLIENT(server,Client_MAC_KEY,Server_MAC_KEY,Client_Cipher_KEY,Server_Cipher_KEY,Client_Cipher_IV,Server_Cipher_IV):
    #나의 cipher_text와 IV
    cipher_text = ('fff1446589ec4120735618ee86884df32bcf0b1bcee9504a5e5f780400068d55')
    IV = ('66c7ce770d79ea09cf9a91dec8c73f8b')

    #IV + cipher_text 
    IV_and_cipher_text = IV+cipher_text

    #암호문을 저장했다가 업데이트 하는식으로 평문
    plain_text = list(cipher_text)

    #브루트포스를 쓸 건지 빠른 탐색을 쓸 건지 물어보기
    #선택지 1, 2, 3 중 선택
    mode = select_mode()
    
    #선택지 1, 2번
    if (mode == 1) or (mode == 2):
        cipher_text, plain_text = select_1_2(cipher_text, IV, IV_and_cipher_text, plain_text, mode, server,Client_MAC_KEY,Server_MAC_KEY,Client_Cipher_KEY,Server_Cipher_KEY,Client_Cipher_IV,Server_Cipher_IV)
    
    #선택지 3번
    elif (mode == 3):
        cipher_text, plain_text = select_3(cipher_text, IV, IV_and_cipher_text, plain_text, mode, server,Client_MAC_KEY,Server_MAC_KEY,Client_Cipher_KEY,Server_Cipher_KEY,Client_Cipher_IV,Server_Cipher_IV)

        
            
    print_final_decryption(cipher_text, plain_text)
    #이미지 복호화할때 쓰려고 반환
    return ''.join(plain_text)

##########################################################################################################################################################
#패딩 오라클 공격에 쓰는 함수들##############################################################################################################################

#서버에 데이터를 보내는 함수
def send_attack_enc_data (soc:socket, protocol:int, msg:bytes, MAC_KEY, CIPHER_KEY, CIPHER_IV): 
    protocol_byte = protocol.to_bytes(1, "little")      
    msg_length = len(msg).to_bytes(4, "little")  
      
    data = protocol_byte + msg_length + msg           
    
    MAC = Calc_MAC(MAC_KEY, data)

    data_with_mac = data + MAC                          
    ciphertext = AES_CBC_Ecnrypt(CIPHER_KEY, CIPHER_IV, data_with_mac)
    
    time.sleep(0.5) 
    soc.sendall(ciphertext)
    
#데이터를 서버에서 받는 함수 
def get_attack_enc_data(soc:socket,SERVER_MAC_KEY,SERVER_CIPHER_KEY,SERVER_CIPHER_IV):
    
    data = soc.recv(BUFFER_SIZE)    
    #print_packet("Get(enc) : ",data,True)
    

    # 구현필요    
    #  1. 데이터 복호화 - AES_CBC_Decrypt 함수 활용
    decrypted_data = AES_CBC_Decrypt(SERVER_CIPHER_KEY, SERVER_CIPHER_IV, data)
    if not decrypted_data:
        raise ValueError("복호화 실패")             #복호화 실패하면 예외 처리
    
    decrypted_mac = decrypted_data[-16:]            #MAC값은 마지막 16바이트
    decrypted_payload = decrypted_data[:-16]        #나머지 데이터 -> 메시지의 페이로드

    #  2. MAC 값 검증 - Calc_MAC 함수 활용(HMAC-SHA256)
    calculated_mac = Calc_MAC(SERVER_MAC_KEY, decrypted_payload)
    if calculated_mac != decrypted_mac:
        raise ValueError("MAC 값이 일치하지 않습니다. 데이터 위변조 가능성이 있습니다.") #계산한 MAC과 수신한 MAC값을 서로 비교
    #  3. 복호화된 데이터(프로토콜 || 메시지길이 || 메시지) 파싱 
    protocol = decrypted_payload[0]                                 #복호화 됬을때 첫번째 바이트 -> 프로토콜
    msg_len = int.from_bytes(decrypted_payload[1:5], "little")      #복호화 됬을때 다음 4바이트 -> 메시지 길이
    msg = decrypted_payload[5:]                                     #복호화 됬을때 나머지는 메시지

    
    if len(msg) != msg_len:                                         #메시지 실제 길이와 계산한 길이 맞는지 체크
        raise ValueError("메시지 길이가 일치하지 않습니다.")
    
    protocol = int(protocol)                                               #콘솔창에서 quit을 입력했을때 꺼지지 않는 문제가 있어서 해결
    
    return (protocol, msg_len, msg, calculated_mac)

#이미지 복호화를 하는 함수
def image_decrypt(DECRYPTED_KEY):
    #조교님이 주신 코드 가져옴
    with open('C://Users//iamal//Desktop//2-2//protocol//TLS//MINI_TLS 2//22.png', 'rb') as f:

        data = f.read() #(들여쓰기 주의)

    iv = data[0:16]

    png_data = data[16:]

    #이미 있는 AES_CBC_Decrypt 함수를 가져와서 채워주기
    decrypted_image = AES_CBC_Decrypt(DECRYPTED_KEY, iv, png_data)
    
    #앞에가 png헤더랑 같은지 확인해보기
    if (decrypted_image[:8] == bytes.fromhex("89504e470d0a1a0a")):
        print("\n\n♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡\n")
        print("<<복호화 성공>>\n")
        print("♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡")
        #자꾸 파일 이상한데 저장되서 그냥 고정 시켜버림
        with open("C://Users//iamal//Desktop//2-2//protocol//TLS//MINI_TLS 2//22_result.png", "wb") as f:
            f.write(decrypted_image)
        print_image()

    else:
        print("파일 복호화 실패")

#이미지를 출력하는 함수
from PIL import Image
def print_image():
    try:
        image = Image.open("C://Users//iamal//Desktop//2-2//protocol//TLS//MINI_TLS 2//22_result.png")
        image.show()
    except Exception as e:
        print("오류 발생")

#데이터 송수신을 하는 함수
def send_and_get_attack_message(server, msg_sent, Client_MAC_KEY, Client_Cipher_KEY, Client_Cipher_IV, Server_MAC_KEY, Server_Cipher_KEY, Server_Cipher_IV):
    #메시지 -> 서버
    send_attack_enc_data(server, 253, msg_sent, Client_MAC_KEY, Client_Cipher_KEY, Client_Cipher_IV)

    #서버 -> 메시지
    protocol, msg_len, msg_received, mac = get_attack_enc_data(server, Server_MAC_KEY, Server_Cipher_KEY, Server_Cipher_IV)

    if msg_received is None:
        raise ValueError("서버에서 메시지를 받지 못했습니다")

    #나중에 형변환 안해줘도 되서 편하다!
    return msg_received.decode()

#변조 진행 상태 출력 함수
def print_attack_progress(block_index, byte_index, candidate, msg_sent, response):
    #.hex() 바이트 -> 16진수 문자열
    #.decode() 바이트 -> 문자열
    #받은 메시지는 wrong padding 또는 OK+
    print(f"{block_index + 1}번째 블록, {byte_index + 1}번째 바이트를 {candidate:02x}로 변조 작업중...")
    print(f"보낸 메시지: \t\t{msg_sent.hex()}")
    print(f"받은 메시지: \t\t{response}")

#일부 복호화된 값 출력 함수
def print_partial_decryption(cipher_text, partial_plain_text):
    print("기존값 : \t\t{}".format(cipher_text))
    print("일부 복호화된 값 : \t{}\n\n".format(''.join(partial_plain_text)))

#최종 결과 출력 함수
def print_final_decryption(cipher_text, plain_text):
    print("♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡")
    print("복호화 완료")
    print("기존값 : \t\t{}".format(cipher_text))
    print("복호화된 값 : \t\t{}".format(''.join(plain_text)))
    print("♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡ ♥♡\n")

#브루트포스를 쓸 건지 빠른 탐색을 쓸 건지 물어보는 함수
def select_mode():
    print("\n\n\n<<모드를 선택하세요>>\n")
    print("1. 브루트포스")
    print("2. 미리 설정된 값을 사용한 빠른 탐색")
    print("3. 이진 탐색을 이용한 패딩 길이 탐색")


    mode = input("\n입력 (1, 2, or 3): \n").strip()

    if mode == "1":
        print("1번 브루트포스 모드 실행\n")
        return 1
    elif mode == "2":
        print("2번 빠른 탐색 모드 실행\n")
        return 2
    elif mode == "3":
        print("3번 패딩 길이 구하기 모드 실행\n")
        return 3
    else:
        print("잘못된 입력. 기본값으로 빠른 탐색 모드 실행.")
        return 2

#저장해둔 패딩값 -> 빠른 탐색
def skip_values(i, j, k):
    if i == 0:
        if (j == 0 and k < 0xf0) or (j == 1 and k != 0x47) or (j == 2 and k != 0x83) or (j == 3 and k != 0x8a) \
                or (j == 4 and k != 0xe3) or (j == 5 and k != 0x16) or (j == 6 and k != 0x59) or (j == 7 and k != 0x73) \
                or (j == 8 and k != 0xfd) or (j == 9 and k != 0xc5) or (j == 10 and k != 0xba) or (j == 11 and k != 0xa0) \
                or (j == 12 and k != 0x80) or (j == 13 and k != 0xee) or (j == 14 and k != 0xbe) or (j == 15 and k != 0x9d):
            return True
    if i == 1:
        if (j == 0 and k != 0xf2) or (j == 1 and k != 0x18) or (j == 2 and k != 0x56) or (j == 3 and k != 0xb1) \
                or (j == 4 and k != 0xa5) or (j == 5 and k != 0x85) or (j == 6 and k != 0xc6) or (j == 7 and k != 0x1a) \
                or (j == 8 and k != 0x55) or (j == 9 and k != 0x1e) or (j == 10 and k != 0x98) or (j == 11 and k != 0x31) \
                or (j == 12 and k != 0xb2) or (j == 13 and k != 0xd0) or (j == 14 and k != 0x5c) or (j == 15 and k != 0x16):
            return True
    return False

#패딩값 세팅 함수
def set_padding_values(Cq_1_prime, IV_xor_plaintext, j):
    for k in range(j):
        Cq_1_prime[(-2 - 2 * k): (-2 - 2 * k) + 2 or None] = format(
            int(''.join(IV_xor_plaintext)[(-2 - 2 * k): (-2 - 2 * k) + 2 or None], 16) ^ (j + 1), '02x'
        )

#패딩 길이를 구하는 함수
def calculate_padding_length(server, cipher_text, Client_MAC_KEY, Client_Cipher_KEY, Client_Cipher_IV, Server_MAC_KEY, Server_Cipher_KEY, Server_Cipher_IV):
    #패딩 최대 범위
    low, high = 0, 15
    cipher_text = list(cipher_text)

    while (low <= high):
        mid = (low + high) // 2  #이진 탐색의 중심값?

        #Cq_1_prime의 마지막 바이트를 변조해주기
        #Cq_1_prime[-2-2*mid:] = format(k, '02x')
        temp = int(''.join(cipher_text[2*mid:2*mid+2]), 16) ^ 0x01
        cipher_text[2*mid:2*mid+2] = f"{temp:02x}"


        #변조된 메시지를 생성
        msg_sent = bytes.fromhex(''.join(cipher_text))

        #서버에 메시지 전송 및 응답 확인 -> 만들어둔 데이터 송수신 함수 활용
        response = send_and_get_attack_message(server, msg_sent, Client_MAC_KEY, Client_Cipher_KEY, Client_Cipher_IV, Server_MAC_KEY, Server_Cipher_KEY, Server_Cipher_IV)

        #디버깅용...
        print("중간 값: {},\t 보낸 메시지: {}, 서버 응답: {}".format(mid+1, msg_sent.hex(), response))

        if response == "Wrong padding":
            #Wrong padding -> 더 작은 값을 탐색
            high = mid - 1
        elif response == "OK+":
            #OK+ -> 더 큰 값을 탐색
            low = mid + 1
        else:
            #그 외 무언가?
            print("예기치 않은 서버 응답: {}".format(response))
            break

    #low를 반환해주기
    return low

#1, 2번 선택 함수 
def select_1_2(cipher_text, IV, IV_and_cipher_text, plain_text, mode, server,Client_MAC_KEY,Server_MAC_KEY,Client_Cipher_KEY,Server_Cipher_KEY,Client_Cipher_IV,Server_Cipher_IV):
    ######################################################################################################################################
    ###############################반복문 1 시작##########################################################################################
    #암호문이 2블록 -> 각 블록 순회
    #1블록 = 16바이트 (다음 반복문에서)
    for i in range (2):

        #블록 끝나는데
        block = -32*i

        #Cq-1을 설정
        Cq_1 = IV_and_cipher_text[block -64: block -32 or None]
        
        #Cq를 설정
        Cq = IV_and_cipher_text[block -32: block or None]

        #Cq-1'를 설정
        Cq_1_prime = list(Cq_1)

        #IV_xor_plaintext를 설정
        #int(): str -> 정수
        #join: list -> str
        IV_xor_plaintext = list(format(int(Cq_1, 16) ^ int(''.join(plain_text[block-32 : block or None]), 16), '02x'))

        

        #1블록이 16 바이트 -> 각 바이트 순회
        ######################################################################################################################################
        ###############################반복문 2 시작##########################################################################################
        for j in range (16):
            #바이트도 이동해야하고 블록도 이동해야함
            #블록은 j에 영향 안받고 루프를 돌 때마다 바뀌는 값이 -2로 고정이다
            block -= 2
            
            #선택지 3번일때 패딩 길이 계산
            if ((mode == 3) and (i == 0)):
                padding_len = calculate_padding_length(server, Cq_1_prime, Cq, Client_MAC_KEY, Client_Cipher_KEY, Client_Cipher_IV, Server_MAC_KEY, Server_Cipher_KEY, Server_Cipher_IV)
                print("패딩 길이 : {} 바이트".format(padding_len))
                continue
            

            #패딩값 세팅 
            set_padding_values(Cq_1_prime, IV_xor_plaintext, j)

            
            #모든 바이트 돌려보기
            ######################################################################################################################################
            ###############################반복문 3 시작##########################################################################################
            #1바이트 = 8비트
            #2^8 = 256
            #00~FF까지 돌려보는거
            for k in range (256):
                #-(2*i) -> 한바이트 = 2글자 -> 한바이트씩 옮겨감
                '''1. Cq_1을 바꿔가면서 -> 서버전송'''
                #빠른 탐색 
                if (mode == 2) and skip_values(i, j, k):
                    continue
                
                #Cq_1값을 바꿔서 보내기
                Cq_1_prime[(-2-2*j): (-2-2*j)+2 or None] = format(k, '02x')

                #protocol_message가 총 48
                #[32:]인 이유 -> 마지막 블록만 

                #bytes로 바꾸기 
                msg_sent = bytes.fromhex(''.join(Cq_1_prime) + Cq)

                #메시지 송수신
                response = send_and_get_attack_message(server, msg_sent, Client_MAC_KEY, Client_Cipher_KEY, Client_Cipher_IV, Server_MAC_KEY, Server_Cipher_KEY, Server_Cipher_IV)

                #출력 함수
                print_attack_progress(i, j, k, msg_sent, response)

                #받은게 OK인지 wrong인지 체크
                '''2. 서버가 OK+를 보내주는지 체크'''
                #wrong이면 continue 걸어서 넘기기
                if(response == "Wrong padding"):
                    print("Wrong padding 입니다.\n\n")
                    continue

                #원본이랑 주작 값이 같은지 체크
                elif (response == "OK+"):
                    #예외 케이스
                    #끝 블록 끝 바이트를 주작할때 Cq_1을 그대로 보내면 패딩이 01이 아니여도 OK+를 받을수있어서 if문 걸어줘야 함
                    if((i == 0) and (j==0) and (Cq_1 == ''.join(Cq_1_prime))):
                        print("끝 블록 끝 바이트를 변조하다가 어딘가가 잘못되었다고 함\n")
                        continue
                    else: 
                        '''3. OK+이면 Cq-1' xor [패딩값] = IV_xor_plaintext'''
                        #1번째 바이트를 찾을 때 패딩값은 1, j = 0 -> 패딩값이 j랑 언제나 1차이남 -> 패딩값 = j + 1
                        IV_xor_plaintext[(-2-2*j): (-2-2*j)+2 or None] = format(int(''.join(Cq_1_prime[(-2-2*j): (-2-2*j)+2 or None]), 16) ^ (j + 1),'02x')


                        '''4. IV_xor_plaintext = Cq-1 xor P'''
                        '''5. plain_text = IV_xor_plaintext(D) xor Cq-1'''
                        #왜 block을 쓰나요? 블록이 여러개니까... 저장할 plaintext 위치를 설정하려면 block이 필요함
                        plain_text[block: block+2 or None] = format(int(''.join(IV_xor_plaintext)[(-2-2*j): (-2-2*j)+2 or None], 16) ^ int(Cq_1[(-2-2*j): (-2-2*j)+2 or None], 16),'02x')


                        #일부 복호화한 값을 출력
                        print_partial_decryption(cipher_text, plain_text)

                        break
                        #print("OK+ 입니다.\n\n")
                        #################################################################################################################################
                #####################################################################################################################################
            #########################################################################################################################################

    return (cipher_text, plain_text)

#3번 선택 함수 -> 너무 길어져서 걍 여기다 만들자
def select_3(cipher_text, IV, IV_and_cipher_text, plain_text, mode, server,Client_MAC_KEY,Server_MAC_KEY,Client_Cipher_KEY,Server_Cipher_KEY,Client_Cipher_IV,Server_Cipher_IV):
    for i in range (2):

            #블록 끝나는데
            block = -32*i

            #Cq-1을 설정
            Cq_1 = IV_and_cipher_text[block -64: block -32 or None]
            
            #Cq를 설정
            Cq = IV_and_cipher_text[block -32: block or None]

            #Cq-1'를 설정
            Cq_1_prime = list(Cq_1)

            #IV_xor_plaintext를 설정
            #int(): str -> 정수
            #join: list -> str
            IV_xor_plaintext = list(format(int(Cq_1, 16) ^ int(''.join(plain_text[block-32 : block or None]), 16), '02x'))

            #선택지 3번일때 패딩 길이 계산
            #일단 자꾸 뜨는거 귀찮아서 조건 걸어둔거... 이따 꺼야해
            if ((mode == 3) and (i == 0)):
                padding_len = calculate_padding_length(server, cipher_text, Client_MAC_KEY, Client_Cipher_KEY, Client_Cipher_IV, Server_MAC_KEY, Server_Cipher_KEY, Server_Cipher_IV)
                print("\n패딩 길이 : {} 바이트\n".format(padding_len))
                
                padding_str = f"{padding_len:02x}"  # '08'
                print("plaintext : \t\t{}\n\n".format(''.join(plain_text)))

                #두 바이트씩 뒤에서부터 설정
                for a in range(padding_len):  # 두 바이트씩 반복
                    plain_text[-(2 * a + 2):-(2 * a) or None] = padding_str
                    #print("패딩을 맞춰둔 값 : \t{}\n\n".format(''.join(plain_text)))
                
                #맞춘 패딩값
                print("패딩을 맞춰둔 값 : \t{}\n\n".format(''.join(plain_text)))

                IV_xor_plaintext = list(format(int(Cq_1, 16) ^ int(''.join(plain_text[block-32 : block or None]), 16), '02x'))


            for j in range (16):
                if((i==0) and (j<padding_len)):
                    block -= 2
                    continue
                
                block -= 2
                
                #패딩값 세팅 
                #set_padding_values(Cq_1_prime, IV_xor_plaintext, j)

                for k in range (256):

                    if (mode == 3) and skip_values(i, j, k):
                        continue

                    Cq_1_prime[(-2-2*j): (-2-2*j)+2 or None] = format(k, '02x')
 
                    msg_sent = bytes.fromhex(''.join(Cq_1_prime) + Cq)

                    response = send_and_get_attack_message(server, msg_sent, Client_MAC_KEY, Client_Cipher_KEY, Client_Cipher_IV, Server_MAC_KEY, Server_Cipher_KEY, Server_Cipher_IV)

                    print_attack_progress(i, j, k, msg_sent, response)

                    if(response == "Wrong padding"):
                        print("Wrong padding 입니다.\n\n")
                        continue

                    elif (response == "OK+"):

                        if((i == 0) and (j==0) and (Cq_1 == ''.join(Cq_1_prime))):
                            print("끝 블록 끝 바이트를 변조하다가 어딘가가 잘못되었다고 함\n")
                            continue
                        else: 
                            IV_xor_plaintext[(-2-2*j): (-2-2*j)+2 or None] = format(int(''.join(Cq_1_prime[(-2-2*j): (-2-2*j)+2 or None]), 16) ^ (j + 1),'02x')

                            plain_text[block: block+2 or None] = format(int(''.join(IV_xor_plaintext)[(-2-2*j): (-2-2*j)+2 or None], 16) ^ int(Cq_1[(-2-2*j): (-2-2*j)+2 or None], 16),'02x')

                            print_partial_decryption(cipher_text, plain_text)

                            break


    return (cipher_text, plain_text)


##########################################################################################################################################################
##########################################################################################################################################################
#ECHO_CLIENT START!
def ECHO_CLIENT(server,Client_MAC_KEY,Server_MAC_KEY,Client_Cipher_KEY,Server_Cipher_KEY,Client_Cipher_IV,Server_Cipher_IV):
    
    while True:
        
        # 구현필요
        # 메시지를 입력하기 (ex: msg = input("SendMsg:").encode())
        msg = input("SendMsg: ").encode()
        # 입력한 msg를 서버에 송신(send_enc_data 사용)
        send_enc_data(server, 254, msg, Client_MAC_KEY, Client_Cipher_KEY, Client_Cipher_IV)
        # 서버에서 반환한 메시지를 수신 (get_enc_data 사용)
        #get_enc_data(server, Server_MAC_KEY, Server_Cipher_KEY, Server_Cipher_IV)
        ##############################################
        
        # 만약 주고받은 메시지가 quit, QUIT, Quit 중 하나인경우 통신 종료
        protocol, msg_len, msg, mac = get_enc_data(server, Server_MAC_KEY, Server_Cipher_KEY, Server_Cipher_IV)
        if protocol == protocol_str["ECHO Mode"]:
            if (msg == b"quit") or (msg == b"QUIT") or (msg == b"Quit"):
                return

def send_enc_data(soc:socket, protocol:int, msg:bytes, MAC_KEY, CIPHER_KEY, CIPHER_IV):
    
    # 구현필요 (send data 참고) (|| <<- 연접 기호)
    # 1. MAC값 계산용 data 생성   data = 프로토콜 || 메시지길이 || 전송하고자 하는 메시지
    protocol_byte = protocol.to_bytes(1, "little")      #프로토콜을 1바이트로
    msg_length = len(msg).to_bytes(4, "little")         #메시지 길이를 4바이트 -> 길이
    data = protocol_byte + msg_length + msg             #프로토콜1바이트+길이4바이트+메세지 

    # 2. data에 대한 MAC값 계산 - Calc_MAC 함수 활용(HMAC-SHA256)
    MAC = Calc_MAC(MAC_KEY, data)

    # 3. (data || MAC) 암호화    ciphertext = enc(data||mac)  - AES_CBC_Encrypt 함수 활용 
    data_with_mac = data + MAC                          #계산된 MAC값
    ciphertext = AES_CBC_Ecnrypt(CIPHER_KEY, CIPHER_IV, data_with_mac)

                          


    time.sleep(0.5) 
    soc.sendall(ciphertext)
    
    #for debug
    print_packet("Send ->",data) 
    print_packet("Send(enc) ->",ciphertext,True)

def get_enc_data(soc:socket,SERVER_MAC_KEY,SERVER_CIPHER_KEY,SERVER_CIPHER_IV):
    
    data = soc.recv(BUFFER_SIZE)    
    print_packet("Get(enc) : ",data,True)
    

    # 구현필요    
    #  1. 데이터 복호화 - AES_CBC_Decrypt 함수 활용
    decrypted_data = AES_CBC_Decrypt(SERVER_CIPHER_KEY, SERVER_CIPHER_IV, data)
    if not decrypted_data:
        raise ValueError("복호화 실패")             #복호화 실패하면 예외 처리
    
    decrypted_mac = decrypted_data[-16:]            #MAC값은 마지막 16바이트
    decrypted_payload = decrypted_data[:-16]        #나머지 데이터 -> 메시지의 페이로드

    #  2. MAC 값 검증 - Calc_MAC 함수 활용(HMAC-SHA256)
    calculated_mac = Calc_MAC(SERVER_MAC_KEY, decrypted_payload)
    if calculated_mac != decrypted_mac:
        raise ValueError("MAC 값이 일치하지 않습니다. 데이터 위변조 가능성이 있습니다.") #계산한 MAC과 수신한 MAC값을 서로 비교
    #  3. 복호화된 데이터(프로토콜 || 메시지길이 || 메시지) 파싱 
    protocol = decrypted_payload[0]                                 #복호화 됬을때 첫번째 바이트 -> 프로토콜
    msg_len = int.from_bytes(decrypted_payload[1:5], "little")      #복호화 됬을때 다음 4바이트 -> 메시지 길이
    msg = decrypted_payload[5:]                                     #복호화 됬을때 나머지는 메시지

    
    if len(msg) != msg_len:                                         #메시지 실제 길이와 계산한 길이 맞는지 체크
        raise ValueError("메시지 길이가 일치하지 않습니다.")
    
    #protocol = int.from_bytes(protocol,"little") 
    protocol = int(protocol)                                               #콘솔창에서 quit을 입력했을때 꺼지지 않는 문제가 있어서 해결
    #print(f"Decrypted raw data: {decrypted_payload.hex()}")               #복호화된 데이터 hex로 출력
    print(f"Decrypted raw data: {msg.decode('utf-8')}")                    #복호화된 데이터 문자열로 출력

    return (protocol, msg_len, msg, calculated_mac)


#이 이하로는 주요 함수 구현 예시(그대로 사용하여도 됨)

#패킷 송신용 함수 그대로 사용 가능
def send_data(soc:socket, protocol:int,msg:bytes):
    p = protocol.to_bytes(1,"little") # int형 데이터를 byte로 변환
    msg_len = len(msg).to_bytes(4,"little") # 메시지 길이를 byte로 변환 - little endian 사용
    data = p+msg_len+msg # 패킷 데이터 : 프로토콜 || 메시지길이 || 메시지

    time.sleep(0.5)  #패킷을 너무 빠르게 전송하면 주고받기가 되지않기에 지연시간 추가
    soc.sendall(data) # 패킷 전송
    
    #for debug
    print_packet("Client>",data) # 보낸 데이터 보기용
    
#패킷 수신용 함수 그대로 사용 가능
def get_data(soc:socket):
    packetsize = 5
    
    data = soc.recv(BUFFER_SIZE)
    if len(data)<=packetsize: #protocol + message_len =5 
        return False # msg가 없는경우
    
    protocol= data[0] # 프로토콜 파싱
    
    msg_len = int.from_bytes(data[1:5],"little") #메시지 길이 파싱 (byte -> int)
    packetsize +=msg_len # 패킷 길이 = protocol(1바이트) + message_len(4바이트) + 실제 메시지길이
    
    if len(data)!= packetsize: # 패킷을 비정상적으로 받은 경우
        return False 
    
    msg = data[5:5+msg_len] # 메시지 파싱
        
    #for debug
    print_packet("Server<",data) # 받은 데이터 보기용
    
    return (protocol, msg_len, msg)




# 안전한 난수생성기 (num byte만큼 난수 생성)
def gen_random(num):
    import os
    return os.urandom(num)


# RSA로 암호화/ 인코딩된 인증서 넣으면 자동으로 인식
def RSA_Encrypt(pub,data):
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP as RSA_OAEP
    
    publickey = RSA.import_key(pub)
    encryptor = RSA_OAEP.new(publickey)
    ciphertext = encryptor.encrypt(data)
    return ciphertext


#AES CBC모드 암호화
def AES_CBC_Ecnrypt(key:bytes,iv:bytes,data:bytes)->bytes:
    from Crypto.Cipher import AES
    if len(key) not in [16,24,32]:
        print("AES Key length error")
        exit(1)
    if len(iv) != 16:
        print("IV length error")
        exit(1)
    
    # padding
    padlen = 16-len(data)%16
    pad = bytes([padlen]*padlen)
    data = data + pad
    
    cipher = AES.new(key,AES.MODE_CBC,iv)
    return cipher.encrypt(data)   
    

#AES CBC모드 복호화
def AES_CBC_Decrypt(key:bytes,iv:bytes,data:bytes)->bytes:
    from Crypto.Cipher import AES
    cipher = AES.new(key,AES.MODE_CBC,iv)
    pt = cipher.decrypt(data)
    
    #unpadding
    padlen = pt[-1]
    if padlen>16:
        print("padding check failed 1")
        return None
    
    pad = bytes([padlen]*padlen)
    if pt[-1*padlen : ] != pad:
        print("padding check failed 2")
        return None
    return pt[:-1*padlen]



#HMAC-SHA256 계산한 결과의 상위 16바이트 반환
def Calc_MAC(mackey,data):
    hmac_obj = hmac.new(mackey,digestmod=hashlib.sha256)
    hmac_obj.update(data)
    return hmac_obj.digest()[:16]


#HKDF 함수
def HKDF(Secret, label, c_random,s_random,outlen):
    if type(label)==str:
        label= label.encode()
    ret=b""
    seed = c_random+s_random
    while len(ret)<outlen:
        hmac_obj = hmac.new(Secret, digestmod=hashlib.sha256)
        hmac_obj.update(label+seed)
        digest =hmac_obj.digest()
        seed = digest[:]
        ret+=digest
    return ret[:outlen]

    


# 이 이하로 수정 금지
def main(server:socket):
    start_mini_tls(server)
    
if __name__=='__main__':
    
    HOST = "210.123.39.41"
    PORT = 33333
    ADDRESS = (HOST,PORT)
    server = socket(AF_INET, SOCK_STREAM)
    server.connect(ADDRESS)
    server.settimeout(360)
    main(server)    
    server.close()
    

