#정보보안암호수학과 20232106 정유진
from tkinter import *
import os #경로 검증해주는 라이브러리
import struct #바이너리 데이터를 특정 형식으로 해석해주는 라이브러리 -> 리틀 엔디안 사용하려고

#GUI로 파일 경로, 저장할 디렉토리의 경로 받아오기 -> 더 이상 터치 X
def input_GUI():
    root = Tk()
    root.geometry("300x200")
    
    #제목 출력
    label = Label(root, text = "두근 두근 파싱 프로그램", font = "Times 16 bold")
    label.pack()

    #파싱할 파일 경로 입력
    Label(root, text = "파싱할 파일 경로").pack()

    entry_current_address = Entry(root)
    entry_current_address.pack()

    #파싱할 파일 저장할 경로를 입력
    Label(root, text = "저장할 디렉토리 경로").pack()

    entry_directory_address = Entry(root)
    entry_directory_address.pack()

    #버튼 함수 
    #버튼을 누르면 주소를 받아온다
    #strip 사용해서 양쪽 따옴표 제거
    def button_clicked():

        root.current_address = entry_current_address.get().strip('"')
        root.directory_address = entry_directory_address.get().strip('"')
        root.quit()


    button = Button(root, text = "확인", width = 10, height = 2, command=button_clicked)
    button.pack()

    root.mainloop()
    root.destroy()

    #파싱할 파일 경로, 저장할 경로를 받아온다
    return root.current_address, root.directory_address

#파일 입출력 -> 더 이상 터치 X
def file_open(current_address):
    #파일 없으면 없다고 말해줌
    if not current_address or not os.path.exists(current_address):
        print(f"file not exist: {current_address}")
        return
    
    #try except 사용해서 예외처리해주기
    #바이트 데이터를 헥스 문자열로 반환해주는 라이브러리 사용해서 받아오기기
    try:
        with open(current_address, "rb") as f :
            data = f.read()
        return data
    except Exception as e:

        print(f"file open error: {e}")


#클러스터와 섹터 크기 구하기에 필요한것들을 클래스로 만들어 넣는다.
#근데 솔직히 전역변수 때려도 괜찮았을거 같음
class FAT32_info:
    #.decode('ascii')는 OEM Name, File System Type 처럼 문자인 경우에 변환하려고 넣어둠
    #.struct.unpack('<H' 은 리틀 엔디안을 사용하는 방법이라고 한다
    # 참고 링크 : https://docs.python.org/3/library/struct.html
    #슬라이싱은 피피티에 있는 범위 그대로 가져옴
    #생성자 안에 다 넣어버리기
    def __init__(self, data):
        self.jump_boot_code = data[0x00:0x03]

        self.oem_name = data[0x03:0x0A].decode('ascii').strip()

        self.bytes_per_sector = struct.unpack('<H', data[0x0B:0x0D])[0]

        self.sectors_per_cluster = data[0x0D]

        self.reserved_sector_count = struct.unpack('<H', data[0x0E:0x10])[0]

        self.num_of_fat = data[0x10]

        self.fat_size_32 = struct.unpack('<I', data[0x24:0x28])[0]

        self.fsinfo_offset = struct.unpack('<H', data[0x30:0x32])[0]

        self.file_system_type = data[0x52:0x59].decode('ascii').strip()

        self.root_directory_sector = 0 + self.reserved_sector_count + (2*self.fat_size_32)

    def __repr__(self):
        #Jump Boot Code가 b'\xebX'이렇게 출력되는게 마음에 들지 않아서...
        jump_boot_code_hex = ' '.join(format(byte, '02X') for byte in self.jump_boot_code)
        return (f"FAT32 Header:\n"
                f"  Jump Boot Code: {jump_boot_code_hex}\n"
                f"  OEM Name: {self.oem_name}\n"
                f"  Bytes per Sector: {self.bytes_per_sector}\n"
                f"  Sectors per Cluster: {self.sectors_per_cluster}\n"
                f"  Reserved Sector Count: {self.reserved_sector_count}\n"
                f"  Num of FAT: {self.num_of_fat}\n"
                f"  FAT Size 32: {self.fat_size_32}\n"
                f"  FSINFO Offset: {self.fsinfo_offset}\n"
                f"  File System Type: {self.file_system_type}\n"
                f"  Root Directory Sector: {self.root_directory_sector}\n"
                #f"  ISV_Cluster Lower Bytes: {self.ISV_cluster_lower_bytes}\n"
                )
    
#파일의 정보를 저장하는 클래스
class file_info:
    def __init__(self,data):
            #print(data.hex())
            #self.filename = bytes(data[0x04:0x08]).decode('ascii', 'ignore').strip()
            
            self.file_extension = bytes(data[0x08:0x0B]).decode('ascii', 'ignore').strip()
            
            self.attribute = data[0x0B]
            
            self.cluster_lower_bytes = struct.unpack('<H', bytes(data[0x1A : 0x1C]))[0]
            
            #file_size_hex = struct.unpack('<H', bytes(data[0x1C: ]))[0]
            self.file_size = struct.unpack('<I', bytes(data[0x1C:0x20]))[0]
    def __repr__(self):
        return (f"FAT32 Header:\n"
                    #f"  File Name: {self.filename}\n"
                    f"  File Extension: {self.file_extension}\n"
                    f"  Attribute: {self.attribute}\n"
                    f"  Cluster Lower Bytes : {self.cluster_lower_bytes}\n"
                    f"  File Size: {self.file_size}"
                    )

#파일을 저장한 폴더를 열어주는 함수 -> 더 이상 터치 X
def open_folder(folder_path):
    try:
        os.startfile(folder_path)
    except Exception as e:
        print(f"Error: {e}")

#GUI로 클러스터, 섹터 정보 등을 출력해주는 함수 -> 더 이상 터치 X
def output_GUI(message):
    root = Tk()
    root.geometry("400x350")

    label = Label(root, text=message, anchor="w", justify="left", font=("Arial", 14))
    label.pack(fill="both", padx=10, pady=10)

    #자동으로 안닫혀서 창을 닫는 함수 만들어줌줌
    def close_window():
        root.destroy()

    #닫힘 버튼
    close_button = Button(root, text="종료", font=("Arial", 14), command=close_window)
    close_button.pack(pady=10)

    root.mainloop()

#Reserved Sector Count로 가서 -> 클러스터 위치
#위치를 찾아서 범위만큼 잘라 -> 0000000000나오면 잘라 or 섹터 2개
#두개 두개로 붙여 
#반복문을 돌려서 잘라
#복구해
def search(directory_address, hex_data):
    cursor = hex_data[(fat_header.reserved_sector_count*fat_header.bytes_per_sector) + 8:]
    print(" ".join(f"{b:02X}" for b in cursor[:32]))

    index = 0
    skip_point = bytes.fromhex("FF FF FF 0F")
    end_point = bytes.fromhex("00 00 00 00")
    slice_size = 4
    cluster_count = 1
    flag = 0

    while index < len(cursor):
        cluster_count += 1
        flag += 1
        print(" ".join(f"{b:02X}" for b in cursor[index:index + 4]))
        if cursor[index:index + 4] == end_point:
            print("파일 탐색 종료")
            break

        #스킵할 패턴이면 건너뛰기
        #4바이트 뒤로 이동
        if cursor[index:index + 4] == skip_point:
            index += 4  
            continue
        
        cluster_data = int.from_bytes(cursor[index:index+4], byteorder="little")
        
        print(cluster_count)
        print(cluster_data)

        sector_a = fat_header.root_directory_sector + (cluster_count-2)*2
        sector_b = fat_header.root_directory_sector + (cluster_data-2)*2
        print("location a : ", sector_a)
        print("location b : ", sector_b)

        data_a = hex_data[sector_a*fat_header.bytes_per_sector:sector_a*fat_header.bytes_per_sector+fat_header.bytes_per_sector*2]
        data_b = hex_data[sector_b*fat_header.bytes_per_sector:sector_b*fat_header.bytes_per_sector+fat_header.bytes_per_sector*2]
        data = data_a + data_b
        #print(" ".join(f"{b:02X}" for b in data))
        #data = bytes(range(2048))  # 예제 데이터 (0x00 ~ 0x07FF)
        """
        for i in range(0, len(data), 16):
            print(" ".join(f"{byte:02X}" for byte in data[i:i+16]))

            # 512바이트(32줄)마다 빈 줄 추가
            if (i // 16 + 1) % 32 == 0:
                print()
        """
        print()

        if flag == 1:
            parsing(directory_address,data[32:])
        else:
            parsing(directory_address,data)
        #break
        index += slice_size

#파싱 함수 길이따라 잘라서 복구 함수로 보내는 역할
def parsing(directory_address,data):

    index = 0
    while index < len(data):
        filename = b""
        size = 32
        if data[index+11] == 0x0F:
            size += 32
            if data[index+43] == 0x0F:
                size += 32
        if size == 32:
            result = data[index:index+32]
            index += size
            filename = result[0x00:0x08]

        if size == 64:
            result = data[index:index+64]
            index += size
            filename = result[1:11]+result[14:26]+result[28:32]

        if size == 96:
            result = data[index:index+96]
            index += size
            filename = result[33:43]+result[46:58]+result[60:64]+result[1:11]+result[14:26]+result[28:32]
        
        i = 0
        final_filename = b""

        end_point = bytes.fromhex("FF FF")
        end_point２ = bytes.fromhex("00 00")

        while i<len(filename):
            if filename[i:i+2] == end_point or filename[i:i+2] == end_point2:
                final_filename = filename[:i]
                print(" ".join(f"{b:02X}" for b in final_filename))
                break
                
            i += 2
        if final_filename == b"":
            final_filename = filename
        print(final_filename.decode('utf-16le'))

        recover(directory_address,result,size, final_filename)


#섹터 위치, 오프셋 위치 구함
def recover(directory_address, result,size,filename):
    file_infos = file_info(result[size-32:])
    print(file_infos)
        
    #file sector와 offset의 길이를 구해줌
    file_sector_location = fat_header.root_directory_sector + (file_infos.cluster_lower_bytes-2)*fat_header.sectors_per_cluster
    print()
    print("  Sector Location : ",file_sector_location)

    offset_location = (file_sector_location*fat_header.bytes_per_sector)
    hex_offset_location = hex(offset_location)
    print("  Offset Location : ", hex_offset_location)
    print()

    

    #0x20 : 파일
    if int(file_infos.attribute)&0x20:
        #바로 복구
        #아까 구한 길이를 이용해서 원본 바이트 파일을 잘라옴
        final = hex_data[offset_location : offset_location + file_infos.file_size]

        #정해진 경로 + 아까 가져온 파일 이름 번호를 사용해 파일을 만들어서 내보내준다

        
        file_name = filename.decode('utf-8', errors='ignore').replace('FF FF', '').strip()
        print(directory_address)
        output_path = os.path.join(directory_address, f"{file_name}")

        print(output_path)
        output_path = output_path.replace("\x00", "")
        print(output_path)
        with open(output_path, 'wb') as f:
            f.write(final)
    

    


if __name__ == "__main__":
    file_address, directory_address = input_GUI()

    hex_data = file_open(file_address)

    #fat header 정보를 계산-저장-출력
    fat_header = FAT32_info(hex_data)
    print(fat_header)

    ##################################################################
    search(directory_address, hex_data)

    #지정해둔 저장용 폴더를 오픈해줌
    open_folder(directory_address)

    #fat header 정보를 GUI로 열어주기
    output_GUI(fat_header)
