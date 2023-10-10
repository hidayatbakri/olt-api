import json
import random
import string
import telnetlib
import time

from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel

import re

users = {
    "admin": {
        "username": "admin",
        "full_name": "Admin",
        "email": "admin@example.com",
        "hashed_password": "2023kamuhebat!",
        "acc_token": "9309aa9699e17138af7081fb07d0d9fa:",
        "disabled": False,
    },
}

app = FastAPI()

def fake_hash_password(password: str):
    return password


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


class User(BaseModel):
    username: str
    email: str | None = None
    full_name: str | None = None
    disabled: bool | None = None


class UserInDB(User):
    hashed_password: str
    acc_token: str


def get_user(db, token: str):
    for username, user_dict in db.items():
        if user_dict.get("acc_token") == token:
            return UserInDB(**user_dict)


def fake_decode_token(token):
    # This doesn't provide any security at all
    # Check the next version
    user = get_user(users, token)
    return user

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    user = fake_decode_token(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)]
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.post("/token")
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user_dict = users.get(form_data.username)
    if not user_dict:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    user = UserInDB(**user_dict)
    hashed_password = fake_hash_password(form_data.password)
    if not hashed_password == user.hashed_password:
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    return {"access_token": f"{user.acc_token}", "token_type": "bearer"}


id_telnet = ''
host = ''
port = 0
username = ''
password = ''

def generate_random_id():
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(8))

try:
    with open("koneksi.json", "r") as file:
        koneksi = json.load(file)
except FileNotFoundError:
    koneksi = []

def simpan_ke_file():
    with open("koneksi.json", "w") as file:
        json.dump(koneksi, file, indent=4)

def print_koneksi():
    if not koneksi:
        print("Tidak ada koneksi tersimpan.")
    else:
        return koneksi

def tambah_koneksi(host, port, username, password):
    try:
        data_koneksi = {
            "id": generate_random_id(),  # Menambahkan ID acak
            "host": host,
            "port": port,
            "username": username,
            "password": password
        }
        koneksi.append(data_koneksi)
        simpan_ke_file()
        return {"message" : f"Koneksi berhasil ditambahkan. ID Koneksi: {data_koneksi['id']}" }
    except Exception as e:
        return {"message" : f"Gagal, {e}" }
        

def edit_koneksi(id, host, port, username, password):
    for data_koneksi in koneksi:
        try:
            if data_koneksi["id"] == id:
                data_koneksi["host"] = host or data_koneksi["host"]
                data_koneksi["port"] = port or data_koneksi["port"]
                data_koneksi["username"] = username or data_koneksi["username"]
                data_koneksi["password"] = password or data_koneksi["password"]
                
                simpan_ke_file()
                return {"message" : "Berhasil mengubah data"}
        except Exception as e:
                return {"message" : f"Gagal, {e}"}
    return {"message" : "ID Koneksi tidak ditemukan."}

def hapus_koneksi(id):
    for data_koneksi in koneksi:
        if data_koneksi["id"] == id:
            koneksi.remove(data_koneksi)
            simpan_ke_file()
            return {"message" : "Data berhasil dihapus"}

    return {"message" : "ID Koneksi tidak ditemukan."}

def telnet_by_id(id_koneksi):
    for data_koneksi in koneksi:
        if data_koneksi["id"] == id_koneksi:
            return data_koneksi
    return {"message" : "ID Koneksi tidak ditemukan."}

def extract_number(input_string):
    match = re.search(r'[-+]?\d*\.\d+|\d+', input_string)
    if match:
        return match.group()
    return None

onu_list = []
def processData(output, tipe):
    if tipe == "state":
        # Mencari indeks awal data yang dimulai dengan "OnuIndex"
        start_index = None
        lines = output.split("\n")
        for i, line in enumerate(lines):
            if line.strip().startswith("OnuIndex"):
                start_index = i
                break

        filtered_output = []
        for line in lines[start_index:]:
            if line.strip().startswith("ONU Number"):
                break
            filtered_output.append(line)

        filtered_output = "\n".join(filtered_output)

        lines = filtered_output.strip().split('\n')
        column_names = [value.strip().replace(" ", "").lower() for value in filtered_output.strip().split('\n')[0].split('  ') if value.strip()]

        onu_data = {}

        for line in lines[2:]:
            values = line.split()
            onu_index = values[0]
            onu_values = {}

            for i in range(0, len(column_names)):
                onu_values[column_names[i]] = values[i]

            onu_data[onu_index] = onu_values

        return onu_data
    if tipe == "uncfg":
        # Mencari indeks awal data yang dimulai dengan "OnuIndex"
        start_index = None
        lines = output.split("\n")
        for i, line in enumerate(lines):
            if line.strip().startswith("OnuIndex"):
                start_index = i
                break

        filtered_output = []
        for line in lines[start_index:]:
            if line.strip().startswith("@Rdp#"):
                break
            filtered_output.append(line)

        filtered_output = "\n".join(filtered_output)

        lines = filtered_output.strip().split('\n')
        column_names = [value.strip().replace(" ", "").lower() for value in filtered_output.strip().split('\n')[0].split('  ') if value.strip()]

        onu_data = {}

        for i, line in enumerate(lines[2:]):
            values = line.split()
            onu_index = i
            onu_values = {}

            for i in range(0, len(column_names)):
                onu_values[column_names[i]] = values[i]

            onu_data[onu_index] = onu_values

        return onu_data
    if tipe == "profile":
        start_index = output.find("ONU interface:")
        end_index = output.find("--More--")
        if start_index != -1 and end_index != -1:
            desired_output = output[start_index:end_index].strip()
        lines = desired_output.strip().split('\n')
        data_objek = {}
        for line in lines:
            bagian = line.split(':', 1)
            if len(bagian) == 2:
                key = bagian[0].strip().replace(" ", "").lower()
                value = bagian[1].strip()
                data_objek[key] = value
        return data_objek
    if tipe == "powers":
        data = {} 
        current_data_key = None  # Variabel untuk melacak kunci data saat ini

        blocks = output.split("@Rdp#\n")
        for i, block in enumerate(blocks):
            lines = block.strip().split('\n')

        for line in lines:
            line = line.strip()

            # Memeriksa apakah baris kosong
            if not line:
                continue
                
            if line.startswith('OLT'):
                current_data_key = f"gpon-onu_{onu_list[(len(data) + 1) - 1]}"  # Membuat kunci data baru
                data[current_data_key] = {}
            else:
                parts = line.split()
                if len(parts) >= 4:
                    direction = parts[0]
                    rx = parts[2]
                    tx = parts[3]
                    attenuation = parts[4]

                    rx_value = extract_number(rx)
                    tx_value = extract_number(tx)

                    data[current_data_key][direction] = {
                        "rx": rx_value,
                        "tx": tx_value,
                        "attenuation": attenuation,
                    }

        return data
    else:
        return {"message" : "Tipe yang tidak dikenali"}

@app.get("/api/gettelnet/", summary="Mengambil semua data telnet")
async def index_telnet(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    return print_koneksi()

@app.get("/api/telnet/{id}", summary="Detail telnet berdasarkan id")
async def show_telnet(id: str,
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    return telnet_by_id(id)

@app.delete("/api/telnet/{id}", summary="Hapus telnet berdasarkan id")
async def delete_telnet(id: str,
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    return hapus_koneksi(id)

class ParamTelnet(BaseModel):
    host: str
    port: int
    username: str
    password: str

@app.put("/api/telnet/{id}", summary="Edit telnet berdasarkan id")
async def update_telnet(id: str, ParamTelnet: ParamTelnet,
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    values = []
    for header, value in ParamTelnet:
        values.append(value)
    return edit_koneksi(id, values[0], values[1], values[2], values[3],)

@app.post("/api/telnet", summary="Tambah telnet baru")
async def update_telnet(ParamTelnet: ParamTelnet,
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    values = []
    for header, value in ParamTelnet:
        values.append(value)
    return tambah_koneksi(values[0], values[1], values[2], values[3],)

tn = None

@app.post("/api/olt/connect/{id}")
async def connect_olt(id: str,
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    global host, id_telnet, tn 
    try:
        telnet = telnet_by_id(id)
        id_telnet = telnet["id"]
        host = telnet["host"]
        port = telnet["port"]
        username = telnet["username"]
        password = telnet["password"]
        tn = telnetlib.Telnet(host, port)
        tn.write(username.encode("utf-8") + b"\n")
        tn.write(password.encode("utf-8") + b"\n")
        

        return {"message" : f"Berhasil terhubung ke olt {host}"}
    except Exception as e :
        id_telnet = ""
        host = ""
        port = ""
        username = ""
        password = ""
        return {"failed" : f"Tidak dapat tersambung ke perangkat, {e}"}

@app.get("/api/olt/getconnect")
async def get_connect_olt(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    global host, id_telnet
    try:
        return {"id" : id_telnet, "host" : host}
    except Exception as e :
        return {"message" : f"Gagal, {e}"}

@app.get("/api/olt/disconnect")
async def disconnect_olt(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    global host, id_telnet
    try:
        global tn 
        tn.close() 
        tn = None
        host = ""
        id_telnet = ""
        return {"message" : "Berhasil memutuskan koneksi"}
    except Exception as e:
        return {"message" : f"Sudah tidak ada koneksi"}
        
def getStateOlt():
    global tn, onu_list
    command = "show gpon onu state\n"
    time.sleep(1)
    # Mengirimkan perintah ke perangkat
    tn.write(command.encode("utf-8"))
    time.sleep(1)
    # Membaca output dari perangkat setelah menjalankan perintah
    output = tn.read_very_eager().decode("utf-8")
    output = processData(output, "state")
    for key, value in output.items():
        onu_list.append(value['onuindex'])
    return output

def getUncfgOlt():
    global tn
    try:
        command = "show gpon onu uncfg\n"
        # Mengirimkan perintah ke perangkat
        tn.write(command.encode("utf-8"))
        time.sleep(1)
        # Membaca output dari perangkat setelah menjalankan perintah
        output = tn.read_very_eager().decode("utf-8")
        output = processData(output, "uncfg")
        return output
    except Exception as e:
        return {"message" : f"Gagal, {e}"}

def find_available_port(getdata, index):
    available_port = f"{index}:1"  # Port default

    if getdata:
        # onu_indices = [item[index] for item in getdata]
        # onu_indices.pop()  # Menghapus elemen terakhir

        for onu_index in getdata:
            # Cek apakah onuindex sudah sesuai dengan format "X/X/X:X"
            if re.match(r'^\d+/\d+/\d+:\d+$', onu_index):
                rak, card, port_data = onu_index.split('/')
                port_card, port_extend = port_data.split(':')

                if onu_index == available_port:
                    if int(port_extend) < 256:
                        next_port_extend = int(port_extend) + 1
                        available_port = f"{rak}/{card}/{port_card}:{next_port_extend}"
                    elif int(port_card) < 16:
                        next_port_card = int(port_card) + 1
                        available_port = f"{rak}/{card}/{next_port_card}:1"
                    elif int(card) < 18:
                        next_card = int(card) + 1
                        available_port = f"{rak}/{next_card}/1:1"
                    else:
                        available_port = "Tidak tersedia."

    return available_port

class ParamConfig(BaseModel):
    onu: str

@app.post("/api/olt/availableport")
async def olt_available_port(ParamConfig:ParamConfig,
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    try:
        for key, value in ParamConfig :
            pattern = r'_(\d+/\d+/\d+)'
            match = re.search(pattern, value)

            if match:
                result = match.group(1)
            return {"data" : find_available_port(getStateOlt(), result)}
    except Exception as e:
        return {"message" : f"Gagal, {e}"}
    
@app.get("/api/olt/state")
async def olt_state(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    return getStateOlt()

@app.get("/api/olt/uncfg")
async def olt_uncfg(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    return getUncfgOlt()

@app.get("/api/olt/powers")
async def olt_profiles(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    # try:
        global tn, onu_list
        onu_list = []
        powers = {}
        output = None
        cmdPower = ""
        state = getStateOlt()
        # for key, value in state.items():
        #     onu_list.append(value['onuindex'])
        for onu in onu_list:
            cmdPower = f"show pon power attenuation gpon-onu_{onu}\n"
            tn.write(cmdPower.encode("utf-8"))
            time.sleep(0.5)

        output = tn.read_very_eager().decode("utf-8")

        # return output
        return processData(output, "powers")
        
    # except Exception as e :
    #     return {"message" : f"Gagal, tidak ada koneksi, {e}"}

@app.get("/api/olt/profiles")
async def olt_profiles(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    # try:
        global tn, id_telnet
        profiles = {}
        onu_list = []
        output2 = None

        # if onu_list:
        #     for onu in onu_list:
        #         cmdProfile = f"show gpon onu detail-info gpon-onu_{onu}\n;"
        #         tn.write(cmdProfile.encode("utf-8"))
        #         time.sleep(0.7)
        #         output2 = tn.read_very_eager().decode("utf-8")
        #         profiles[onu] = processData(output2, "profile")
        # else:
        state = getStateOlt()
        for key, value in state.items():
            onu_list.append(value['onuindex'])
        for onu in onu_list:
            cmdProfile = f"show gpon onu detail-info gpon-onu_{onu}\n;"
            tn.write(cmdProfile.encode("utf-8"))
            time.sleep(0.7)
            output2 = tn.read_very_eager().decode("utf-8")
            profiles[onu] = processData(output2, "profile")
        
        return profiles
    # except Exception as e :
    #     return {"message" : f"Gagal, tidak ada koneksi {e}"}

class ParamProfile(BaseModel):
    onu: str

@app.post("/api/olt/profile")
async def olt_profiles(ParamProfile:ParamProfile,
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    try:
        global tn, id_telnet
        for key, value in ParamProfile:
            cmdProfile = f"show gpon onu detail-info {value}\n;"
            tn.write(cmdProfile.encode("utf-8"))
            time.sleep(0.7)
            output2 = tn.read_very_eager().decode("utf-8")
            profile = processData(output2, "profile")
            profile["id_telnet"] = id_telnet
        return profile
    except Exception as e :
        return {"message" : f"Failed {e}"}

class ParamCommand(BaseModel):
    command: str

@app.post("/api/olt/command/{type}")
async def olt_profiles(ParamCommand:ParamCommand,
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    try:
        global tn
        for key, value in ParamCommand:
            tn.write(value.encode("utf-8"))
            time.sleep(1.5)
            tn.write("exit".encode("utf-8"))
            time.sleep(0.5)
            tn.write("exit".encode("utf-8"))
        if type == "delete" :
            getUncfgOlt()
        getStateOlt()
        return {"message" : f"success"}
    except Exception as e :
        return {"message" : f"Failed {e}"}

