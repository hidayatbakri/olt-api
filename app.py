import json
import random
import string
import telnetlib
import time

from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel

import hashlib

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
    data_koneksi = {
        "id": generate_random_id(),  # Menambahkan ID acak
        "host": host,
        "port": port,
        "username": username,
        "password": password
    }
    koneksi.append(data_koneksi)
    simpan_ke_file()
    return {"message" : "Koneksi berhasil ditambahkan. ID Koneksi: " + data_koneksi["id"]}

def edit_koneksi(id, host, port, username, password):
    for data_koneksi in koneksi:
        if data_koneksi["id"] == id:
            data_koneksi["host"] = host or data_koneksi["host"]
            data_koneksi["port"] = port or data_koneksi["port"]
            data_koneksi["username"] = username or data_koneksi["username"]
            data_koneksi["password"] = password or data_koneksi["password"]
            
            simpan_ke_file()
            return {"message" : "Berhasil mengubah data"}

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


def processData(output, tipe):
    # menjalankan kode yang sesuai berdasarkan kondisi tersebut.
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
            if line.strip() == "ONU Number: 7/7":
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
    elif tipe == "profile":
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
    elif tipe == "powers":
        data = {}  # Membuat objek data kosong
        current_data_key = None  # Variabel untuk melacak kunci data saat ini

        blocks = output.split("@Rdp#\n")
        for i, block in enumerate(blocks):
            
            # Pisahkan data berdasarkan baris
            lines = block.strip().split('\n')

        for line in lines:
            # Menghapus karakter whitespace di awal dan akhir baris
            line = line.strip()

            # Memeriksa apakah baris kosong
            if not line:
                continue

            # Memeriksa apakah baris merupakan header atau data
            if line.startswith('OLT'):
                current_data_key = f"{onu_list[(len(data) + 1) - 1]}"  # Membuat kunci data baru
                data[current_data_key] = {}  # Membuat objek data baru dalam bentuk dictionary
            else:
                parts = line.split()
                if len(parts) >= 4:
                    direction = parts[0]
                    rx = parts[2]
                    tx = parts[3]
                    attenuation = parts[4]

                    # Menambahkan data ke objek data saat ini
                    data[current_data_key][direction] = {
                        "rx": rx,
                        "tx": tx,
                        "attenuation": attenuation,
                    }

        # Hasil data dalam bentuk objek JSON
        import json
        result = json.dumps(data, indent=4)
        return data
    else:
        # Kode untuk tipe selain "state"
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

@app.get("/api/olt/connect/{id}")
async def connect_olt(id: str,
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    try:
        telnet = telnet_by_id(id)
        host = telnet["host"]
        port = telnet["port"]
        username = telnet["username"]
        password = telnet["password"]

        global tn 
        tn = telnetlib.Telnet(host, port)
        tn.write(username.encode("utf-8") + b"\n")
        tn.write(password.encode("utf-8") + b"\n")

        return {"message" : f"Berhasil terhubung ke olt {host}"}
    except Exception as e :
        return {"message" : f"Tidak dapat tersambung ke perangkat, {e}"}

@app.get("/api/olt/disconnect")
async def disconnect_olt(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    try:
        global tn
        tn.close() 
        return {"message" : "Berhasil memutuskan koneksi"}
    except Exception as e:
        return {"message" : f"Sudah tidak ada koneksi"}
        
onu_list = []
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

@app.get("/api/olt/state")
async def olt_state(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    return getStateOlt()

@app.get("/api/olt/powers")
async def olt_profiles(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    try:
        global tn, onu_list
        powers = {}
        output = None
        cmdPower = ""
        if onu_list:
            for onu in onu_list:
                cmdPower = f"show pon power attenuation gpon-onu_{onu}\n"
                tn.write(cmdPower.encode("utf-8"))
                time.sleep(0.5)
        else:
            getStateOlt()
            for onu in onu_list:
                cmdPower = f"show pon power attenuation gpon-onu_{onu}\n"
                tn.write(cmdPower.encode("utf-8"))
                time.sleep(0.5)

        output = tn.read_very_eager().decode("utf-8")

        return processData(output, "powers")
        
    except Exception as e :
        return {"message" : f"Gagal, tidak ada koneksi"}

@app.get("/api/olt/profiles")
async def olt_profiles(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    try:
        global tn, onu_list
        profiles = {}
        output2 = None

        if onu_list:
            for onu in onu_list:
                cmdProfile = f"show gpon onu detail-info gpon-onu_{onu}\n;"
                tn.write(cmdProfile.encode("utf-8"))
                time.sleep(0.7)
                output2 = tn.read_very_eager().decode("utf-8")
                profiles[onu] = processData(output2, "profile")
        else:
            getStateOlt()
            for onu in onu_list:
                cmdProfile = f"show gpon onu detail-info gpon-onu_{onu}\n;"
                tn.write(cmdProfile.encode("utf-8"))
                time.sleep(0.7)
                output2 = tn.read_very_eager().decode("utf-8")
                profiles[onu] = processData(output2, "profile")


        return profiles
    except Exception as e :
        return {"message" : f"Gagal, tidak ada koneksi {e}"}

class ParamProfile(BaseModel):
    onu: str

@app.get("/api/olt/profile")
async def olt_profiles(ParamProfile:ParamProfile,
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    try:
        global tn
        for key, value in ParamProfile:
            cmdProfile = f"show gpon onu detail-info gpon-onu_{value}\n;"
            tn.write(cmdProfile.encode("utf-8"))
            time.sleep(0.7)
            output2 = tn.read_very_eager().decode("utf-8")
            profile = processData(output2, "profile")

        return profile
    except Exception as e :
        return {"message" : f"Failed {e}"}

