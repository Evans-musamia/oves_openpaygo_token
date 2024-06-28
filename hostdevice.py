from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import os
import codecs
import struct
import pandas as pd
import siphash
from fastapi import FastAPI, Request, HTTPException,status, Query
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import os
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],  # Allow OPTIONS method
    allow_headers=["*"],
)
templates = Jinja2Templates(directory="templates")
@app.get("/", response_class=HTMLResponse)
async def render_page(request: Request):
    return templates.TemplateResponse("devices.html", {"request": request})
class TokenInput(BaseModel):
    token: str

class TokenType(object):
    ADD_TIME = 1
    SET_TIME = 2
    DISABLE_PAYG = 3
    COUNTER_SYNC = 4
    INVALID = 10
    ALREADY_USED = 11

class OpenPAYGOTokenShared(object):
    MAX_BASE = 999
    MAX_ACTIVATION_VALUE = 995
    PAYG_DISABLE_VALUE = 998
    COUNTER_SYNC_VALUE = 999
    TOKEN_VALUE_OFFSET = 1000

    @classmethod
    def get_token_base(cls, code):
        return int(code) % cls.TOKEN_VALUE_OFFSET

    @classmethod
    def put_base_in_token(cls, token, token_base):
        if token_base > cls.MAX_BASE:
            Exception("INVALID_VALUE")
        return token - cls.get_token_base(token) + token_base

    @classmethod
    def generate_next_token(cls, last_code, key):
        conformed_token = struct.pack(">L", last_code)
        conformed_token += conformed_token
        token_hash = cls.generate_hash(key, conformed_token)
        new_token = cls.convert_hash_to_token(token_hash)
        return new_token

    @classmethod
    def convert_hash_to_token(cls, this_hash):
        hash_int = struct.pack(">Q", this_hash)
        hi_hash = struct.unpack(">L", hash_int[0:4])[0]
        lo_hash = struct.unpack(">L", hash_int[4:8])[0]
        result_hash = hi_hash ^ lo_hash
        token = cls._convert_to_29_5_bits(result_hash)
        return token

    @classmethod
    def generate_starting_code(cls, key):
        starting_hash = OpenPAYGOTokenShared.generate_hash(key, key)
        return OpenPAYGOTokenShared.convert_hash_to_token(starting_hash)

    @classmethod
    def load_secret_key_from_hex(cls, secret_key):
        try:
            return codecs.decode(secret_key, "hex")
        except Exception:
            raise ValueError(
                "The secret key provided is not correctly formatted, it should be 32 "
                "hexadecimal characters. "
            )

    @classmethod
    def _convert_to_29_5_bits(cls, source):
        mask = ((1 << (32 - 2 + 1)) - 1) << 2
        temp = (source & mask) >> 2
        if temp > 999999999:
            temp = temp - 73741825
        return temp

    @classmethod
    def convert_to_4_digit_token(cls, source):
        restricted_digit_token = ""
        bit_array = cls._bit_array_from_int(source, 30)
        for i in range(15):
            this_array = bit_array[i * 2 : (i * 2) + 2]
            restricted_digit_token += str(cls._bit_array_to_int(this_array) + 1)
        return int(restricted_digit_token)

    @classmethod
    def convert_from_4_digit_token(cls, source):
        bit_array = []
        for digit in str(source):
            digit = int(digit) - 1
            this_array = cls._bit_array_from_int(digit, 2)
            bit_array += this_array
        return cls._bit_array_to_int(bit_array)

    @classmethod
    def generate_hash(cls, key, value):
        return siphash.SipHash_2_4(key, value).hash()

    @classmethod
    def _bit_array_to_int(cls, bit_array):
        integer = 0
        for bit in bit_array:
            integer = (integer << 1) | bit
        return integer

    @classmethod
    def _bit_array_from_int(cls, source, bits):
        bit_array = []
        for i in range(bits):
            bit_array += [bool(source & (1 << (bits - 1 - i)))]
        return bit_array


class OpenPAYGOTokenDecoder(object):
    MAX_TOKEN_JUMP = 64
    MAX_TOKEN_JUMP_COUNTER_SYNC = 100
    MAX_UNUSED_OLDER_TOKENS = 2 * 2

    @classmethod
    def decode_token(
        cls,
        token,
        secret_key,
        count,
        used_counts=None,
        starting_code=None,
        value_divider=1,
        restricted_digit_set=False,
    ):
        secret_key = OpenPAYGOTokenShared.load_secret_key_from_hex(secret_key)
        if not starting_code:
            starting_code = OpenPAYGOTokenShared.generate_starting_code(secret_key)
        if not restricted_digit_set:
            if len(token) <= 9:
                extended_token = False
            elif len(token) <= 12:
                extended_token = True
            else:
                raise ValueError("Token is too long")
        elif restricted_digit_set:
            if len(token) <= 15:
                extended_token = False
            elif len(token) <= 20:
                extended_token = True
            else:
                raise ValueError("Token is too long")
        token = int(token)
        if not extended_token:
            (
                value,
                token_type,
                count,
                updated_counts,
            ) = cls.get_activation_value_count_and_type_from_token(
                token,
                starting_code,
                secret_key,
                count,
                restricted_digit_set,
                used_counts,
            )
        else:
            (
                value,
                token_type,
                count,
                updated_counts,
            ) = cls.get_activation_value_count_from_extended_token(
                token,
                starting_code,
                secret_key,
                count,
                restricted_digit_set,
                used_counts,
            )
        if value and value_divider:
            value = value / value_divider
        # Print the updated used counts
        print("Updated Used Counts:", updated_counts)
        return value, token_type, count, updated_counts

    @classmethod
    def get_activation_value_count_and_type_from_token(
        cls,
        token,
        starting_code,
        key,
        last_count,
        restricted_digit_set=False,
        used_counts=None,
    ):
        if restricted_digit_set:
            token = OpenPAYGOTokenShared.convert_from_4_digit_token(token)
        valid_older_token = False
        token_base = OpenPAYGOTokenShared.get_token_base(token)
        current_code = OpenPAYGOTokenShared.put_base_in_token(starting_code, token_base)
        starting_code_base = OpenPAYGOTokenShared.get_token_base(starting_code)
        value = cls._decode_base(starting_code_base, token_base)
        if value == OpenPAYGOTokenShared.COUNTER_SYNC_VALUE:
            max_count_try = last_count + cls.MAX_TOKEN_JUMP_COUNTER_SYNC + 1
        else:
            max_count_try = last_count + cls.MAX_TOKEN_JUMP + 1
        for count in range(0, max_count_try):
            masked_token = OpenPAYGOTokenShared.put_base_in_token(current_code, token_base)
            if count % 2:
                if value == OpenPAYGOTokenShared.COUNTER_SYNC_VALUE:
                    this_type = TokenType.COUNTER_SYNC
                elif value == OpenPAYGOTokenShared.PAYG_DISABLE_VALUE:
                    this_type = TokenType.DISABLE_PAYG
                else:
                    this_type = TokenType.SET_TIME
            else:
                this_type = TokenType.ADD_TIME
            if masked_token == token:
                if cls._count_is_valid(count, last_count, value, this_type, used_counts):
                    updated_counts, token_already_used = cls.update_used_counts(used_counts, count)
                    if token_already_used:
                        return None, TokenType.ALREADY_USED, None, used_counts
                    return value, this_type, count, updated_counts
                else:
                    valid_older_token = True
            current_code = OpenPAYGOTokenShared.generate_next_token(current_code, key)
        if valid_older_token:
            return None, TokenType.ALREADY_USED, None, used_counts
        return None, TokenType.INVALID, None, used_counts

    @classmethod
    def _count_is_valid(cls, count, last_count, value, type, used_counts):
        if value == OpenPAYGOTokenShared.COUNTER_SYNC_VALUE:
            if count > (last_count - cls.MAX_TOKEN_JUMP):
                return True
        elif count > last_count:
            return True
        elif cls.MAX_UNUSED_OLDER_TOKENS > 0:
            if count > last_count - cls.MAX_UNUSED_OLDER_TOKENS:
                if count not in used_counts and type == TokenType.ADD_TIME:
                    return True
        return False

    @classmethod
    def update_used_counts(cls, past_used_counts, new_count):
        if not past_used_counts:
            past_used_counts = []
        if new_count in past_used_counts:
            return past_used_counts, True  # Token already used
        past_used_counts.append(new_count)
        return past_used_counts, False

    @classmethod
    def _decode_base(cls, starting_code_base, token_base):
        decoded_value = token_base - starting_code_base
        if decoded_value < 0:
            return decoded_value + 1000
        else:
            return decoded_value

csv_file_path = 'valid_decoded_tokens.csv'
if os.path.exists(csv_file_path):
    decoded_tokens_df = pd.read_csv(csv_file_path)
else:
    columns = ["Token", "Decoded Value", "Token Type", "Decoded Count"]
    decoded_tokens_df = pd.DataFrame(columns=columns)
    secret_key_hex = "236432F2318504F7236432F2318504F7"
    secret_key = OpenPAYGOTokenShared.load_secret_key_from_hex(secret_key_hex)
    starting_code = OpenPAYGOTokenShared.generate_starting_code(secret_key)
    initial_row = {
        "Token": [starting_code],
        "Decoded Value": [0],
        "Token Type": [TokenType.ADD_TIME],
        "Decoded Count": [0]
    }
    decoded_tokens_df = pd.concat([decoded_tokens_df, pd.DataFrame(initial_row)], ignore_index=True)
    decoded_tokens_df.to_csv(csv_file_path, index=False)
    print(f"Initial token setup saved to CSV. Starting Code: {starting_code}, Count: 0")

@app.post("/decode-token/")
async def decode_token(token_input: TokenInput):
    global decoded_tokens_df  # Correct use of 'global' keyword
    try:
        if not token_input.token.isdigit():
            raise ValueError("Token must contain only numeric characters.")

        secret_key_hex = "236432F2318504F7236432F2318504F7"
        secret_key = OpenPAYGOTokenShared.load_secret_key_from_hex(secret_key_hex)
        last_code = int(decoded_tokens_df.iloc[-1]['Token'])
        count = int(decoded_tokens_df.iloc[-1]['Decoded Count'])
        used_counts = decoded_tokens_df['Decoded Count'].tolist()

        decoded_value, token_type, decoded_count, used_counts = OpenPAYGOTokenDecoder.decode_token(
            token_input.token, secret_key_hex, count, used_counts, starting_code=last_code
        )

        if token_type not in [TokenType.ALREADY_USED, TokenType.INVALID]:
            new_row = {
                "Token": [token_input.token],
                "Decoded Value": [decoded_value],
                "Token Type": [token_type],
                "Decoded Count": [decoded_count]
            }
            decoded_tokens_df = pd.concat([decoded_tokens_df, pd.DataFrame(new_row)], ignore_index=True)
            decoded_tokens_df.to_csv(csv_file_path, index=False)

        response = {
            "Token": token_input.token,
            "Decoded Value": decoded_value,
            "Token Type": token_type,
            "Decoded Count": decoded_count,
        }
        print(response)
        return response

    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)