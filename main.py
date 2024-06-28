

import codecs

import struct
import siphash
from enum import Enum
from pydantic import BaseModel
from fastapi import FastAPI, Request, HTTPException,status, Query
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import sqlite3
import httpx
from httpx import AsyncClient
from httpx import Timeout

class TokenType(Enum):
    ADD_TIME = 1
    SET_TIME = 2
    DISABLE_PAYG = 3
    COUNTER_SYNC = 4
    INVALID = 10
    ALREADY_USED = 11

class OpenPAYGOTokenShared:
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
        token = int(token)
        token_base = int(token_base)
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

class OpenPAYGOTokenEncoder:
    @classmethod
    def generate_token(cls, secret_key, count, value=None, token_type=TokenType.ADD_TIME, starting_code=None, value_divider=1, restricted_digit_set=False, extended_token=False):
        secret_key = OpenPAYGOTokenShared.load_secret_key_from_hex(secret_key)
        if not starting_code:
            starting_code = OpenPAYGOTokenShared.generate_starting_code(secret_key)
        if token_type in [TokenType.ADD_TIME, TokenType.SET_TIME]:
            value = int(round(value * value_divider, 0))
            if not extended_token:
                max_value = OpenPAYGOTokenShared.MAX_ACTIVATION_VALUE
            else:
                max_value = OpenPAYGOTokenSharedExtended.MAX_ACTIVATION_VALUE
            if value > max_value:
                raise ValueError("The value provided is too high.")
        elif token_type == TokenType.DISABLE_PAYG:
            value = OpenPAYGOTokenShared.PAYG_DISABLE_VALUE
        elif token_type == TokenType.COUNTER_SYNC:
            value = OpenPAYGOTokenShared.COUNTER_SYNC_VALUE
        else:
            raise ValueError("The token type provided is not supported.")

        if extended_token:
            return cls.generate_extended_token(
                starting_code,
                secret_key,
                value,
                count,
                token_type,
                restricted_digit_set,
            )
        else:
            return cls.generate_standard_token(
                starting_code,
                secret_key,
                value,
                count,
                token_type,
                restricted_digit_set,
            )
#  Add more token type fromsettime and add time to payg and sync token type

    @classmethod
    def generate_standard_token(cls, starting_code=None, key=None, value=None, count=None, mode=TokenType.ADD_TIME, restricted_digit_set=False):
        starting_code_base = OpenPAYGOTokenShared.get_token_base(starting_code)
        token_base = cls._encode_base(starting_code_base, value)
        current_token = OpenPAYGOTokenShared.put_base_in_token(starting_code, token_base)
        new_count = cls._get_new_count(count, mode)
        for xn in range(0, new_count):
            current_token = OpenPAYGOTokenShared.generate_next_token(current_token, key)
        final_token = OpenPAYGOTokenShared.put_base_in_token(current_token, token_base)
        if restricted_digit_set:
            final_token = OpenPAYGOTokenShared.convert_to_4_digit_token(final_token)
            final_token = "{:015d}".format(final_token)
        else:
            final_token = "{:09d}".format(final_token)
        return new_count, final_token

    @classmethod
    def _encode_base(cls, base, number):
        if number + base > 999:
            return number + base - 1000
        else:
            return number + base

    @classmethod
    def generate_extended_token(cls, starting_code, key, value, count, mode=TokenType.ADD_TIME, restricted_digit_set=False):
        starting_code_base = OpenPAYGOTokenSharedExtended.get_token_base(starting_code)
        token_base = cls._encode_base_extended(starting_code_base, value)
        current_token = OpenPAYGOTokenSharedExtended.put_base_in_token(starting_code, token_base)
        new_count = cls._get_new_count(count, mode)
        for xn in range(0, new_count):
            current_token = OpenPAYGOTokenSharedExtended.generate_next_token(current_token, key)
        final_token = OpenPAYGOTokenSharedExtended.put_base_in_token(current_token, token_base)
        if restricted_digit_set:
            final_token = OpenPAYGOTokenSharedExtended.convert_to_4_digit_token(final_token)
            final_token = "{:020d}".format(final_token)
        else:
            final_token = "{:012d}".format(final_token)
        return new_count, final_token

    @classmethod
    def _encode_base_extended(cls, base, number):
        if number + base > 999999:
            return number + base - 1000000
        else:
            return number + base

    @classmethod
    def _get_new_count(cls, count, mode):
        current_count_odd = count % 2
        if mode in [TokenType.SET_TIME, TokenType.DISABLE_PAYG, TokenType.COUNTER_SYNC]:
            if current_count_odd:
                new_count = count + 2
            else:
                new_count = count + 1
        else:
            if current_count_odd:
                new_count = count + 1
            else:
                new_count = count + 2
        return new_count

# Create an instance of FastAPI
app = FastAPI()

class TokenResponse(BaseModel):
    generated_count: int
    generated_token: str

# Instantiate Jinja2Templates
templates = Jinja2Templates(directory="templates")

# Define endpoint to render the HTML page
@app.get("/", response_class=HTMLResponse)
async def render_page(request: Request):
    return templates.TemplateResponse("server.html", {"request": request})
class ProductInitRequest(BaseModel):
    oem_item_id: str
    secret_key: str
    initial_token: str
    token_type: int
    token_value: int
    token_count: int

class ProductDetails(BaseModel):
    secret_key: str
    last_code: int
    last_count: int
    token_type: str  # Assuming token_type is a string, adjust if it's different
    token_value: int

class TokenOperationRequest(BaseModel):
    oem_item_id: str
    value: int

GRAPHQL_ENDPOINT = "https://dev-federated-graphql-api.omnivoltaic.com/graphql"
AUTHORIZATION_HEADER = {
    'Authorization': 'Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InhqTTVuMytXY2d3S0k0aEd6Ry94UzhOb2IvNW1keTdSOGhNVVQ3ZW9aNjA9In0.eyJkZWxlZ2F0b3JFbWFpbCI6Im92ZXNUZXN0RGlzdHJpYnV0b3IzQG91dGxvb2suY29tIiwiZGVsZWdhdG9yUm9sZUlkIjoiNjE3NjZkMzlmNzRlZWI0NDBlMzRmMDk2IiwidXNlcklkIjpudWxsLCJzZXJ2aWNlcklkIjpudWxsLCJkaXN0cmlidXRvcklkIjoiNjE4MTFjYzJiZjVhM2Y4MWZiZWI1ZDQxIiwiZW1haWwiOiJvdmVzVGVzdERpc3RyaWJ1dG9yM0BvdXRsb29rLmNvbSIsInJvbGVJZCI6IjYxNzY2ZDM5Zjc0ZWViNDQwZTM0ZjA5NiIsInJvbGVOYW1lIjoiRElTVFJJQlVUT1IiLCJzZXJ2aWNlIjpudWxsLCJhdXRoSW5zdGFuY2UiOiI2MTc2NjhhMGY3NGVlYjE5NDYzNGVlODIiLCJkaXN0cmlidXRvclBlcm0iOm51bGwsInN1YlJvbGVJZCI6bnVsbCwiZGVmYXVsdEluc3RhbmNlIjpudWxsLCJkaXN0cmlidXRvckRlbGVnYXRlIjpmYWxzZSwiaWF0IjoxNzE5NTAyOTk3LCJleHAiOjE3MTk1ODkzOTd9.cDcF85cQjmfEy0OwrlbWP5dG1AvQ6uepukbFiV0OcP95B6jJNSnPLR5pS70CDFFo2b5ynr753cYuDaScnpD9hTcD3l2c9fn0mMxdmkxBiM5zkr2UxPWSZE67mrtPQLfCLANhnwq-z5_-SX5E0tIiylLdsnvmU7-Ho6w1h9006mE-VAvgxNKhjqVwIYfTWnY5jL_pFUv8CedAzh7CIp2LOaujeVTkSqpwMgRZmQz3-3whdPrNbJNDDVREoxBadGvYEs7guxM3aM-Mc4kMpRW5EocnzWgFReQndRJ0ckXU76Op1ga50pEHn9TmhQCfLKuxNSWlDXBrEuG3d5BcYZ4MHQ'  # Update your token here
}
async def fetch_product_details(oem_item_id: str):
    query = """
    query GetItemByOemItemId($oemItemId: ID!) {
        getItembyOemItemId(oemItemId: $oemItemId) {
            _id
            openTokencodeGen {
                _id
                secret_key
                generated_token
                token_type
                token_value
                token_count
            }
        }
    }
    """
    variables = {"oemItemId": oem_item_id}
    timeout_config = Timeout(30.0, connect=120.0)  # Read timeout of 10 seconds, connect timeout of 60 seconds

    # Use the custom timeout in the HTTP client
    async with httpx.AsyncClient(timeout=timeout_config) as client:
        response = await client.post(
            GRAPHQL_ENDPOINT,
            json={"query": query, "variables": variables},
            headers=AUTHORIZATION_HEADER
        )
        response_data = response.json()

        if "errors" in response_data:
            raise HTTPException(status_code=400, detail=str(response_data["errors"]))

        data = response_data.get("data", {}).get("getItembyOemItemId")
        if not data or not data.get("openTokencodeGen"):
            raise HTTPException(status_code=404, detail="Product details not found.")

        # Constructing the product details from the response
        openTokencodeGen = data["openTokencodeGen"]
        return ProductDetails(
            secret_key=openTokencodeGen["secret_key"],
            last_code=int(openTokencodeGen["generated_token"]),
            last_count=openTokencodeGen["token_count"],
            token_type=openTokencodeGen["token_type"],
            token_value=openTokencodeGen["token_value"]
        )
    
@app.post("/initialize_product/", status_code=status.HTTP_201_CREATED)
async def initialize_product(request: ProductInitRequest):
    # Decode the hex-encoded secret key before using it
    decoded_secret_key = OpenPAYGOTokenShared.load_secret_key_from_hex(request.secret_key)
    initial_token = OpenPAYGOTokenShared.generate_starting_code(decoded_secret_key)
    
    # Insert the new product data into the database
    print("Received request data:", request.json())

    # Update the token data during initialization
    update_response = await update_token_data(
        oem_item_id=request.oem_item_id,
        secret_key=request.secret_key,
        generated_token=str(initial_token),
        token_type=request.token_type,
        value=request.token_value,
        generated_count=request.token_count
    )

    if update_response:
        return {"message": "Product initialized and token data updated successfully.", "update_response": update_response}
    else:
        raise HTTPException(status_code=500, detail="Failed to update token data during initialization.")
@app.get("/fetch_latest_record/")
async def fetch_latest_record(oem_id: str = Query(..., description="The OEM ID to fetch the latest record for")):
    product_details = await fetch_product_details(oem_id)
    return {
        "oem_item_id": oem_id,
        "last_token": product_details.last_code,
        "token_type": product_details.token_type,
        "last_value": product_details.token_value,  # Adjust according to your actual data model
        "last_count": product_details.last_count,
        "secret_key": product_details.secret_key
    }


async def update_token_data(oem_item_id: str, secret_key: str, generated_token: str, token_type: str, value: int, generated_count: int):
    print(oem_item_id, secret_key, generated_token, token_type, value, generated_count)
    mutation = """
    mutation updateTokenData($input: UpdateTokenDataInput!) {
        updateTokenData(updateTokenDataInput: $input) {
            openTokencodeGen {
                generated_token
                token_value
                secret_key
                token_count
            }
        }
    }
    """
    variables = {
        "input": {
            "oem_item_id": oem_item_id,
            "generated_token": generated_token,
            "token_type": "ADD_TIME",
            "token_value": value,
            "token_count": generated_count,
            "secret_key": secret_key
        }
    }
    async with httpx.AsyncClient() as client:
        response = await client.post(
            GRAPHQL_ENDPOINT,
            json={"query": mutation, "variables": variables},
            headers=AUTHORIZATION_HEADER
        )
        response_data = response.json()
        print("this graphql mutation response", response_data)
        if response_data.get("errors"):
            raise HTTPException(status_code=400, detail=str(response_data["errors"]))
        return response_data["data"]["updateTokenData"]



@app.post("/operate_token/")
async def operate_token(request: TokenOperationRequest):
    try:
        product_details = await fetch_product_details(request.oem_item_id)
        if not product_details:
            raise HTTPException(status_code=404, detail="Product details not found for the given OEM ID.")

        # Convert token type from string to Enum
        try:
            token_type = TokenType[product_details.token_type]
        except KeyError:
            raise HTTPException(status_code=400, detail=f"Unsupported token type provided: {product_details.token_type}")

        # Validate and convert numeric fields
        try:
            last_code = int(product_details.last_code)
            last_count = int(product_details.last_count)
            value = int(request.value)
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e))

        # Generate token
        secret_key = (product_details.secret_key * 2)[:32]  # Repeat and slice to 32 characters
        generated_count, generated_token = OpenPAYGOTokenEncoder.generate_token(
            secret_key, last_count, value, token_type, last_code
        )
        # Save the generated token in the database
        update_response = await update_token_data(
            request.oem_item_id,
            product_details.secret_key,
            generated_token,
            token_type,
            value,
            generated_count
        )

        # Return the result as a JSON response
        return {
            "generated_token": generated_token,
            "token_type": token_type.name,
            "value": value,
            "generated_count": generated_count
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8100)
