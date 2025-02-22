from flask import Flask, render_template, request, jsonify
import os
import rsa
import pymongo
from bson.objectid import ObjectId

app = Flask(__name__)

# Connect to MongoDB
client = pymongo.MongoClient("mongodb://localhost:27017/")
db = client["digital_signature_db"]

# Collections
keys_collection = db["keys"]
signed_files_collection = db["signed_files"]
verified_files_collection = db["verified_files"]

# Folder to store uploaded files
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# -------------------
# 🔹 Generate Key Pair and Store in DB
# -------------------
@app.route('/generate_keys', methods=['POST'])
def generate_keys():
    public_key, private_key = rsa.newkeys(512)

    key_data = {
        "public_key": public_key.save_pkcs1().decode(),
        "private_key": private_key.save_pkcs1().decode()
    }

    inserted_key = keys_collection.insert_one(key_data)
    
    return jsonify({
        "message": "Key generated successfully!",
        "key_id": str(inserted_key.inserted_id)
    })

# -------------------
# 🔹 Sign Document and Store Signature in DB
# -------------------
@app.route('/sign', methods=['POST'])
def sign_document():
    if 'file' not in request.files or 'key_id' not in request.form:
        return jsonify({"error": "File and key are required"}), 400

    file = request.files['file']
    key_id = request.form['key_id']
    
    key_data = keys_collection.find_one({"_id": ObjectId(key_id)})
    if not key_data:
        return jsonify({"error": "Invalid key ID"}), 400

    private_key = rsa.PrivateKey.load_pkcs1(key_data["private_key"].encode())

    file_path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(file_path)

    with open(file_path, "rb") as f:
        file_data = f.read()

    signature = rsa.sign(file_data, private_key, "SHA-256")
    signature_path = file_path + ".sig"

    with open(signature_path, "wb") as sig_file:
        sig_file.write(signature)

    # Store signed file record
    signed_files_collection.insert_one({
        "file_name": file.filename,
        "file_path": file_path,
        "signature_path": signature_path,
        "key_id": key_id
    })

    return jsonify({
        "message": "Document signed successfully!",
        "signature_path": signature_path
    })

# -------------------
# 🔹 Verify Signature
# -------------------
@app.route('/verify', methods=['POST'])
def verify_signature():
    if 'file' not in request.files or 'signature' not in request.files or 'key_id' not in request.form:
        return jsonify({"error": "File, signature, and key are required"}), 400

    file = request.files['file']
    signature_file = request.files['signature']
    key_id = request.form['key_id']

    key_data = keys_collection.find_one({"_id": ObjectId(key_id)})
    if not key_data:
        return jsonify({"error": "Invalid key ID"}), 400

    public_key = rsa.PublicKey.load_pkcs1(key_data["public_key"].encode())

    file_data = file.read()
    signature_data = signature_file.read()

    try:
        rsa.verify(file_data, signature_data, public_key)
        verified_files_collection.insert_one({
            "file_name": file.filename,
            "verified_with_key": key_id,
            "status": "VALID"
        })
        return jsonify({"message": "✅ Signature is VALID"}), 200
    except rsa.VerificationError:
        verified_files_collection.insert_one({
            "file_name": file.filename,
            "verified_with_key": key_id,
            "status": "INVALID"
        })
        return jsonify({"message": "❌ Signature is INVALID"}), 400

@app.route('/keys', methods=['GET'])
def get_keys():
    keys = list(keys_collection.find({}, {"_id": 1}))  # Fetch only the key IDs

    formatted_keys = [
        {"key_id": str(key["_id"]), "label": f"Key {index + 1}"}
        for index, key in enumerate(keys)
    ]
    return jsonify(formatted_keys)


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
