from flask import Flask, render_template, request, send_file
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import os

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
KEYS_FOLDER = "keys"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(KEYS_FOLDER, exist_ok=True)

# Generate RSA Key Pair
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    with open(f"{KEYS_FOLDER}/private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(f"{KEYS_FOLDER}/public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))


# Sign a Document
def sign_document(file_path):
    with open(f"{KEYS_FOLDER}/private_key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    with open(file_path, "rb") as f:
        document = f.read()

    signature = private_key.sign(
        document,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

    signature_path = f"{file_path}.sig"
    with open(signature_path, "wb") as f:
        f.write(signature)

    return signature_path


# Verify a Signature
def verify_signature(file_path, signature_path):
    with open(f"{KEYS_FOLDER}/public_key.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    with open(file_path, "rb") as f:
        document = f.read()

    with open(signature_path, "rb") as f:
        signature = f.read()

    try:
        public_key.verify(
            signature,
            document,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return "Signature is VALID ✅"
    except:
        return "Signature is INVALID ❌"


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/generate_keys', methods=['POST'])
def generate_keys_route():
    generate_keys()
    return "Keys Generated Successfully ✅"

@app.route('/sign', methods=['POST'])
def sign():
    file = request.files['file']
    file_path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(file_path)
    signature_path = sign_document(file_path)
    return send_file(signature_path, as_attachment=True)

@app.route('/verify', methods=['POST'])
def verify():
    file = request.files['file']
    signature = request.files['signature']

    file_path = os.path.join(UPLOAD_FOLDER, file.filename)
    signature_path = os.path.join(UPLOAD_FOLDER, signature.filename)

    file.save(file_path)
    signature.save(signature_path)

    result = verify_signature(file_path, signature_path)
    return result

if __name__ == '__main__':
    app.run(debug=True)
