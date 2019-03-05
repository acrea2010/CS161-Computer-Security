package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	// You neet to add with
	// go get github.com/nweaver/cs161-p2/userlib
	"github.com/nweaver/cs161-p2/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging etc
	"encoding/hex"

	// UUIDs are generated right based on the crypto RNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys
	"strings"

	// Want to import errors
	"errors"

	// optional
	_"strconv"

	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg
	// see someUsefulThings() below
)

// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var pk userlib.PKEEncKey
        var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("Key is %v, %v", pk, sk)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

// The structure definition for a user record
type User struct {
	Username string
	Password string
	Ds_sign []byte
	Pke_private []byte
	Uuid_filenames uuid.UUID

	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the user has a STRONG password
func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	userdata.Password = password 
	userdata.Username = username
	
	//Hash password using Argon2Key, using username as salt. This allows same uuid to be generated.
	b_password := []byte(password)
	salt := []byte(username)
	password_key := userlib.Argon2Key(b_password,salt,128)

	//obtain UUID
	user_id, _ := uuid.FromBytes(password_key[:16])

	//creating UUID for filenames 
	uuid_file_key, err := userlib.HMACEval(password_key[:16],[]byte("file"))
	uuid_filenames, _ := uuid.FromBytes(uuid_file_key[:16])
	userdata.Uuid_filenames = uuid_filenames

	// Digital Signatures
	ds_sign, ds_verify, err := userlib.DSKeyGen()

	//Public Key Encryption 
	pke_public, pke_private, err := userlib.PKEKeyGen()

	//save private keys in user struct
	userdata.Ds_sign, _ = json.Marshal(ds_sign)
	userdata.Pke_private, _ = json.Marshal(pke_private)

	//encrypt private keys using symmetric encryption
	byte1, _ := json.Marshal(ds_sign)
	byte2, _ := json.Marshal(pke_private)
	byteslice := append(byte1, byte2...)

	key, err := userlib.HMACEval(password_key[:16],[]byte(username))
	iv := userlib.RandomBytes(userlib.AESBlockSize)
	encrypt_keys := userlib.SymEnc(key[:16], iv, byteslice)

	//use digital signature to ensure data integrity in datastore
	//https://crypto.stackexchange.com/questions/3505/what-is-the-length-of-an-rsa-signature
	//signatures have length 256 bytes if they have a 2048-bit modulus
	signed_encryption, err := userlib.DSSign(ds_sign,encrypt_keys)

	//store private keys in Datastore
	userlib.DatastoreSet(user_id,append(encrypt_keys,signed_encryption...))

	//store public keys in keystore
	userlib.KeystoreSet(username + "1", pke_public)
	userlib.KeystoreSet(username + "2", ds_verify)

	return &userdata, err
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	userdata.Password = password 
	userdata.Username = username

	//obtain user_id (UUID) and decryption key
	b_password := []byte(password)
	salt := []byte(username)
	password_key := userlib.Argon2Key(b_password,salt,128)
	user_id, _ := uuid.FromBytes(password_key[:16])
	key, err := userlib.HMACEval(password_key[:16], []byte(username))

	//get uuid_filenames
	uuid_file_key, err := userlib.HMACEval(password_key[:16],[]byte("file"))
	uuid_filenames, _ := uuid.FromBytes(uuid_file_key[:16])
	userdata.Uuid_filenames = uuid_filenames

	//obtain public keys 
	ds_verify, _ := userlib.KeystoreGet(username + "2")

	//unlock information in datastore
	byteslice, _ := userlib.DatastoreGet(user_id)
	signature := byteslice[len(byteslice)-256:]
	encryption := byteslice[:len(byteslice)-256]

	//verify signature (maintain integrity and authenticity)
	err = userlib.DSVerify(ds_verify,encryption,signature)
	if err != nil {
		return userdataptr, errors.New("signature fail")
	}
	decryption := userlib.SymDec(key[:16], encryption)

	privatekeys := strings.Split(string(decryption),"}{")

	//save private keys in datastruct
	userdata.Ds_sign = []byte(privatekeys[0]+"}")
	userdata.Pke_private = []byte("{"+privatekeys[1])

	return userdataptr, nil
}

// This stores a file in the datastore.
//
// The name of the file should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {

	//store filename
	pke_public, _ := userlib.KeystoreGet(userdata.Username + "1")
	var pke_private userlib.PrivateKeyType
	json.Unmarshal(userdata.Pke_private, &pke_private)
	filenames_encrypted, okay := userlib.DatastoreGet(userdata.Uuid_filenames)
	if okay == false {
		encrypt_filename, _ := userlib.PKEEnc(pke_public, []byte(filename))
		userlib.DatastoreSet(userdata.Uuid_filenames, encrypt_filename)
	} else {
		encrypt_filename, _ := userlib.PKEDec(pke_private, filenames_encrypted)
		encrypt_filename = append(encrypt_filename,[]byte(","+filename)...)
		userlib.DatastoreDelete(userdata.Uuid_filenames)
		userlib.DatastoreSet(userdata.Uuid_filenames, encrypt_filename)
	}

	//generate uuid for file and pointer to data
	uuid_file := uuid.New()
	uuid_1 := uuid.New()

	//generate Mac & encryption key
	MAC_key := userlib.RandomBytes(16)
	AESkey := userlib.RandomBytes(16)
	iv := userlib.RandomBytes(userlib.AESBlockSize)

	//encrypt data message
	encrypt_message := userlib.SymEnc(AESkey, iv, data)
	signed_encryption, _ := userlib.HMACEval(MAC_key,encrypt_message)
	encryption := append(encrypt_message, signed_encryption...)


	//store message and filename
	userlib.DatastoreSet(uuid_1, encryption)

	//store uuid_1 (data) in uuid_file)
	uuid_1_json, _ := json.Marshal(uuid_1)
	userlib.DatastoreSet(uuid_file, uuid_1_json)

	//encrypt keys (MACkey, AESkey and uuid)
	uuid_file_json, _ := json.Marshal(uuid_file)
	byteslice := append(MAC_key, AESkey...)
	byteslice = append(byteslice, uuid_file_json...)
	encrypt_keys, _ := userlib.PKEEnc(pke_public, byteslice)

	//store keys in new uuid
	salt := []byte(userdata.Username + filename)
	argonkey := userlib.Argon2Key([]byte(userdata.Password), salt, 16)
	uuid_2, _ := uuid.FromBytes(argonkey)
	userlib.DatastoreSet(uuid_2, encrypt_keys)

	return
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.

func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	//retrive uuid and encrypted keys
	salt := []byte(userdata.Username + filename)
	argonkey := userlib.Argon2Key([]byte(userdata.Password), salt, 16)
	uuid_2, _ := uuid.FromBytes(argonkey)
	encryption, _ := userlib.DatastoreGet(uuid_2)

	//check for empty file
	if encryption == nil {
		return errors.New("file does not exist")
	}

	//decrypt keys
	var privatekey userlib.PrivateKeyType
	err = json.Unmarshal(userdata.Pke_private, &privatekey)
	decryption, err := userlib.PKEDec(privatekey, encryption)
	MAC_key := decryption[:16]
	AESkey := decryption[16:32]
	uuid_file_json := decryption[32:]
	var uuid_file uuid.UUID
	err = json.Unmarshal(uuid_file_json, &uuid_file)

	//obtain pointers to subfiles and add a new pointer
	new_uuid := uuid.New()
	new_uuid_json, _ := json.Marshal(new_uuid)
	uuids_json, _ := userlib.DatastoreGet(uuid_file)
	userlib.DatastoreDelete(uuid_file)
	uuids_json = append(uuids_json, new_uuid_json...)
	userlib.DatastoreSet(uuid_file, uuids_json)

	//encrypt additional data and save in new_uuid
	iv := userlib.RandomBytes(userlib.AESBlockSize)
	encrypt_data := userlib.SymEnc(AESkey, iv, data)
	signed_encryption, _ := userlib.HMACEval(MAC_key,encrypt_data)
	encrypt_message := append(encrypt_data, signed_encryption...)
	userlib.DatastoreSet(new_uuid, encrypt_message)

	return nil
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	//retrive uuid and encrypted keys
	salt := []byte(userdata.Username + filename)
	argonkey := userlib.Argon2Key([]byte(userdata.Password), salt, 16)
	uuid_2, _ := uuid.FromBytes(argonkey)
	encryption, _ := userlib.DatastoreGet(uuid_2)

	//check for empty file
	if encryption == nil {
		return nil, errors.New("File does not exist")
	}

	//decrypt keys
	var privatekey userlib.PrivateKeyType
	err = json.Unmarshal(userdata.Pke_private, &privatekey)
	decryption, err := userlib.PKEDec(privatekey, encryption)
	MAC_key := decryption[:16]
	AESkey := decryption[16:32]
	uuid_file_json := decryption[32:]
	var uuid_file uuid.UUID
	err = json.Unmarshal(uuid_file_json, &uuid_file)

	//verify signature using HMAC
	uuids_json, _ := userlib.DatastoreGet(uuid_file)

	var dataslice []byte
	for i:=0;i<len(uuids_json)/38;i++{
		var uuid_json []byte 
		if i != len(uuids_json)/38-1 {
			uuid_json = uuids_json[38*i:38*(i+1)]
		} else {
			uuid_json = uuids_json[38*i:]
		}

		var uuid uuid.UUID
		err = json.Unmarshal(uuid_json, &uuid)

		encrypted_file, _ := userlib.DatastoreGet(uuid)
		if encrypted_file == nil {
			return nil, errors.New("File does not exist!")
		}
		signature := encrypted_file[len(encrypted_file)-64:]
		encrypted_data := encrypted_file[:len(encrypted_file)-64]
		hmac_sign, _ := userlib.HMACEval(MAC_key, encrypted_data)
		okay := userlib.HMACEqual(hmac_sign,signature)
		if okay == false {
			return nil, errors.New("Signature does not match")
		}
		decrypted_data := userlib.SymDec(AESkey, encrypted_data)

		dataslice = append(dataslice, decrypted_data...)
	}

	return dataslice, nil
}

// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.
type sharingRecord struct {
	MAC_key []byte
	AESkey []byte
	Uuid_file userlib.UUID
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.

func (userdata *User) ShareFile(filename string, recipient string) (
	magic_string string, err error) {
	//finding the uuid_keys of filea and the encrypted keys
	salt := []byte(userdata.Username + filename)
	argonkey := userlib.Argon2Key([]byte(userdata.Password), salt, 16)
	uuid_keys, _ := uuid.FromBytes(argonkey)
	encryption, _ := userlib.DatastoreGet(uuid_keys)
	if encryption == nil {
		return
	}

	//decrypt keys
	var privatekey userlib.PrivateKeyType
	err = json.Unmarshal(userdata.Pke_private, &privatekey)
	decryption, err := userlib.PKEDec(privatekey, encryption)

	MAC_key := decryption[:16]
	AESkey := decryption[16:32]
	uuid_file_json := decryption[32:]
	var uuid_file uuid.UUID
	err = json.Unmarshal(uuid_file_json, &uuid_file)

	//initialising magic_string
	var shared_string sharingRecord
	shared_string.MAC_key = MAC_key
	shared_string.AESkey = AESkey
	shared_string.Uuid_file = uuid_file
	// shared_string.Uuid_keys = uuid_keys

	//encrypt string using publickey of recipient
	pke_recipient, okay := userlib.KeystoreGet(recipient+"1")
	if !okay {
		return
	}
	shared_string_json, err := json.Marshal(shared_string)
	magic_encrypted, err := userlib.PKEEnc(pke_recipient,shared_string_json)
	var signkey userlib.PrivateKeyType
	err = json.Unmarshal(userdata.Ds_sign, &signkey)
	magic_signed, err := userlib.DSSign(signkey,magic_encrypted)
	magic_string_json := append(magic_encrypted,magic_signed...)
	magic_string = string(magic_string_json)

	return magic_string, err
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	magic_string string) error {

	//check if filename has been used
	var privatekey userlib.PrivateKeyType
	json.Unmarshal(userdata.Pke_private, &privatekey)
	filenames_encrypted, okay := userlib.DatastoreGet(userdata.Uuid_filenames)
	if okay == true {
		filenames_json, _ := userlib.PKEDec(privatekey, filenames_encrypted)
		filenames := strings.Split(string(filenames_json),",")
		for i:=0;i<len(filenames);i++{
			if filenames[i] == filename {
				return errors.New("Error: You have a file with the same name")
			}
		}
	}

	//decrypt magic_string
	magic_string_json := []byte(magic_string)
	magic_signed := magic_string_json[len(magic_string_json)-256:]
	magic_encrypted := magic_string_json[:len(magic_string_json)-256]
	//1: check if it has been tampered with
	sender_verifykey, _ := userlib.KeystoreGet(sender+"2")
	err := userlib.DSVerify(sender_verifykey, magic_encrypted, magic_signed)
	//2: obtain Mac_key, AESkey and Uuid_file
	magic_decrypted, _ := userlib.PKEDec(privatekey, magic_encrypted)
	var magic sharingRecord
	json.Unmarshal(magic_decrypted, &magic)

	// store keys in new uuid
	salt := []byte(userdata.Username + filename)
	argonkey := userlib.Argon2Key([]byte(userdata.Password), salt, 16)
	uuid_new, _ := uuid.FromBytes(argonkey)
	var decrypt_keys []byte
	decrypt_keys = append(magic.MAC_key, magic.AESkey...)
	uuid_file_json, _ := json.Marshal(magic.Uuid_file)
	decrypt_keys = append(decrypt_keys, uuid_file_json...)

	//encrypt keys
	publickey, _ := userlib.KeystoreGet(userdata.Username+"1")
	encrypt_keys, _ := userlib.PKEEnc(publickey, decrypt_keys)
	userlib.DatastoreSet(uuid_new, encrypt_keys)

	return err
}

// Removes access for all others.
func (userdata *User) RevokeFile(filename string) (err error) {
	//get uuid_keys and encrypted keys
	salt := []byte(userdata.Username + filename)
	argonkey := userlib.Argon2Key([]byte(userdata.Password), salt, 16)
	uuid_keys, _ := uuid.FromBytes(argonkey)
	encrypted_keys, _ := userlib.DatastoreGet(uuid_keys)

	//decrypt encrypted keys and get uuid_files
	var privatekey userlib.PrivateKeyType
	json.Unmarshal(userdata.Pke_private, &privatekey)
	decrypted_keys, _ := userlib.PKEDec(privatekey, encrypted_keys)
	MAC_key := decrypted_keys[:16]
	AESkey := decrypted_keys[16:32]
	uuid_file_json := decrypted_keys[32:]
	var uuid_file uuid.UUID
	err = json.Unmarshal(uuid_file_json, &uuid_file)

	//get file data, erase old uuid and put file data into a new place
	data, _ := userlib.DatastoreGet(uuid_file)
	userlib.DatastoreDelete(uuid_file)
	new_uuid := uuid.New()
	userlib.DatastoreSet(new_uuid, data)

	//store new uuid for file
	uuid_json, _ := json.Marshal(new_uuid)
	keys := append(MAC_key, AESkey...)
	keys = append(keys, uuid_json...)
	publickey, _ := userlib.KeystoreGet(userdata.Username+"1")
	encrypted_keys, _ = userlib.PKEEnc(publickey, keys)
	userlib.DatastoreDelete(uuid_keys)
	userlib.DatastoreSet(uuid_keys, encrypted_keys)

	return err
}

