package client

// CS 161 Project 2

// Only the following imports are allowed! ANY additional imports
// may break the autograder!
// - bytes
// - encoding/hex
// - encoding/json
// - errors
// - fmt
// - github.com/cs161-staff/project2-userlib
// - github.com/google/uuid
// - strconv
// - strings

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username    string
	SourceKey   []byte
	SharedFiles []string
	RSAPrivate  userlib.PKEDecKey
	DSPrivate   userlib.DSSignKey

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

type File struct {
	FilePointers    uuid.UUID
	HMACKey         []byte
	SymmetricEncKey []byte
	Invitations     map[string]uuid.UUID
}

type FilePointers struct {
	FileHeadUUID uuid.UUID
	FileTailUUID uuid.UUID
}

type FileText struct {
	Next          uuid.UUID
	EncryptedData []byte
	HMACVerify    []byte
}

type Invite struct {
	FilePointers    uuid.UUID
	HMACKey         []byte
	SymmetricEncKey []byte
}

type InvitePtr struct {
	InvitePtrUUID uuid.UUID
	DSSign        []byte
}

type Gift struct {
	Encrypted []byte
	Signature []byte
}

// NOTE: The following methods have toy (insecure!) implementations.

func IndividualGiftWrap(sourceKey []byte, v interface{}, purpose string) (marshalledGift []byte, err error) {
	// 1. Encrypt
	userStructEncryptionKey, err := userlib.HashKDF(sourceKey, []byte(purpose+"encrypt"))
	if err != nil {
		return nil, errors.New("Error generating hash to gift wrap")
	}
	iv := userlib.RandomBytes(16)
	plainText, err := json.Marshal(v)
	if err != nil {
		return nil, errors.New("Error marshalling struct")
	}
	encryptedUserStruct := userlib.SymEnc(userStructEncryptionKey[:16], iv, plainText)

	// 2. MAC: create a new key first
	userStructHMACKey, err := userlib.HashKDF(sourceKey, []byte(purpose+"mac"))
	if err != nil {
		return nil, errors.New("Error generating hash to gift wrap")
	}
	userStructMAC, err := userlib.HMACEval(userStructHMACKey[:16], encryptedUserStruct)
	if err != nil {
		return nil, errors.New("Error creating HMAC tag for gift wrap")
	}

	// 3. Marshal
	gift := Gift{
		Encrypted: encryptedUserStruct,
		Signature: userStructMAC,
	}
	return json.Marshal(gift)
}

// TODO: error handling, how to generate error
func IndividualGiftUnwrap(marshalledGift []byte, sourceKey []byte, purpose string, myInterface interface{}) (structPtr interface{}, err error) {
	// 1. Unmarshal
	var encryptedGift Gift
	json.Unmarshal(marshalledGift, &encryptedGift)

	// 2. check signature for integrity/authenticity
	signature := encryptedGift.Signature
	cipherText := encryptedGift.Encrypted
	userStructHMACKey, err := userlib.HashKDF(sourceKey, []byte(purpose+"mac"))
	if err != nil {
		return nil, errors.New("Error generating hash to gift unwrap")
	}
	userStructMAC, err := userlib.HMACEval(userStructHMACKey[:16], cipherText)
	if err != nil {
		return nil, errors.New("Error generating HMAC tag for unwrapping gift")
	}
	isAuthentic := userlib.HMACEqual(signature, userStructMAC)
	if !isAuthentic {
		// integrity and authenticity violated because HMAC tags are not equal
		return nil, errors.New("Integrity is violated")
	}

	// 3. Decrypt
	userStructEncryptionKey, err := userlib.HashKDF(sourceKey, []byte(purpose+"encrypt"))
	if err != nil {
		return nil, errors.New("Error generating hash to decrypt gift")
	}
	plainText := userlib.SymDec(userStructEncryptionKey[:16], cipherText)

	// TODO: fix err
	switch myInterface.(type) {
	case User:
		var userdata User
		json.Unmarshal(plainText, &userdata)
		return &userdata, nil
	case InvitePtr:
		var invitepointer InvitePtr
		json.Unmarshal(plainText, &invitepointer)
		return &invitepointer, nil
	case File:
		var fileStruct File
		json.Unmarshal(plainText, &fileStruct)
		return &fileStruct, nil
	default:
		return nil, nil
	}

}

// TODO: ERROR HANDLING
func InitUser(username string, password string) (userdataptr *User, err error) {
	_, userExists := userlib.KeystoreGet(username + "pk")
	if len(username) == 0 {
		return nil, errors.New("Username is empty")
	}
	if userExists {
		return nil, errors.New("User already exists efeef")
	}
	// compute source key
	salt := userlib.Hash([]byte(username))[:16]
	sourceKey := userlib.Argon2Key([]byte(password), salt, 16)

	// generate uuid using username and sourcekey
	userUUIDHash, err := userlib.HashKDF(sourceKey, []byte("useruuid"))
	if err != nil {
		return nil, errors.New("Error generating user UUID Hash")
	}
	userUUID, err := uuid.FromBytes(userUUIDHash[:16])
	if err != nil {
		return nil, errors.New("Init User: Byte array length greater than 16")
	}

	// generate key value pair and put in Keystore
	PKEEncryptionKey, PKEDecryptionKey, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, errors.New("Error generating Public Key for new user")
	}
	DSSignKey, DSVerifyKey, err := userlib.DSKeyGen()
	if err != nil {
		return nil, errors.New("Error generating DSKey for new user")
	}
	userlib.KeystoreSet(username+"pk", PKEEncryptionKey)
	userlib.KeystoreSet(username+"ds", DSVerifyKey)

	// store data in struct
	var userdata User
	userdata.Username = username
	userdata.SourceKey = sourceKey
	userdata.SharedFiles = make([]string, 0)
	userdata.RSAPrivate = PKEDecryptionKey
	userdata.DSPrivate = DSSignKey

	// marshal data struct and store in Datastore
	gift, err := IndividualGiftWrap(sourceKey, userdata, "userstruct")
	if err != nil {
		return nil, err
	}
	userlib.DatastoreSet(userUUID, gift)

	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	_, userExists := userlib.KeystoreGet(username + "pk")
	if !userExists {
		return nil, errors.New("User does not exist")
	}

	// compute source key
	salt := userlib.Hash([]byte(username))[:16]
	sourceKey := userlib.Argon2Key([]byte(password), salt, 16)

	// generate uuid using username and sourcekey
	userUUIDHash, err := userlib.HashKDF(sourceKey, []byte("useruuid"))
	if err != nil {
		return nil, errors.New("Error generating hash to get user")
	}
	userUUID, err := uuid.FromBytes(userUUIDHash[:16])
	if err != nil {
		return nil, errors.New("Get User: Byte array length greater than 16")
	}

	var userptrInterface User

	marshalledGift, ok := userlib.DatastoreGet(userUUID)
	if !ok {
		return nil, errors.New("Gift does not exist at UUID")
	}
	unwrappedData, err := IndividualGiftUnwrap(marshalledGift, sourceKey, "userstruct", userptrInterface)

	if err != nil {
		return nil, err
	}

	userData, ok := unwrappedData.(*User)
	if !ok {
		// Handle the case where unwrappedData is not of type User
		return nil, errors.New("Data is not of type User")
	}

	return userData, nil
}

func AddNodesToFileLL(content []byte, headPointer uuid.UUID, currPointer uuid.UUID, symmEncKey []byte, HMACKey []byte) (head uuid.UUID, curr uuid.UUID, err error) {
	// if head passed in is nil, then we know we need to set it as we are at the first Node in the LL
	// otherwise, it has already been set and we do not need to return a uuid for it

	// Likewise, if current is uuid.Nil then we know we are creating the first node in the LL
	for len(content) > 0 {
		dataSize := len(content)
		if dataSize > 128 {
			dataSize = 128
		}

		plainText := content[:dataSize]

		iv := userlib.RandomBytes(16)
		encryptedText := userlib.SymEnc(symmEncKey, iv, plainText)

		// 2. MAC: create a new key first
		textMAC, err := userlib.HMACEval(HMACKey, encryptedText)
		if err != nil {
			return uuid.Nil, uuid.Nil, errors.New("Append to shared file: error generating HMAC tag")
		}

		newNode := FileText{
			EncryptedData: encryptedText,
			HMACVerify:    textMAC,
			Next:          uuid.New(),
		}
		marshalledNewNode, err := json.Marshal(newNode)
		if err != nil {
			return uuid.Nil, uuid.Nil, err
		}

		//Create LL
		var currentNode FileText
		if currPointer != uuid.Nil {
			marshalledCurrentNode, _ := userlib.DatastoreGet(currPointer)
			json.Unmarshal(marshalledCurrentNode, &currentNode)
			userlib.DatastoreSet(currentNode.Next, marshalledNewNode)
			currPointer = currentNode.Next
		} else {
			currPointer = uuid.New()
			headPointer = currPointer
			userlib.DatastoreSet(currPointer, marshalledNewNode)
		}
		content = content[dataSize:]
	}
	return headPointer, currPointer, nil
}

func StoreSharedFile(userdata *User, filename string, content []byte) (err error) {
	sharedInviteStructHash, err := userlib.HashKDF(userdata.SourceKey, []byte(filename+"shared"))
	if err != nil {
		return errors.New("Error generating hash to store shared file")
	}
	sharedInviteStructUUID, err := uuid.FromBytes(sharedInviteStructHash[:16])
	if err != nil {
		return errors.New("Store Shared File: byte array length is greater than 16")
	}

	marshalledInvitePtr, ok := userlib.DatastoreGet(sharedInviteStructUUID)
	if !ok {
		return errors.New("Invite Pointer not found at UUID")
	}

	var invitePtrInterface InvitePtr
	unwrappedData, err := IndividualGiftUnwrap(marshalledInvitePtr, userdata.SourceKey, filename+"shared", invitePtrInterface)

	if err != nil {
		return err
	}

	invitePtr, ok := unwrappedData.(*InvitePtr)
	if !ok {
		// Handle the case where unwrappedData is not of type User
		return errors.New("Data is not of type InvitePtr")
	}

	var invite Invite
	marshalledInvite, ok := userlib.DatastoreGet(invitePtr.InvitePtrUUID)
	json.Unmarshal(marshalledInvite, &invite)

	if ok {
		// file exists in datastore, overwrite
		var filePtr FilePointers

		head, current, err := AddNodesToFileLL(content, uuid.Nil, uuid.Nil, invite.SymmetricEncKey, invite.HMACKey)
		if err != nil {
			return err
		}
		filePtr.FileHeadUUID = head
		filePtr.FileTailUUID = current

		marshalledFilePtr, err := json.Marshal(filePtr)
		if err != nil {
			return errors.New("Error marshalling file ptr")
		}

		userlib.DatastoreSet(invite.FilePointers, marshalledFilePtr)
		return nil
	}
	//if not ok, they got revoked and their kdf gave garbage
	return errors.New("User access to file is revoked")
}

func StoreOwnedFile(userdata *User, filename string, content []byte) (err error) {
	// file struct uuid
	ownedFileStructHash, err := userlib.HashKDF(userdata.SourceKey, []byte(filename+"owned"))
	if err != nil {
		return errors.New("Error generating hash to store owned file")
	}
	ownedFileStructUUID, err := uuid.FromBytes(ownedFileStructHash[:16])
	if err != nil {
		return errors.New("Store Owned File: byte length array greater than 16")
	}

	marshalledFileStruct, fileExists := userlib.DatastoreGet(ownedFileStructUUID)

	if fileExists {
		var fileStructInterface File
		unwrappedData, unwrapErr := IndividualGiftUnwrap(marshalledFileStruct, userdata.SourceKey, filename+"owned", fileStructInterface)
		// file exists in datastore, overwrite
		if unwrapErr != nil {
			return unwrapErr
		}

		fileStruct, isTypeFile := unwrappedData.(*File)
		if !isTypeFile {
			// Handle the case where unwrappedData is not of type User
			return errors.New("Data is not of type File")
		}

		var filePtr FilePointers
		head, current, err := AddNodesToFileLL(content, uuid.Nil, uuid.Nil, fileStruct.SymmetricEncKey, fileStruct.HMACKey)
		filePtr.FileHeadUUID = head
		filePtr.FileTailUUID = current

		marshalledFilePtr, err := json.Marshal(filePtr)
		if err != nil {
			return errors.New("error marshalling file ptr")
		}
		userlib.DatastoreSet(fileStruct.FilePointers, marshalledFilePtr)

	} else {
		// create a file since it does not exist
		var newFileStruct File
		newFileStruct.FilePointers = uuid.New()
		newFileStruct.HMACKey = userlib.RandomBytes(16)
		newFileStruct.SymmetricEncKey = userlib.RandomBytes(16)
		newFileStruct.Invitations = make(map[string]uuid.UUID)

		// call giftwrap
		gift, err := IndividualGiftWrap(userdata.SourceKey, newFileStruct, filename+"owned")
		if err != nil {
			return err
		}

		userlib.DatastoreSet(ownedFileStructUUID, gift)
		var filePtr FilePointers

		head, current, err := AddNodesToFileLL(content, uuid.Nil, uuid.Nil, newFileStruct.SymmetricEncKey, newFileStruct.HMACKey)
		if err != nil {
			return err
		}
		filePtr.FileHeadUUID = head
		filePtr.FileTailUUID = current

		marshalledFilePtr, err := json.Marshal(filePtr)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(newFileStruct.FilePointers, marshalledFilePtr)
	}
	return nil
}

// Account for overwriting case
func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	// go thru shared files to see if file is shared or not
	for _, file := range userdata.SharedFiles {
		if filename == file {
			err := StoreSharedFile(userdata, filename, content)
			return err
		}
	}
	storeOwnedFileError := StoreOwnedFile(userdata, filename, content)
	return storeOwnedFileError
}

func AppendToSharedFile(userdata *User, filename string, content []byte) error {
	// file struct uuid
	invitePtrHash, err := userlib.HashKDF(userdata.SourceKey, []byte(filename+"shared"))
	if err != nil {
		return errors.New("Append to shared file: Error generating hash")
	}
	invitePtrUUID, err := uuid.FromBytes(invitePtrHash[:16])
	if err != nil {
		return errors.New("Append to shared file: byte length array greater than 16")
	}

	marshalledInvitePtr, ok := userlib.DatastoreGet(invitePtrUUID)
	if !ok {
		return errors.New("Invite Ptr not found at UUID")
	}

	var invitePtrInterface InvitePtr

	unwrappedData, err := IndividualGiftUnwrap(marshalledInvitePtr, userdata.SourceKey, filename+"shared", invitePtrInterface)

	if err != nil {
		return err
	}

	invitePtr, ok := unwrappedData.(*InvitePtr)
	if !ok {
		// Handle the case where unwrappedData is not of type User
		return errors.New("Data is not of type InvitePtr")
	}

	var invite Invite
	marshalledInvite, pointerToInviteExists := userlib.DatastoreGet(invitePtr.InvitePtrUUID)
	json.Unmarshal(marshalledInvite, &invite)

	if pointerToInviteExists {
		// file exists in datastore, get filePtr
		filePtrUUID := invite.FilePointers

		var filePtr FilePointers
		marshalledFilePtr, ok := userlib.DatastoreGet(filePtrUUID)
		if !ok {
			return errors.New("File Pointer does not exist at UUID")
		}
		json.Unmarshal(marshalledFilePtr, &filePtr)

		current := filePtr.FileTailUUID
		head := filePtr.FileHeadUUID

		//Put the UUIDs of head and tail in filePtr
		// CALL LL HELPER, GET UUID OF TAIL AFTER DONE
		_, current, err = AddNodesToFileLL(content, head, current, invite.SymmetricEncKey, invite.HMACKey)
		if err != nil {
			return err
		}

		filePtr.FileTailUUID = current

		marshalledFilePtr, err = json.Marshal(filePtr)
		if err != nil {
			return errors.New("unable to marshal lameo")
		}
		userlib.DatastoreSet(invite.FilePointers, marshalledFilePtr)
		return nil
	}
	return errors.New("Access has been revoked loser")
}

func AppendToOwnedFile(userdata *User, filename string, content []byte) error {
	// file struct uuid
	ownedFileStructHash, err := userlib.HashKDF(userdata.SourceKey, []byte(filename+"owned"))
	if err != nil {
		return errors.New("Append to owned file: error generating hash")
	}
	ownedFileStructUUID, err := uuid.FromBytes(ownedFileStructHash[:16])
	if err != nil {
		return errors.New("Append to owned file: byte array length is greater than 16")
	}

	marshalledFileStruct, fileExists := userlib.DatastoreGet(ownedFileStructUUID)

	//ok is not really necessary but could help?
	if fileExists {
		// file exists in datastore, get filePtr

		var fileStructInterface File

		unwrappedData, err := IndividualGiftUnwrap(marshalledFileStruct, userdata.SourceKey, filename+"owned", fileStructInterface)

		if err != nil {
			return err
		}

		fileStructPtr, ok := unwrappedData.(*File)
		if !ok {
			// Handle the case where unwrappedData is not of type File
			return errors.New("Data is not of type File")
		}

		filePtrUUID := fileStructPtr.FilePointers

		var filePtr FilePointers
		marshalledFilePtr, filePtrExists := userlib.DatastoreGet(filePtrUUID)
		if !filePtrExists {
			return errors.New("File Pointer does not exist at UUID")
		}
		json.Unmarshal(marshalledFilePtr, &filePtr)

		current := filePtr.FileTailUUID
		head := filePtr.FileHeadUUID
		// CALL LL HELPER TO GET UUID OF TAIL
		_, current, err = AddNodesToFileLL(content, head, current, fileStructPtr.SymmetricEncKey, fileStructPtr.HMACKey)
		if err != nil {
			return err
		}

		filePtr.FileTailUUID = current

		marshalledFilePtr, err = json.Marshal(filePtr)
		if err != nil {
			return errors.New("unable to marshal lameo")
		}
		userlib.DatastoreSet(fileStructPtr.FilePointers, marshalledFilePtr)
		return nil
	}
	return errors.New("idk how this happeed lol")
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	for _, file := range userdata.SharedFiles {
		if filename == file {
			return AppendToSharedFile(userdata, filename, content)
		}
	}
	return AppendToOwnedFile(userdata, filename, content)
}

func LoadFileHelper(head uuid.UUID, SymmEncKey []byte, HMACKey []byte) (fileData []byte, err error) {
	// GO THRU LL AND VERIFY AUTHENTICITY + DECRYPT FILE TEXT AND RETURN DATA
	var data []byte
	for currentUUID := head; !(currentUUID == uuid.Nil); {
		marshalledText, ok := userlib.DatastoreGet(currentUUID)
		if !ok {
			// This means we have reached the last link of the LL, return what we have gotten so far
			return data, nil
		}
		var fileText FileText
		json.Unmarshal(marshalledText, &fileText)

		// verifying authenticity
		signature := fileText.HMACVerify
		cipherText := fileText.EncryptedData
		fileStructMAC, err := userlib.HMACEval(HMACKey, cipherText)
		if err != nil {
			return nil, errors.New("Load Owned File: Error generating HMAC tag")
		}
		isAuthentic := userlib.HMACEqual(signature, fileStructMAC)
		if !isAuthentic {
			return nil, errors.New("the file is not authentic")
		}
		// decrypt message, append to data array
		plainText := userlib.SymDec(SymmEncKey, cipherText)
		data = append(data, plainText...)

		currentUUID = fileText.Next
	}
	return data, nil
}

func LoadOwnedFile(userdata *User, filename string) (content []byte, err error) {
	// file struct uuid
	ownedFileStructHash, err := userlib.HashKDF(userdata.SourceKey, []byte(filename+"owned"))
	if err != nil {
		return nil, errors.New("Load Owned File: error generating hash")
	}
	ownedFileStructUUID, err := uuid.FromBytes(ownedFileStructHash[:16])
	if err != nil {
		return nil, errors.New("Load Owned File: byte length array greater than 16")
	}

	marshalledFileStruct, fileExists := userlib.DatastoreGet(ownedFileStructUUID)

	var fileStructInterface File

	unwrappedData, err := IndividualGiftUnwrap(marshalledFileStruct, userdata.SourceKey, filename+"owned", fileStructInterface)

	if err != nil {
		return nil, err
	}

	fileStructPtr, ok := unwrappedData.(*File)
	if !ok {
		// Handle the case where unwrappedData is not of type User
		return nil, errors.New("Data is not of type File")
	}

	//ok is not really necessary but could help?
	if fileExists {
		// file exists in datastore, get filePtr
		filePtrUUID := fileStructPtr.FilePointers

		var filePtr FilePointers
		marshalledFilePtr, ok := userlib.DatastoreGet(filePtrUUID)
		if !ok {
			return nil, errors.New("File Ptr does not exist at UUID")
		}
		json.Unmarshal(marshalledFilePtr, &filePtr)

		// CALL HELPER
		head := filePtr.FileHeadUUID
		data, err := LoadFileHelper(head, fileStructPtr.SymmetricEncKey, fileStructPtr.HMACKey)
		if err != nil {
			return nil, err
		}

		return data, nil
	}
	return nil, errors.New("idk how this happened lol")
}

func LoadSharedFile(userdata *User, filename string) (content []byte, err error) {
	// file struct uuid
	invitePtrHash, err := userlib.HashKDF(userdata.SourceKey, []byte(filename+"shared"))
	if err != nil {
		return nil, errors.New("Load Shared File: error generating hash")
	}
	invitePtrUUID, err := uuid.FromBytes(invitePtrHash[:16])
	if err != nil {
		return nil, errors.New("Load Shared File: byte array length greater than 16")
	}

	marshalledInvitePtr, invitePtrExists := userlib.DatastoreGet(invitePtrUUID)
	if !invitePtrExists {
		return nil, errors.New("Invite Ptr does not exist at UUID")
	}

	var invitePtrInterface InvitePtr

	unwrappedData, err := IndividualGiftUnwrap(marshalledInvitePtr, userdata.SourceKey, filename+"shared", invitePtrInterface)

	if err != nil {
		return nil, err
	}

	invitePtr, ok := unwrappedData.(*InvitePtr)
	if !ok {
		// Handle the case where unwrappedData is not of type User
		return nil, errors.New("Data is not of type InvitePtr")
	}

	var invite Invite
	marshalledInvite, inviteExists := userlib.DatastoreGet(invitePtr.InvitePtrUUID)
	json.Unmarshal(marshalledInvite, &invite)

	if inviteExists {
		// file exists in datastore, get filePtr
		filePtrUUID := invite.FilePointers

		var filePtr FilePointers
		marshalledFilePtr, ok := userlib.DatastoreGet(filePtrUUID)
		if !ok {
			return nil, errors.New("File Ptr does not exist at UUID")
		}
		json.Unmarshal(marshalledFilePtr, &filePtr)

		head := filePtr.FileHeadUUID
		data, err := LoadFileHelper(head, invite.SymmetricEncKey, invite.HMACKey)
		if err != nil {
			return nil, err
		}

		return data, nil
	}
	return nil, errors.New("Access has been revokedl")
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	// go thru shared files to see if file is shared or not
	for _, file := range userdata.SharedFiles {
		if filename == file {
			res, err := LoadSharedFile(userdata, filename)
			if err != nil {
				return nil, err
			}
			return res, nil
		}
	}
	res, err := LoadOwnedFile(userdata, filename)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func CopySharedInvitation(userdata *User, filename string, recipientUsername string) (invitationPtr uuid.UUID, err error) {
	// copy invitation
	invitePtrHash, err := userlib.HashKDF(userdata.SourceKey, []byte(filename+"shared"))
	if err != nil {
		return uuid.Nil, errors.New("Create invitation: error generating invite ptr hash")
	}
	invitePtrUUID, err := uuid.FromBytes(invitePtrHash[:16])
	if err != nil {
		return uuid.Nil, errors.New("Create invitation: byte length array greater than 16")
	}

	marshalledInvitePtr, ok := userlib.DatastoreGet(invitePtrUUID)
	if !ok {
		return uuid.Nil, errors.New("Invite Ptr not found at UUID")
	}

	// CREATE NEW INVITE PTR TO BE GIVEN TO RECEIVER
	var invitePtrStructInterface InvitePtr
	unwrappedData, err := IndividualGiftUnwrap(marshalledInvitePtr, userdata.SourceKey, filename+"shared", invitePtrStructInterface)
	if err != nil {
		return uuid.Nil, err
	}
	// type assertion
	invitePtr, ok := unwrappedData.(*InvitePtr)
	if !ok {
		// Handle the case where unwrappedData is not of type User
		return uuid.Nil, errors.New("Data is not of type InvitePtr")
	}

	newInvitePtrUUID, err := createInvitePtr(recipientUsername, invitePtr.InvitePtrUUID, userdata)
	return newInvitePtrUUID, err
}

func createInvitePtr(recipientUsername string, invitationUUID uuid.UUID, userdata *User) (invitationPtr uuid.UUID, err error) {
	var newInvitePtr InvitePtr
	newInvitePtr.InvitePtrUUID = invitationUUID
	signTag, err := userlib.DSSign(userdata.DSPrivate, []byte("enene"))
	if err != nil {
		return uuid.Nil, errors.New("Error signing InvitePtr")
	}

	newInvitePtr.DSSign = signTag
	// encrypt data in invite ptr with receiver's PK and authenticate with sender's SK
	receiverPK, ok := userlib.KeystoreGet(recipientUsername + "pk")
	if !ok {
		return uuid.Nil, errors.New("Error fetching recipient PK from Keystore")
	}
	marshalledNewInvitePtr, err := json.Marshal(newInvitePtr)
	if err != nil {
		return uuid.Nil, errors.New("Error marshalling new invite ptr for creating invitation")
	}
	// ENCRYPT
	symmEncKey := userlib.RandomBytes(16)
	iv := userlib.RandomBytes(16)
	cipherText := userlib.SymEnc(symmEncKey, iv, marshalledNewInvitePtr)
	cipherKey, err := userlib.PKEEnc(receiverPK, symmEncKey)
	if err != nil {
		return uuid.Nil, errors.New("Error encrypting invite ptr for creating invitation")
	}
	//Create a gift structure; this will hold the cipherkey, which can be decrypted using the receiver's SK,
	//as well as the marshalled, encrypted invitePtr
	invitePtrGift := Gift{
		Encrypted: cipherText,
		//We are calling it a signature because we are reusing the struct, but in reality it is a key
		Signature: cipherKey,
	}
	marshalledGift, err := json.Marshal(invitePtrGift)
	if err != nil {
		return uuid.Nil, errors.New("Error creating a gift structure to hold the invite pointer to send")
	}

	// ADD THE ENCRYPTED INVITE PTR TO DATASTORE
	newInvitePtrUUID := uuid.New()
	userlib.DatastoreSet(newInvitePtrUUID, marshalledGift)
	return newInvitePtrUUID, nil
}

// CREATE NEW INVITATION THAT WILL BE GIVEN TO RECEIVER
func OwnedCreateInvitation(userdata *User, filename string, recipientUsername string) (invitationPtr uuid.UUID, err error) {
	//Get File struct UUID
	ownedFileStructHash, err := userlib.HashKDF(userdata.SourceKey, []byte(filename+"owned"))
	if err != nil {
		return uuid.Nil, errors.New("Share Owned File: error generating hash")
	}
	ownedFileStructUUID, err := uuid.FromBytes(ownedFileStructHash[:16])
	if err != nil {
		return uuid.Nil, errors.New("Share Owned File: byte length array greater than 16")
	}

	marshalledFileStruct, fileExists := userlib.DatastoreGet(ownedFileStructUUID)
	if !fileExists {
		return uuid.Nil, errors.New("File with this name does not exist")
	}

	var fileStructInterface File

	unwrappedData, err := IndividualGiftUnwrap(marshalledFileStruct, userdata.SourceKey, filename+"owned", fileStructInterface)

	if err != nil {
		return uuid.Nil, err
	}

	fileStructPtr, ok := unwrappedData.(*File)
	if !ok {
		// Handle the case where unwrappedData is not of type User
		return uuid.Nil, errors.New("Data is not of type File")
	}

	//Create Invite Struct, populate with same info as in File struct
	var inviteStruct Invite
	inviteStruct.FilePointers = fileStructPtr.FilePointers
	inviteStruct.SymmetricEncKey = fileStructPtr.SymmetricEncKey
	inviteStruct.HMACKey = fileStructPtr.HMACKey

	//Put the new invite into the map of invitations
	inviteStructUUID := uuid.New()
	fileStructPtr.Invitations[recipientUsername] = inviteStructUUID

	//Rewrap the FileStruct and store it
	gift, err := IndividualGiftWrap(userdata.SourceKey, fileStructPtr, filename+"owned")
	if err != nil {
		return uuid.Nil, err
	}
	userlib.DatastoreSet(ownedFileStructUUID, gift)

	//Put marshalled InviteStruct in DataStore
	marshalledInviteStruct, err := json.Marshal(inviteStruct)
	if err != nil {
		return uuid.Nil, errors.New("Share owned file: error marshalling invite Struct")
	}
	userlib.DatastoreSet(inviteStructUUID, marshalledInviteStruct)

	//Create InvitePtr, encode + authenticate it, put in datastore, send uuid
	newInvitePtrUUID, err := createInvitePtr(recipientUsername, inviteStructUUID, userdata)
	return newInvitePtrUUID, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (invitationPtr uuid.UUID, err error) {
	for _, file := range userdata.SharedFiles {
		if filename == file {
			invitePtr, err := CopySharedInvitation(userdata, filename, recipientUsername)
			return invitePtr, err
		}
	}
	// create invitation
	invitePtr, err := OwnedCreateInvitation(userdata, filename, recipientUsername)
	return invitePtr, err
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {

	//Check if filename already exists in user's namespace
	for _, file := range userdata.SharedFiles {
		if filename == file {
			return errors.New("Accept Invitation: Filename already exists in your namespace")
		}
	}
	//Check if it exists in owned file namespace
	ownedFileStructHash, err := userlib.HashKDF(userdata.SourceKey, []byte(filename+"owned"))
	if err != nil {
		return errors.New("Accept Invitation: error generating hash for confirming filename is not in namespace")
	}
	ownedFileStructUUID, err := uuid.FromBytes(ownedFileStructHash[:16])
	if err != nil {
		return errors.New("Accept Invitation: byte length array greater than 16")
	}

	_, fileExists := userlib.DatastoreGet(ownedFileStructUUID)
	if fileExists {
		return errors.New("Accept Invitation: Filename already exists in your namespace")
	}

	//Unencrypt whatever is at the UUID that got shared (it should be a Gift)
	marshalledInviteGift, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New("No invitation pointer found")
	}

	var inviteGift Gift
	err = json.Unmarshal(marshalledInviteGift, &inviteGift)
	if err != nil {
		return errors.New("Error unmarshalling invitePtr")
	}

	cipherKey := inviteGift.Signature
	userSK := userdata.RSAPrivate
	SymKey, err := userlib.PKEDec(userSK, cipherKey)
	if err != nil {
		return errors.New("Error decrypting cipherkey for accessing the invite pointer")
	}

	marshalledInvitePtr := userlib.SymDec(SymKey, inviteGift.Encrypted)
	if err != nil {
		return errors.New("Error decrypting Invitation Pointer")
	}
	var invitePtrStruct InvitePtr
	err = json.Unmarshal(marshalledInvitePtr, &invitePtrStruct)
	if err != nil {
		return errors.New("Error unmarshalling invitePtr")
	}

	//Authenticate using DSSignKey in InvitePtr
	senderDS, ok := userlib.KeystoreGet(senderUsername + "ds")
	if !ok {
		return errors.New("Sender's public key for authentication of Invite Ptr not found.")
	}

	err = userlib.DSVerify(senderDS, []byte("enene"), invitePtrStruct.DSSign)
	if err != nil {
		return errors.New("This Invite Pointer is not authentic (not from who it claims to be from)")
	}

	//Reassign InvitePtr to a UUID you can get using hash kdf on your filename
	invitePtrHash, err := userlib.HashKDF(userdata.SourceKey, []byte(filename+"shared"))
	if err != nil {
		return errors.New("Create invitation: error generating invite ptr hash")
	}
	invitePtrUUID, err := uuid.FromBytes(invitePtrHash[:16])
	if err != nil {
		return errors.New("Create invitation: byte length array greater than 16")
	}

	//Wrap InvitePtr and store in Datastore
	wrappedInvitePtr, err := IndividualGiftWrap(userdata.SourceKey, invitePtrStruct, filename+"shared")
	if err != nil {
		return err
	}
	userlib.DatastoreSet(invitePtrUUID, wrappedInvitePtr)

	//Add filename to user struct under shared files
	userdata.SharedFiles = append(userdata.SharedFiles, filename)

	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	//Get File struct UUID
	ownedFileStructHash, err := userlib.HashKDF(userdata.SourceKey, []byte(filename+"owned"))
	if err != nil {
		return errors.New("Share Owned File: error generating hash")
	}
	ownedFileStructUUID, err := uuid.FromBytes(ownedFileStructHash[:16])
	if err != nil {
		return errors.New("Share Owned File: byte length array greater than 16")
	}

	marshalledFileStruct, fileExists := userlib.DatastoreGet(ownedFileStructUUID)
	if !fileExists {
		return errors.New("File with this name does not exist")
	}

	var fileStructInterface File

	unwrappedData, err := IndividualGiftUnwrap(marshalledFileStruct, userdata.SourceKey, filename+"owned", fileStructInterface)

	if err != nil {
		return err
	}

	fileStructPtr, ok := unwrappedData.(*File)
	if !ok {
		// Handle the case where unwrappedData is not of type File
		return errors.New("Data is not of type File")
	}

	//Use map of username:Invite UUIDs to find UUID of invite block to delete
	//Delete that invite block and remove from invitations

	revokedInviteUUID, exists := fileStructPtr.Invitations[recipientUsername]
	if !exists {
		return errors.New("The user you are trying to revoke access from does not have access to the file already.")
	}

	userlib.DatastoreDelete(revokedInviteUUID)
	//TODO: CHECK THAT THIS ACTUALLY DELETES IT FROM THE MAPPING
	delete(fileStructPtr.Invitations, recipientUsername)

	//Change Symmetric Key and HMAC Encryption Key for File
	oldSymmKey := fileStructPtr.SymmetricEncKey
	oldHMACKey := fileStructPtr.HMACKey

	fileStructPtr.HMACKey = userlib.RandomBytes(16)
	fileStructPtr.SymmetricEncKey = userlib.RandomBytes(16)

	//Re-encrypt + Re-authenticate all FileTexts with new keys
	filePtrUUID := fileStructPtr.FilePointers

	var filePtr FilePointers
	marshalledFilePtr, ok := userlib.DatastoreGet(filePtrUUID)
	if !ok {
		return errors.New("File Ptr does not exist at UUID")
	}
	json.Unmarshal(marshalledFilePtr, &filePtr)

	head := filePtr.FileHeadUUID
	data, err := LoadFileHelper(head, oldSymmKey, oldHMACKey)
	if err != nil {
		return err
	}

	head, current, err := AddNodesToFileLL(data, uuid.Nil, uuid.Nil, fileStructPtr.SymmetricEncKey, fileStructPtr.HMACKey)
	filePtr.FileHeadUUID = head
	filePtr.FileTailUUID = current

	marshalledFilePtr, err = json.Marshal(filePtr)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(fileStructPtr.FilePointers, marshalledFilePtr)

	gift, err := IndividualGiftWrap(userdata.SourceKey, fileStructPtr, filename+"owned")
	if err != nil {
		return err
	}

	userlib.DatastoreSet(ownedFileStructUUID, gift)

	//Update valid Invite blocks with the new keys
	for _, inviteUUID := range fileStructPtr.Invitations {
		marshalledInvite, ok := userlib.DatastoreGet(inviteUUID)
		if !ok {
			return errors.New("Could not get invite from Invite map to reset keys after revoking another user")
		}

		var inviteBlock Invite
		json.Unmarshal(marshalledInvite, &inviteBlock)
		inviteBlock.HMACKey = fileStructPtr.HMACKey
		inviteBlock.SymmetricEncKey = fileStructPtr.SymmetricEncKey
	}

	return nil
}
