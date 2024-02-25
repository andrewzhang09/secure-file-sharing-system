package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	_ "errors"
	_ "strconv"
	_ "strings"
	"testing"
	"encoding/json"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	var charles *client.User
	var sanjay *client.User
	var andrew *client.User
	// var frank *client.User
	// var grace *client.User
	// var horace *client.User
	// var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User
	var sanjayPhone *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	sanjayFile := "sanjayFile.txt"
	andrewFile := "andrewFile.txt"
	// frankFile := "frankFile.txt"
	// graceFile := "graceFile.txt"
	// horaceFile := "horaceFile.txt"
	// iraFile := "iraFile.txt"

	measureBandwidth := func(probe func()) (bandwidth int) {
		before := userlib.DatastoreGetBandwidth()
		probe()
		after := userlib.DatastoreGetBandwidth()
		return after - before
	}

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

	})

	Describe("User Tests", func() {

		//METHOD: INIT USER
		//Test that username cannot be empty
		Specify("Testing that username cannot be empty", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("", defaultPassword)
			Expect(err).ToNot(BeNil())
		})
		//Test that 2 usernames cannot be the same thing
		Specify("Testing user cannot have same username as another", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Alice B.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})
		//Test case sensitivity for usernames
		Specify("Testing that usernames are case sensitive", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())
		})
		//Test that if it has been tampered, it errors out
		Specify("Testing when datastore has been tampered with", func() {
			userlib.DatastoreClear()

			userlib.DebugMsg("Initializing user Andrew.")
			andrew, err = client.InitUser("andrew", "ENENE")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Tampering with Datastore")
			var datastore = userlib.DatastoreGetMap()
			for uuid, _ := range datastore {
				userlib.DatastoreSet(uuid, []byte("andrew is a cutie <3"))
			}

			userlib.DebugMsg("Get user Andrew")
			andrew, err = client.GetUser("andrew", "ENENE")
			Expect(err).ToNot(BeNil())
		})

		//Test multi session for same user
		Specify("Testing that different instances of same user gets same user ", func() {
			userlib.DebugMsg("Initializing user Sanjay")
			sanjay, err = client.InitUser("sanjay", "EEEE")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Sanjay on phone")
			sanjayPhone, err = client.GetUser("sanjay", "EEEE")
			Expect(err).To(BeNil())

			var sanjay_babu, _ = json.Marshal(sanjay)
			var sanjay_mobile_device, _ = json.Marshal(sanjayPhone)
			Expect(sanjay_babu).Should(Equal(sanjay_mobile_device))
		})

		//METHOD: GETUSER
		//Test that getuser on a username that doesn't exist results in an error
		Specify("Testing that get user fails for a user that does not exist", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)

			userlib.DebugMsg("Getting user Bob.")
			bob, err = client.GetUser("bob", defaultPassword)
			Expect(err).ToNot(BeNil())
		})
		//Check that trying to getuser with wrong username/password errors
		Specify("Testing trying to get user with wrong password fails", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			alice, err = client.GetUser("bob", "EFEEEEF")
			Expect(err).ToNot(BeNil())
		})
	})
	

	Describe("File tests", func() {
		//StoreFile
		//TODO: Test that storefile cannot occur if not authentic

		// Test StoreOwnedFile for file that exists
		Specify("Testing StoreOwnedFile for file that already exists", func() {
			userlib.DebugMsg("Initializing user Sanjay.")
			sanjay, err = client.InitUser("sanjay", "EEEE")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = sanjay.StoreFile(sanjayFile, []byte(contentOne))
			Expect(err).To(BeNil())

			// should be able to override
			userlib.DebugMsg("Storing file data: %s", contentTwo)
			err = sanjay.StoreFile(sanjayFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file data: %s", sanjayFile)
			contents, err := sanjay.LoadFile(sanjayFile)
			Expect(err).To(BeNil())
			Expect(contents).To(Equal([]byte(contentTwo)))
		})
		//LoadFile
		//Given filename does not exist --> error
		Specify("Testing that load file fails when file does not exist", func() {
			userlib.DebugMsg("Initializing user Sanjay.")
			sanjay, err = client.InitUser("sanjay", "EEEE")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			_, err = sanjay.LoadFile(andrewFile)
			Expect(err).ToNot(BeNil())
		})
		//TODO: Integrity of file cannot be confirmed --> error

		//AppendtoFile
		//Filename does not exist in personal namespace
		Specify("Testing that append file fails when file does not exist", func() {
			userlib.DebugMsg("Initializing user Sanjay.")
			sanjay, err = client.InitUser("sanjay", "EEEE")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = sanjay.AppendToFile(andrewFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})
		// Testing Bandwith is constant
		Specify("Testing AppendFile bandwidth is constant", func() {
			userlib.DebugMsg("Initializing user Sanjay.")
			sanjay, err = client.InitUser("sanjay", "EEEE")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = sanjay.StoreFile(sanjayFile, userlib.RandomBytes(2000))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending to sanjay file: %s", sanjayFile)
			// measure bw
			bandwidth := measureBandwidth(func() {
				sanjay.AppendToFile(sanjayFile, []byte("moan!"))
			})
			Expect(bandwidth >= 2000).ToNot(BeTrue())
		})
	})

	Describe("Invitation Tests", func() {
		//CreateInvitation
		// Test StoreSharedFile
		Specify("Testing StoreSharedFile", func() {
			userlib.DebugMsg("Initializing user Drew.")
			andrew, err = client.InitUser("andrew", "ENEN")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Sanjay.")
			sanjay, err = client.InitUser("sanjay", "EEEE")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = andrew.StoreFile(andrewFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("andrew creating invite for sanjay.")
			invite, err := andrew.CreateInvitation(andrewFile, "sanjay")
			Expect(err).To(BeNil())

			userlib.DebugMsg("sanjay accepting invite for file: %s.", andrewFile)
			err = sanjay.AcceptInvitation("andrew", invite, sanjayFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Storing file data of shared file: %s", contentTwo)
			err = sanjay.StoreFile(sanjayFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file data: %s", sanjayFile)
			contents, err := sanjay.LoadFile(sanjayFile)
			Expect(err).To(BeNil())
			Expect(contents).To(Equal([]byte(contentTwo)))
		})

		//filename does not exist in namespace
		Specify("Testing create invitation fails if file does not exist within namespace", func() {
			userlib.DebugMsg("Initializing user Drew.")
			andrew, err = client.InitUser("andrew", "ENEN")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Sanjay.")
			sanjay, err = client.InitUser("sanjay", "EEEE")
			Expect(err).To(BeNil())

			userlib.DebugMsg("drew creating invite for sanjay.")
			_, err := andrew.CreateInvitation(sanjayFile, "sanjay")
			Expect(err).ToNot(BeNil())
		})
		//recipientUsername does not exist
		Specify("Testing create invitation fails if recipient does not exist", func() {
			userlib.DebugMsg("Initializing user Drew.")
			andrew, err = client.InitUser("andrew", "ENEN")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = andrew.StoreFile(andrewFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("drew creating invite for sanjay.")
			_, err := andrew.CreateInvitation(andrewFile, "Vaishik Kota")
			Expect(err).ToNot(BeNil())
		})

		//AcceptInvitation
		//User already has a file with the chosen filename
		Specify("Testing user already has file with chosen filename", func() {
			userlib.DebugMsg("Initializing user Drew.")
			andrew, err = client.InitUser("andrew", "ENEN")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Sanjay.")
			sanjay, err = client.InitUser("sanjay", "EEEE")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = andrew.StoreFile(sanjayFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = sanjay.StoreFile(sanjayFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("andrew creating invite for sanjay.")
			invite, err := andrew.CreateInvitation(sanjayFile, "sanjay")
			Expect(err).To(BeNil())

			userlib.DebugMsg("sanjay accepting invite for file: %s.", sanjayFile)
			err = sanjay.AcceptInvitation("andrew", invite, sanjayFile)
			Expect(err).ToNot(BeNil())
		})
		//TODO: Check that invitationPtr with wrong UUID --> error

		//Check that if user cannot confirm invitationPtr is from sender --> error
		Specify("Testing Accepting Invitation when invitation is not from sender", func() {
			userlib.DebugMsg("Initializing user andrew.")
			andrew, err = client.InitUser("andrew", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user sanjay.")
			sanjay, err = client.InitUser("sanjay", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Charlie.")
			charles, err = client.InitUser("charlie", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing new file %s", andrewFile)
			err = andrew.StoreFile(andrewFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Creating invitation for andrewFile")
			invite, err := andrew.CreateInvitation(andrewFile, "charlie")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing new file %s", sanjayFile)
			err = sanjay.StoreFile(sanjayFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Creating invitation for sanjayFile")
			invite2, err := sanjay.CreateInvitation(sanjayFile, "charlie")
			Expect(err).To(BeNil())

			// invite is actually from andrew
			userlib.DebugMsg("Accepting invitation for filename in namespace")
			err = charles.AcceptInvitation("sanjay", invite, charlesFile)
			Expect(err).ToNot(BeNil())

			// invite is actually from sanjay
			userlib.DebugMsg("Accepting invitation for filename in namespace")
			err = charles.AcceptInvitation("andrew", invite2, charlesFile)
			Expect(err).ToNot(BeNil())
		})

		//RevokeAccess
		//filename does not exist in namespace --> error
		Specify("Testing RevokeAccess when filename does not exist", func() {
			userlib.DebugMsg("Initializing user andrew.")
			andrew, err = client.InitUser("andrew", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user sanjay.")
			sanjay, err = client.InitUser("sanjay", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing new file %s", andrewFile)
			err = andrew.StoreFile(andrewFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Creating invitation for andrewFile")
			invite, err := andrew.CreateInvitation(andrewFile, "sanjay")
			Expect(err).To(BeNil())

			// invite accepted by Sanjay
			userlib.DebugMsg("Accepting invitation for filename in namespace")
			err = sanjay.AcceptInvitation("andrew", invite, sanjayFile)
			Expect(err).To(BeNil())

			//Revoke access to a file that does not exist in Andrew's namespace
			userlib.DebugMsg("Revoking access for filename not in Andrew namespace")
			err = andrew.RevokeAccess("charlieFile", "sanjay")
			Expect(err).ToNot(BeNil())
		})

		//if file is not already shared with revokedUser --> error
		Specify("Testing RevokeAccess when it has not been shared with the person you are revoking from", func() {
			userlib.DebugMsg("Initializing user andrew.")
			andrew, err = client.InitUser("andrew", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user sanjay.")
			sanjay, err = client.InitUser("sanjay", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing new file %s", andrewFile)
			err = andrew.StoreFile(andrewFile, []byte(contentOne))
			Expect(err).To(BeNil())

			//Revoke access to a file that does not exist in Andrew's namespace
			userlib.DebugMsg("Revoking access for someone it hasnt been shared with")
			err = andrew.RevokeAccess(andrewFile, "sanjay")
			Expect(err).ToNot(BeNil())
		})

		//Check that once revoked, you cannot access the file
		Specify("Testing that once revoked, you cannot access the file", func() {
			userlib.DebugMsg("Initializing user andrew.")
			andrew, err = client.InitUser("andrew", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user sanjay.")
			sanjay, err = client.InitUser("sanjay", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing new file %s", andrewFile)
			err = andrew.StoreFile(andrewFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Creating invitation for andrewFile")
			invite, err := andrew.CreateInvitation(andrewFile, "sanjay")
			Expect(err).To(BeNil())

			// invite accepted by Sanjay
			userlib.DebugMsg("Accepting invitation for filename in namespace")
			err = sanjay.AcceptInvitation("andrew", invite, sanjayFile)
			Expect(err).To(BeNil())

			//Revoke access to the file
			userlib.DebugMsg("Revoking access for filename")
			err = andrew.RevokeAccess(andrewFile, "sanjay")
			Expect(err).To(BeNil())

			//Have sanjay try to load file he was revoked from
			userlib.DebugMsg("Trying to access revoked file")
			_, err = sanjay.LoadFile(sanjayFile)
			Expect(err).ToNot(BeNil())

			//Have sanjay try to append to file he was revoked from
			userlib.DebugMsg("Trying to append to revoked file")
			err = sanjay.AppendToFile(sanjayFile, []byte("enene"))
			Expect(err).ToNot(BeNil())

			//Have sanjay reaccept invitation
			userlib.DebugMsg("Accepting invitation for filename in namespace")
			err = sanjay.AcceptInvitation("andrew", invite, sanjayFile)
			Expect(err).ToNot(BeNil())

			//Have sanjay try to load file he was revoked from
			userlib.DebugMsg("Trying to access revoked file")
			_, err = sanjay.LoadFile(sanjayFile)
			Expect(err).ToNot(BeNil())

			//Have sanjay try to append to file he was revoked from
			userlib.DebugMsg("Trying to append to revoked file")
			err = sanjay.AppendToFile(sanjayFile, []byte("enene"))
			Expect(err).ToNot(BeNil())
		})

		//Test that once one user is revoked, the others can still load/store
		Specify("Testing that once revoked, others can access the file", func() {
			userlib.DebugMsg("Initializing user andrew.")
			andrew, err = client.InitUser("andrew", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user sanjay.")
			sanjay, err = client.InitUser("sanjay", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user charlie.")
			charlie, err := client.InitUser("charlie", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing new file %s", andrewFile)
			err = andrew.StoreFile(andrewFile, []byte(contentOne))
			Expect(err).To(BeNil())

			//Invite for Sanjay
			userlib.DebugMsg("Creating invitation for andrewFile")
			invite, err := andrew.CreateInvitation(andrewFile, "sanjay")
			Expect(err).To(BeNil())

			// invite accepted by Sanjay
			userlib.DebugMsg("Accepting invitation for filename in namespace")
			err = sanjay.AcceptInvitation("andrew", invite, sanjayFile)
			Expect(err).To(BeNil())

			//Invite for charlie
			userlib.DebugMsg("Creating invitation for andrewFile")
			invite2, err := andrew.CreateInvitation(andrewFile, "charlie")
			Expect(err).To(BeNil())

			//Invite accepted by Charlie
			userlib.DebugMsg("Accepting invitation for filename in namespace")
			err = charlie.AcceptInvitation("andrew", invite2, "charlieFile")
			Expect(err).To(BeNil())

			//Revoke access to the file for Sanjay
			userlib.DebugMsg("Revoking access for filename")
			err = andrew.RevokeAccess(andrewFile, "sanjay")
			Expect(err).To(BeNil())

			//Store Shared file for Charlie
			userlib.DebugMsg("Storing new file %s", "charlieFile")
			err = charlie.StoreFile("charlieFile", []byte("enene"))
			Expect(err).To(BeNil())
		})
	})
	//DatastoreAdversary
	//use DatastoreGetMap to get a map of all things in datastore to modify datastore directly; tamper it, ensure authenticity failed
	//Swapping attack??

	//Revoked Adversary
	//Test that any UUID the person who is revoked cannot be used to reaccess file (should be tested already)
})
