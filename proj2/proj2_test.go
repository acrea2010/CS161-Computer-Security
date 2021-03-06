package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	"testing"
	"reflect"
	"github.com/nweaver/cs161-p2/userlib"
	_ "encoding/json"
	_ "encoding/hex"
	_ "github.com/google/uuid"
	_ "strings"
	_ "errors"
	_ "strconv"
)


func TestInit(t *testing.T) {
	t.Log("Initialization test")

	// You may want to turn it off someday
	userlib.SetDebugStatus(true)
	someUsefulThings()
	userlib.SetDebugStatus(false)
	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Got user", u)
	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.
}


func TestStorage(t *testing.T) {
	// And some more tests, because
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}
	t.Log("Loaded user", u)

	v := []byte("This is a test")
	u.StoreFile("file1", v)


	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
	}
}
func TestAppend(t *testing.T){
    u, err := GetUser("alice", "fubar")
    if err != nil {
        t.Error("Failed to reload user", err)
        return
    }
    t.Log("Loaded user", u)

    v := []byte("This is a test")
    second_file := []byte("This is a second test")
    third_file := []byte("This is the third test")
    u.StoreFile("file1", v)
    u.AppendFile("file1", second_file)
    u.AppendFile("file1", third_file)

    expected_file := append(v,second_file...)
    expected_file = append(expected_file, third_file...)
    v2, err2 := u.LoadFile("file1")
    if err2 != nil {
        t.Error("Failed to upload and download", err2)
    }
    if !reflect.DeepEqual(expected_file, v2) {
        t.Error("Downloaded file is not the same", v, v2)
    }
}

func TestShare(t *testing.T) {
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
	}

	var v, v2 []byte
	var magic_string string

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
	}

	magic_string, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the file", err)
	}
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the shared message", err)
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
	}

}

func TestRevoke(t *testing.T) {
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
	}

	var v, v2 []byte
	var magic_string string

	v , err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
	}

	magic_string, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the file", err)
	}
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the shared message", err)
	}

	err = u.RevokeFile("file1")
	if err != nil {
		t.Error("Failed to revoke file", err)
	}

	v2, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to reload revoked file", err)
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
	}

}
