package main

import (
	"bytes"
	"reflect"
	"testing"
)

func init() {
	printMessages = false
}

func Test_mainInternal(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{
			name: "Use Case",
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mainInternal(); got != tt.want {
				t.Errorf("mainInternal() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Benchmark_mainInternal(b *testing.B) {
	for n := 0; n < b.N; n++ {
		mainInternal()
	}
}

func Benchmark_GenerateKeyPair(b *testing.B) {
	for n := 0; n < b.N; n++ {
		GenerateKeyPair()
	}
}

func Benchmark_encrypt(b *testing.B) {
	private, err := GenerateKeyPair()
	if err != nil {
		panic(err)
	}

	public, err := GenerateKeyPair()
	if err != nil {
		panic(err)
	}

	msg := []byte("This is a secret Message")

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		encrypt(private, public.PublicKeys, msg)
	}
}

func Test_encrypt(t *testing.T) {
	private, err := GenerateKeyPair()
	if err != nil {
		panic(err)
	}

	public, err := GenerateKeyPair()
	if err != nil {
		panic(err)
	}

	type args struct {
		private HybridKeyPair
		public  PublicKeys
		msg     []byte
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "No Error",
			args: args{
				private: private,
				public:  public.PublicKeys,
				msg:     []byte("This is a secret Message"),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := encrypt(tt.args.private, tt.args.public, tt.args.msg)
			if (err != nil) != tt.wantErr {
				t.Errorf("encrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Benchmark_decrypt(b *testing.B) {
	aliceKeys, _ := GenerateKeyPair()
	bobKeys, _ := GenerateKeyPair()
	plain := []byte("This is a secret Message")
	wd, _ := encrypt(aliceKeys, bobKeys.PublicKeys, plain)

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		decrypted, _ := decrypt(wd.SendersPublicKeys, bobKeys.PrivateKeys, wd)
		if !bytes.Equal(plain, decrypted) {
			b.FailNow()
		}
	}
}

func Test_decrypt(t *testing.T) {
	aliceKeys, _ := GenerateKeyPair()
	bobKeys, _ := GenerateKeyPair()
	plain := []byte("This is a secret Message")
	wd, _ := encrypt(aliceKeys, bobKeys.PublicKeys, plain)

	type args struct {
		public   PublicKeys
		private  PrivateKeys
		wiredata WireData
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "No Error",
			args: args{
				public:   aliceKeys.PublicKeys,
				private:  bobKeys.PrivateKeys,
				wiredata: wd,
			},
			want: plain,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decrypt(tt.args.public, tt.args.private, tt.args.wiredata)
			if (err != nil) != tt.wantErr {
				t.Errorf("decrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("decrypt() = %v, want %v", got, tt.want)
			}
		})
	}
}

func manipulateSlice(input []byte) []byte {
	data := make([]byte, 0)
	data = append(data, input...)
	index := len(data) / 2
	data[index] = ^data[index]
	return data
}

func Test_decrypt_Manipulation(t *testing.T) {
	aliceKeys, _ := GenerateKeyPair()
	bobKeys, _ := GenerateKeyPair()
	plain := []byte("This is a secret Message")
	wd, _ := encrypt(aliceKeys, bobKeys.PublicKeys, plain)

	t.Logf("%x", wd.AssociatedData)

	type args struct {
		wiredata           WireData
		manipulateWireData func(WireData) WireData
	}
	tests := []struct {
		name             string
		args             args
		want             []byte
		wantErr          bool
		wantErrorMessage string
	}{
		{
			name: "AssociatedData",
			args: args{
				wiredata: wd,
				manipulateWireData: func(wd WireData) WireData {
					wd.AssociatedData = manipulateSlice(wd.AssociatedData)
					return wd
				},
			},
			wantErr:          true,
			wantErrorMessage: "cipher: message authentication failed",
		},
		{
			name: "CipherText",
			args: args{
				wiredata: wd,
				manipulateWireData: func(wd WireData) WireData {
					wd.CipherText = manipulateSlice(wd.CipherText)
					return wd
				},
			},
			wantErr:          true,
			wantErrorMessage: "cipher: message authentication failed",
		},
		{
			name: "EncapsulatedKey",
			args: args{
				wiredata: wd,
				manipulateWireData: func(wd WireData) WireData {
					wd.EncapsulatedKey = manipulateSlice(wd.EncapsulatedKey)
					return wd
				},
			},
			wantErr:          true,
			wantErrorMessage: "cipher: message authentication failed",
		},
		{
			name: "Info",
			args: args{
				wiredata: wd,
				manipulateWireData: func(wd WireData) WireData {
					wd.Info += "#"
					return wd
				},
			},
			wantErr:          true,
			wantErrorMessage: "cipher: message authentication failed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.args.wiredata = tt.args.manipulateWireData(tt.args.wiredata)

			_, err := decrypt(aliceKeys.PublicKeys, bobKeys.PrivateKeys, tt.args.wiredata)
			if (err != nil) != tt.wantErr {
				t.Errorf("decrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err.Error() != tt.wantErrorMessage {
				t.Errorf("decrypt() error = %v, wantErr %v", err, tt.wantErrorMessage)
				return
			}
		})
	}
}
