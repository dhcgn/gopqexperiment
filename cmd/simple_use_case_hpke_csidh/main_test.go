package main

import (
	"bytes"
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
	aliceKeys, _ := GenerateKeyPair()
	bobKeys, _ := GenerateKeyPair()
	msg := []byte("This is a secret Message")

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		encrypt(aliceKeys, bobKeys.PublicKeys, msg)
	}
}

func Test_encrypt(t *testing.T) {
	aliceKeys, _ := GenerateKeyPair()
	bobKeys, _ := GenerateKeyPair()

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
				private: aliceKeys,
				public:  bobKeys.PublicKeys,
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
		decrypted := decrypt(wd.SendersPublicKeys, bobKeys.PrivateKeys, wd)
		if !bytes.Equal(plain, decrypted) {
			b.FailNow()
		}
	}
}
