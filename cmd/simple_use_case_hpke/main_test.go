package main

import (
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
		encrypt(private.PrivateKeys, public.PublicKeys, msg)
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
		private PrivateKeys
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
				private: private.PrivateKeys,
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
