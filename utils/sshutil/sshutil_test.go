// Copyright 2019 Drone.IO Inc. All rights reserved.
// Use of this source code is governed by the Polyform License
// that can be found in the LICENSE file.

package sshutil

import (
	"fmt"
	"golang.org/x/crypto/ssh"
	"testing"
)

func TestGeneratePEMKeyPair_ED25519(t *testing.T) {
	config := &Config{
		KeyType: "ed25519",
	}
	keypair, err := GeneratePEMKeyPair(config)
	if err != nil {
		t.Error(err)
	}

	fmt.Println(keypair.PrivateKey)

	if _, err := ssh.ParsePrivateKey([]byte(keypair.PrivateKey)); err != nil {
		t.Error(err)
	}
}

func TestGeneratePEMKeyPair_RSA(t *testing.T) {
	config := &Config{
		KeyType: "rsa",
	}
	keypair, err := GeneratePEMKeyPair(config)
	if err != nil {
		t.Error(err)
	}

	if _, err := ssh.ParsePrivateKey([]byte(keypair.PrivateKey)); err != nil {
		t.Error(err)
	}
}

func TestGenerateAuthorizedKeyKeyFromPEMPrivateKey_ED25519(t *testing.T) {
	b := "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
		"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n" +
		"QyNTUxOQAAACAfPd0wsHWfm9YDd+IpgRwQwTM11Tw1v/PFlqakDatqyQAAAKC94DuMveA7\n" +
		"jAAAAAtzc2gtZWQyNTUxOQAAACAfPd0wsHWfm9YDd+IpgRwQwTM11Tw1v/PFlqakDatqyQ\n" +
		"AAAEB9KIyxxYnujdMTO55hKd+kPBhzp+vEgg8ImPYEKlQBSB893TCwdZ+b1gN34imBHBDB\n" +
		"MzXVPDW/88WWpqQNq2rJAAAAGnRpdG91QHRyb29wZXItZm9sb2N0ZXQtY29tAQID\n" +
		"-----END OPENSSH PRIVATE KEY-----\n"
	want := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB893TCwdZ+b1gN34imBHBDBMzXVPDW/88WWpqQNq2rJ\n"
	got, err := GenerateAuthorizedKeyKeyFromPEMPrivateKey(b)
	if err != nil {
		t.Error(err)
	}
	if got != want {
		t.Errorf("Want public key %q, got %q", want, got)
	}
}

func TestGenerateAuthorizedKeyKeyFromPEMPrivateKey_RSA(t *testing.T) {
	b := "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
		"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn\n" +
		"NhAAAAAwEAAQAAAQEA7B8WV8PgOLeZvFdXWBGsMvgFhVrccML2c708TwB5dqGHJVBWCcBE\n" +
		"BIM2naOmrO5XeDVAtphTwV7g1Gcxun8R1anVs5OS/rBq9iFJGwqGVaDxG92xG7H9Dr9amh\n" +
		"V/icWPvPygH/8mPy3mEuhlC0xS5yQhhJ2WP4wdXs6f8BoqpXIcj5nJYo5qUt9XdwkVC0mH\n" +
		"F30zJ5xBh8yOhLh5gRHCiH68mSIZsSIOmVnN+cZaTxejsKSliVix+e5U581PDHfGvnAUMI\n" +
		"0uBTIuegbwEpg33CB1uOYC9lVGDn3ubCMaW+GYcI/919FF1HDbgxPDrhKGVgtEnk/MtWbx\n" +
		"OG0nBAr5WwAAA9CAtJw8gLScPAAAAAdzc2gtcnNhAAABAQDsHxZXw+A4t5m8V1dYEawy+A\n" +
		"WFWtxwwvZzvTxPAHl2oYclUFYJwEQEgzado6as7ld4NUC2mFPBXuDUZzG6fxHVqdWzk5L+\n" +
		"sGr2IUkbCoZVoPEb3bEbsf0Ov1qaFX+JxY+8/KAf/yY/LeYS6GULTFLnJCGEnZY/jB1ezp\n" +
		"/wGiqlchyPmclijmpS31d3CRULSYcXfTMnnEGHzI6EuHmBEcKIfryZIhmxIg6ZWc35xlpP\n" +
		"F6OwpKWJWLH57lTnzU8Md8a+cBQwjS4FMi56BvASmDfcIHW45gL2VUYOfe5sIxpb4Zhwj/\n" +
		"3X0UXUcNuDE8OuEoZWC0SeT8y1ZvE4bScECvlbAAAAAwEAAQAAAQAEUeFHw8ajYwCGCJcJ\n" +
		"fnFHEXCQawQjb/2wSmMDEwAl4nilfx3D2eekqX3jTm4rNcUV5uuDK7BElmbInAa14cNCxH\n" +
		"OrcGS9Eh8y15MN0ph4kpQ2rUyjNBNsJKYUsZX+wEWL8JdBXpqlh0JxUB0hIslVfzy5v2RT\n" +
		"T03uQRt9+gyTsETEeteUQVUjRnCk1P/oc4dj2GsEhuD2GY9LIRSHDKDljB+MCFnoSuECgT\n" +
		"khfGgre8amBi0ssj8AP+FLXGE+qtu6nPrNyKWh7HXZovusm8zrZ96rk2+BEwrYxqn9Ned3\n" +
		"yLHnR8aYuiPiBexftBiVZqASiZAgbhGoBB3/ja9bnkRxAAAAgQC872s43hyv4cteT86qPr\n" +
		"5CZHzrghxloroZWndZBGxEieD3AY2JTF9tk9x6P8/yeqI/DoYr6OGUXasOrJDfKKzttg3m\n" +
		"Xf37XrrKpzPGUeRbpIAoWFw+aRQC8kQWkjDR5xKXWW7WOPh3X1iJ6OFxbBaKAx8ljFlQWS\n" +
		"jDdtrzsW0VFgAAAIEA9kw1Ub1OtCDNTKGdPhGpqv+QBEP0bu+1cCmRC6hIioKslZxcTMM/\n" +
		"0W7Ay34UjNXu/oGcHTGxspalwTfyWzgB+p9bShFq0I91fPju/okYcF10o6MuWsETUUsZfa\n" +
		"pIj6ngy+0uA1LcfJpzAhHtFCtjOq8zdiFiFQAOZy4yA+RhSUkAAACBAPVsQacGM6vROfx4\n" +
		"aA1S/g1VrBdqMJRA3dBHARICYywHT61AsOOjM08E+FBDbSAgItotXNO9MaGM8Y/K08b7gr\n" +
		"yl3nf4ZHb1nEm3kxK38XfPowzrNMHvG/fKiuwxiviBtv2gRnY/nwmsDEiMKq5WOtSw9LPM\n" +
		"9BrCaxyUOhas37GDAAAAGnRpdG91QHRyb29wZXItZm9sb2N0ZXQtY29t\n" +
		"-----END OPENSSH PRIVATE KEY-----\n"
	want := "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDsHxZXw+A4t5m8V1dYEawy+AWFWtxwwvZzvTxPAHl2oYclUFYJwEQEgzado6as7ld4NUC2mFPBXuDUZzG6fxHVqdWzk5L+sGr2IUkbCoZVoPEb3bEbsf0Ov1qaFX+JxY+8/KAf/yY/LeYS6GULTFLnJCGEnZY/jB1ezp/wGiqlchyPmclijmpS31d3CRULSYcXfTMnnEGHzI6EuHmBEcKIfryZIhmxIg6ZWc35xlpPF6OwpKWJWLH57lTnzU8Md8a+cBQwjS4FMi56BvASmDfcIHW45gL2VUYOfe5sIxpb4Zhwj/3X0UXUcNuDE8OuEoZWC0SeT8y1ZvE4bScECvlb\n"
	got, err := GenerateAuthorizedKeyKeyFromPEMPrivateKey(b)
	if err != nil {
		t.Error(err)
	}
	if got != want {
		t.Errorf("Want public key %q, got %q", want, got)
	}
}

func TestCalculateFingerprint_MD5(t *testing.T) {
	b := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB893TCwdZ+b1gN34imBHBDBMzXVPDW/88WWpqQNq2rJ\n"
	want := "3e:0c:12:c9:50:fb:32:25:7c:f8:ec:26:33:e1:89:d9"
	got, err := CalculateFingerprint(b, "Md5")
	if err != nil {
		t.Error(err)
	}
	if got != want {
		t.Errorf("Want public key %q, got %q", want, got)
	}
}

func TestCalculateFingerprint_SHA256(t *testing.T) {
	b := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB893TCwdZ+b1gN34imBHBDBMzXVPDW/88WWpqQNq2rJ\n"
	want := "htBCH5aijJeaQ4gf0qH0cHhFExi7fpFlCGzMjadsbfM"
	got, err := CalculateFingerprint(b, "Sha256")
	if err != nil {
		t.Error(err)
	}
	if got != want {
		t.Errorf("Want public key %q, got %q", want, got)
	}
}

func TestCalculateFingerprint_SHA1(t *testing.T) {
	b := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB893TCwdZ+b1gN34imBHBDBMzXVPDW/88WWpqQNq2rJ\n"
	want := "ZqUNe/Yg6Clsg7zSuwhZ0OAm2s0"
	got, err := CalculateFingerprint(b, "sha1")
	if err != nil {
		t.Error(err)
	}
	if got != want {
		t.Errorf("Want public key %q, got %q", want, got)
	}
}
