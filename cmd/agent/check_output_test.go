package main

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"golang.org/x/text/encoding/charmap"
)

// cp850 is what ping.exe and sc.exe write on a pt-BR Windows.
func cp850(t *testing.T, s string) []byte {
	t.Helper()
	b, err := charmap.CodePage850.NewEncoder().Bytes([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// noReplacement fails when the text would reach the console with "?" in
// place of a character: invalid UTF-8 becomes U+FFFD once it is marshalled.
func noReplacement(t *testing.T, got string) {
	t.Helper()
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if !utf8.ValidString(got) || strings.Contains(string(encoded), `�`) {
		t.Fatalf("output would show replacement characters: %s", encoded)
	}
}

func TestPingOutputKeepsAccentsFromTheConsolePage(t *testing.T) {
	text := "Estatísticas do Ping para 8.8.8.8:\r\n    Pacotes: Enviados = 1, Recebidos = 1, Perdidos = 0 (0% de perda),\r\nAproximar um número redondo de vezes em milissegundos:"
	raw := cp850(t, text)
	if utf8.Valid(raw) {
		t.Fatal("precondition: cp850 bytes are not UTF-8")
	}
	ok, got := pingResult(raw, nil, 850)
	if !ok || got != text {
		t.Fatalf("pingResult = %v, %q", ok, got)
	}
	noReplacement(t, got)
	if ok, _ := pingResult(raw, errors.New("exit status 1"), 850); ok {
		t.Fatal("a failed ping passed")
	}
	// Linux and macOS print UTF-8, which passes through untouched.
	if _, got := pingResult([]byte("1 packets transmitted, 1 received, 0% packet loss"), nil, 0); got != "1 packets transmitted, 1 received, 0% packet loss" {
		t.Fatalf("UTF-8 output changed: %q", got)
	}
}

func TestServiceQueryOutputKeepsAccentsAndTheState(t *testing.T) {
	running := "\r\nNOME_DO_SERVIÇO: Spooler\r\n        TIPO               : 110  WIN32_OWN_PROCESS\r\n        ESTADO             : 4  RUNNING\r\n"
	ok, got := serviceQueryResult(cp850(t, running), 850)
	if !ok || got != running {
		t.Fatalf("serviceQueryResult = %v, %q", ok, got)
	}
	noReplacement(t, got)

	missing := "[SC] OpenService FALHA 1060:\r\n\r\nO serviço especificado não existe como serviço instalado.\r\n"
	ok, got = serviceQueryResult(cp850(t, missing), 850)
	if ok || got != missing {
		t.Fatalf("missing service = %v, %q", ok, got)
	}
	noReplacement(t, got)

	stopped := "NOME_DO_SERVIÇO: Spooler\r\n        ESTADO             : 1  STOPPED\r\n"
	if ok, _ := serviceQueryResult(cp850(t, stopped), 850); ok {
		t.Fatal("a stopped service passed")
	}
}
