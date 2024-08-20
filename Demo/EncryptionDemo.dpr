program EncryptionDemo;
{$APPTYPE CONSOLE}
{$R *.res}


uses
  System.SysUtils,
  DX.Encryption;

const
  TEST_STRING = 'HELLO WORLD';
  TEST_PASSWORD = 'some_very_secret_phrase0815';

var
  LEncrypted: TBytes;
  LDecrypted: string;

begin
  try
    Writeln('Executing TDXCipher.Encrypt and TDXCipher.Decrypt with various algorithms');
    Writeln;
    Writeln('BLOWFISH');
    Writeln('encrypting ...');
    LEncrypted := TDXCipher.Encrypt(TEST_STRING, TEST_PASSWORD, Blowfish);
    Assert(Length(LEncrypted) > 0);
    Writeln('decrypting ...');
    LDecrypted := TDXCipher.Decrypt(LEncrypted, TEST_PASSWORD, Blowfish);
    Assert(LDecrypted = TEST_STRING);
    Writeln;

    Writeln('AES');
    Writeln('encrypting ...');
    LEncrypted := TDXCipher.Encrypt(TEST_STRING, TEST_PASSWORD, AES);
    Assert(Length(LEncrypted) > 0);
    Writeln('decrypting ...');
    LDecrypted := TDXCipher.Decrypt(LEncrypted, TEST_PASSWORD, AES);
    Assert(LDecrypted = TEST_STRING);
    Writeln;

    Writeln('TWOFISH');
    Writeln('encrypting ...');
    LEncrypted := TDXCipher.Encrypt(TEST_STRING, TEST_PASSWORD, Twofish);
    Assert(Length(LEncrypted) > 0);
    Writeln('decrypting ...');
    LDecrypted := TDXCipher.Decrypt(LEncrypted, TEST_PASSWORD, Twofish);
    Assert(LDecrypted = TEST_STRING);
    Writeln;

    Writeln('All tests passed');
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
  Readln;

end.
