/// <summary>
/// DX.Encryption.pas provides an easy-to-use interface for encrypting and decrypting data
/// using various cryptographic algorithms. It includes a TDXCipher class that acts
/// as a wrapper for different cipher algorithms such as AES, Twofish, and Blowfish.
/// The unit also defines a custom exception class for handling encryption-related errors.
///
/// This unit relies on the Delphi Encryption Compendium (DEC), a comprehensive library
/// that provides implementations of various cryptographic algorithms. By leveraging DEC,
/// this unit abstracts the complexity of cipher operations, offering a simplified API
/// for encryption and decryption tasks.
/// </summary>
unit DX.Encryption;

interface

uses
  System.Classes, System.SysUtils,
  DECCipherBase,
  DECCipherModes,
  DECCipherFormats,
  DECCiphers, System.AnsiStrings, System.Math;

/// <summary>
/// Custom exception class for encryption-related errors.
/// </summary>
type
  EDXEncryptionError = class(Exception)
  end;

  /// <summary>
  /// Type aliases for easy selection of cipher algorithms.
  /// </summary>
type
  // Ciphers
  Twofish = TCipher_Twofish;
  Blowfish = TCipher_Blowfish;
  AES = TCipher_AES256;

  // Cipher modes
  TCipherMode = (
    cmCTSx = Ord(DECCipherBase.TCipherMode.cmCTSx),
    cmCBCx = Ord(DECCipherBase.TCipherMode.cmCBCx),
    cmCFB8 = Ord(DECCipherBase.TCipherMode.cmCFB8),
    cmCFBx = Ord(DECCipherBase.TCipherMode.cmCFBx),
    cmOFB8 = Ord(DECCipherBase.TCipherMode.cmOFB8),
    cmOFBx = Ord(DECCipherBase.TCipherMode.cmOFBx),
    cmCFS8 = Ord(DECCipherBase.TCipherMode.cmCFS8),
    cmCFSx = Ord(DECCipherBase.TCipherMode.cmCFSx),
    cmECBx = Ord(DECCipherBase.TCipherMode.cmECBx),
    cmGCM = Ord(DECCipherBase.TCipherMode.cmGCM),
    cmDefault // use Default for Cipher
    );

  /// <summary>
  /// TDXCipher is a utility class that provides an easy-to-use wrapper for
  /// various cryptographic algorithms. It simplifies the process of encryption
  /// and decryption by abstracting the underlying cipher implementation details.
  /// Users can easily switch between different algorithms like AES, Twofish,
  /// and Blowfish by selecting the appropriate cipher class.
  ///
  /// TDXCipher leverages the Delphi Encryption Compendium (DEC) to perform the actual
  /// cryptographic operations, making it a reliable and robust solution for secure data handling.
  /// </summary>
type
  TDXCipher = class(TObject)
  protected
    /// <summary>
    /// Initializes the cipher with the specified key and initialization vector.
    /// </summary>
    /// <param name="ACipher">The cipher object to be initialized.</param>
    /// <param name="AKey">The encryption key.</param>
    class procedure InitCipher(ACipher: TDECFormattedCipher; const AKey: AnsiString; ACipherMode: TCipherMode);

  public
    /// <summary>
    /// Encrypts the given input string using the specified cipher algorithm and password.
    /// </summary>
    /// <param name="AInput">The string to be encrypted.</param>
    /// <param name="APassword">The password used for encryption.</param>
    /// <param name="ACipherClass">The cipher class to be used for encryption.</param>
    /// <returns>Returns the encrypted data as a byte array.</returns>
    /// <exception cref="EDXEncryptionError">
    /// Raises an exception if encryption fails.
    /// </exception>
    class function Encrypt(AInput: string; APassword: AnsiString; ACipherClass: TDECFormattedCipherClass; ACipherMode:
        TCipherMode = cmDefault): TBytes;

    /// <summary>
    /// Decrypts the given input bytes using the specified cipher algorithm and password.
    /// </summary>
    /// <param name="AInput">The encrypted data as a byte array.</param>
    /// <param name="APassword">The password used for decryption.</param>
    /// <param name="ACipherClass">The cipher class to be used for decryption.</param>
    /// <param name="AStringEncoding">
    /// The encoding used for the output string. If not specified, UTF-8 will be used.
    /// </param>
    /// <returns>Returns the decrypted string.</returns>
    /// <exception cref="EDXEncryptionError">
    /// Raises an exception if decryption fails.
    /// </exception>
    class function Decrypt(AInput: TBytes; APassword: AnsiString; ACipherClass: TDECFormattedCipherClass; ACipherMode:
        TCipherMode = cmDefault; AStringEncoding: TEncoding = nil): string;
  end;

implementation

class procedure TDXCipher.InitCipher(ACipher: TDECFormattedCipher; const AKey: AnsiString; ACipherMode: TCipherMode);
var
  LInitVector: RawByteString;
  LMaxKeySize: Integer;
  LKey : RawByteString;
begin
  // Mode
  if ACipher is AES then
  begin
    if ACipherMode = cmDefault then
    begin
      // Default for AES is authentication mode
      ACipherMode := cmGCM;
    end;
  end
  else
  begin
    if ACipherMode = cmDefault then
    begin
       ACipherMode := cmCBCx;
    end;
  end;
  ACipher.Mode := DECCipherBase.TCipherMode(ACipherMode);
  if ACipherMode = cmGCM then begin
    //Only with cmGCM
    ACipher.AuthenticationResultBitLength := 128;
  end;
  ACipher.FillMode := fmByte;

  // InitVector
  LInitVector := ''; // '!"§%_42_SomeSecretInitializationVector_!§$%_0815'; // Todo: make configurable
  SetLength(LInitVector, Min(Length(LInitVector), ACipher.Context.BufferSize div 2)); // String is 2 bytes per char

  // Key Length
  LMaxKeySize := ACipher.Context.KeySize; // div 2; // String is 2 bytes per char
  LKey := RawByteString(Copy(AKey, 1, LMaxKeySize));
  ACipher.Init(LKey, LInitVector);
end;

class function TDXCipher.Encrypt(AInput: string; APassword: AnsiString; ACipherClass: TDECFormattedCipherClass;
    ACipherMode: TCipherMode = cmDefault): TBytes;
var
  LCipher: TDECFormattedCipher;
  LInput: TBytes;
begin
  LCipher := ACipherClass.Create;
  try
    try
      InitCipher(LCipher, APassword, ACipherMode);
      LInput := TEncoding.UTF8.GetBytes(AInput);
      result := LCipher.EncodeBytes(LInput);
      LCipher.Done;
    except
      on E: Exception do
        raise EDXEncryptionError.Create('Encryption failed. ' + E.Message);
    end;
  finally
    // Clean up. Also removes the key from RAM
    LCipher.Free;
  end;
end;

class function TDXCipher.Decrypt(AInput: TBytes; APassword: AnsiString; ACipherClass: TDECFormattedCipherClass;
    ACipherMode: TCipherMode = cmDefault; AStringEncoding: TEncoding = nil): string;
var
  LCipher: TDECFormattedCipher;
  LOutput: TBytes;
  LEncoding: TEncoding;
begin
  LCipher := ACipherClass.Create;
  try
    try
      InitCipher(LCipher, APassword, ACipherMode);
      LOutput := LCipher.DecodeBytes(AInput);
      LCipher.Done;
      if Assigned(AStringEncoding) then
      begin
        LEncoding := AStringEncoding;
      end
      else
      begin
        LEncoding := TEncoding.UTF8;
      end;
      result := LEncoding.GetString(LOutput);
    except
      on E: Exception do
        raise EDXEncryptionError.Create('Decryption failed. ' + E.Message);
    end;
  finally
    // Clean up. Also removes the key from RAM
    LCipher.Free;
  end;
end;

end.
