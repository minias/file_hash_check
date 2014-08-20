unit main;

{$mode objfpc}{$H+}

interface

uses
  LCLIntf, // OpenURL
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, EditBtn,
  StdCtrls, Buttons, ExtCtrls, DCPsha256, DCPmd5, DCPsha1;

type

  { TForm1 }

  TForm1 = class(TForm)
    edt_sha256: TEdit;
    edt_md5: TEdit;
    edt_sha1: TEdit;
    FileNameEdit1: TFileNameEdit;
    Label1: TLabel;
    Label2: TLabel;
    Label3: TLabel;
    btn_vt: TSpeedButton;
    procedure FileNameEdit1AcceptFileName(Sender: TObject);
    procedure FormDropFiles(Sender: TObject; const FileNames: array of String);
    procedure btn_vtClick(Sender: TObject);
    procedure md5Encrypt(Sender: TObject);
    procedure sha1Encrypt(Sender: TObject);
    procedure sha256Encrypt(Sender: TObject);
    procedure edt_sha256Change(Sender: TObject);
    procedure ZeroMemory(Destination: Pointer; Length: DWORD);
  private
    { private declarations }
  public
    { public declarations }
  end;

var
  Form1: TForm1;

implementation

{$R *.lfm}

{ TForm1 }

procedure TForm1.sha256Encrypt(Sender: TObject);
var
  Hash: TDCP_sha256;
  Digest: array[0..63] of byte;
  Source: TFileStream;
  i: integer;
  s,f: string;
begin
  // Local variable 'Digest' does not seem to be initialized Fix
  ZeroMemory(@Digest, SizeOf(Digest));
  Source:= nil;
  f:=  UTF8ToSys(FileNameEdit1.FileName);
  try
    //한글 오류 수정 UTF8ToSys
    Source:= TFileStream.Create(f,fmOpenRead);
  except
    MessageDlg('Unable to open file',mtError,[mbOK],0);
  end;
  if Source <> nil then
  begin
    Hash:= TDCP_sha256.Create(Self);
    Hash.Init;
    Hash.UpdateStream(Source,Source.Size);
    Hash.Final(Digest);
    Source.Free;
    s:= '';
    for i:= 0 to 31 do
      s:= s + IntToHex(Digest[i],2);
    edt_sha256.Text:= s;
  end;
end;

procedure TForm1.FileNameEdit1AcceptFileName(Sender: TObject);
begin
  md5Encrypt(Sender);
  sha1Encrypt(Sender);
  sha256Encrypt(Sender);
end;

procedure TForm1.sha1Encrypt(Sender: TObject);
var
  Hash: TDCP_sha1;
  Digest: array[0..39] of byte;
  Source: TFileStream;
  i: integer;
  s,f: string;
begin

  // Local variable 'Digest' does not seem to be initialized Fix
  ZeroMemory(@Digest, SizeOf(Digest));
  Source:= nil;
  f:=  UTF8ToSys(FileNameEdit1.FileName);
  try
    //한글 오류 수정 UTF8ToSys
    Source:= TFileStream.Create(f,fmOpenRead);
  except
    MessageDlg('Unable to open file',mtError,[mbOK],0);
  end;
  if Source <> nil then
  begin
    Hash:= TDCP_sha1.Create(Self);
    Hash.Init;
    Hash.UpdateStream(Source,Source.Size);
    Hash.Final(Digest);
    Source.Free;
    s:= '';
    for i:= 0 to 19 do
      s:= s + IntToHex(Digest[i],2);
    edt_sha1.Text:= s;
  end;
end;

procedure TForm1.md5Encrypt(Sender: TObject);
var
  Hash: TDCP_md5;
  Digest: array[0..31] of byte;
  Source: TFileStream;
  i: integer;
  s,f: string;
begin
  // Local variable 'Digest' does not seem to be initialized Fix
  ZeroMemory(@Digest, SizeOf(Digest));
  Source:= nil;
  f:=  UTF8ToSys(FileNameEdit1.FileName);
  try
    //한글 오류 수정 UTF8ToSys
    Source:= TFileStream.Create(f,fmOpenRead);
  except
    MessageDlg('Unable to open file',mtError,[mbOK],0);
  end;
  if Source <> nil then
  begin
    Hash:= TDCP_md5.Create(Self);
    Hash.Init;
    Hash.UpdateStream(Source,Source.Size);
    Hash.Final(Digest);
    Source.Free;
    s:= '';
    for i:= 0 to 15 do
      s:= s + IntToHex(Digest[i],2);
    edt_md5.Text:= s;
  end;
end;

procedure TForm1.edt_sha256Change(Sender: TObject);
begin
  if edt_sha256.text <> '' then
    btn_vt.Visible:= true
  else
    btn_vt.Visible:= false;
end;

procedure TForm1.FormDropFiles(Sender: TObject; const FileNames: array of String
  );
var
  i: Integer;
  filename:String;
begin
  for i := Low(FileNames) to High(FileNames) do
  begin
     filename     :=  FileNames[i];
     FileNameEdit1.Filename := filename;
     Form1.FileNameEdit1AcceptFileName(Sender);
  end;

end;

procedure TForm1.btn_vtClick(Sender: TObject);
begin
  if edt_sha256.text <> '' then
    OpenURL('https://www.virustotal.com/ko/file/' + pchar(edt_sha256.text) + '/analysis/');
end;

// does not seem to be initialized Fix
procedure TForm1.ZeroMemory(Destination: Pointer; Length: DWORD);
begin
  FillChar(Destination^, Length, 0);
end;

end.

