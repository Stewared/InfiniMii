


void FUN_7100ba6d44(undefined8 *param_1)

{
  *param_1 = 0xb0100000b01;
  param_1[1] = 0x100000001;
  param_1[2] = 0x20000000200;
  param_1[3] = 0x900000001;
  param_1[4] = 0x1003f800000;
  *(undefined4 *)(param_1 + 5) = 0x10000;
  return;
}



void FUN_7100ba6d7c(undefined4 *param_1,undefined4 param_2,undefined4 param_3)

{
  *param_1 = param_2;
  param_1[1] = param_3;
  return;
}



void FUN_7100ba6d84(long param_1,undefined4 param_2,undefined4 param_3)

{
  *(undefined4 *)(param_1 + 8) = param_2;
  *(undefined4 *)(param_1 + 0xc) = param_3;
  return;
}



void FUN_7100ba6d8c(long param_1,undefined4 param_2,undefined4 param_3)

{
  *(undefined4 *)(param_1 + 0x10) = param_2;
  *(undefined4 *)(param_1 + 0x14) = param_3;
  return;
}



void FUN_7100ba6d94(long param_1,undefined4 param_2)

{
  *(undefined4 *)(param_1 + 0x18) = param_2;
  return;
}



void FUN_7100ba6d9c(long param_1,undefined4 param_2)

{
  *(undefined4 *)(param_1 + 0x1c) = param_2;
  return;
}



void FUN_7100ba6da4(undefined4 param_1,long param_2)

{
  *(undefined4 *)(param_2 + 0x20) = param_1;
  return;
}



undefined4 FUN_7100ba6dac(undefined4 *param_1)

{
  return *param_1;
}



undefined4 FUN_7100ba6db4(long param_1)

{
  return *(undefined4 *)(param_1 + 4);
}



undefined4 FUN_7100ba6dbc(long param_1)

{
  return *(undefined4 *)(param_1 + 8);
}



undefined4 FUN_7100ba6dc4(long param_1)

{
  return *(undefined4 *)(param_1 + 0xc);
}



undefined4 FUN_7100ba6dcc(long param_1)

{
  return *(undefined4 *)(param_1 + 0x10);
}



undefined4 FUN_7100ba6dd4(long param_1)

{
  return *(undefined4 *)(param_1 + 0x14);
}



undefined4 FUN_7100ba6ddc(long param_1)

{
  return *(undefined4 *)(param_1 + 0x1c);
}



undefined4 FUN_7100ba6de4(long param_1)

{
  return *(undefined4 *)(param_1 + 0x20);
}



undefined4 FUN_7100ba6dec(long param_1)

{
  return *(undefined4 *)(param_1 + 0x24);
}



undefined4 FUN_7100ba6df4(long param_1)

{
  return *(undefined4 *)(param_1 + 0x28);
}



void FUN_7100ba6e00(undefined8 *param_1)

{
  FUN_71005fbd98(param_1);
  *(undefined2 *)((long)param_1 + 6) = 0x29;
  *(undefined2 *)param_1 = 0x101;
  *(undefined1 *)((long)param_1 + 2) = 1;
  return;
}



uint FUN_7100ba6e40(uint param_1)

{
  char cVar1;
  int iVar2;
  uint uVar3;
  
  cVar1 = FUN_7100ba7690((char)param_1);
  if (cVar1 == '\x01') {
    return param_1;
  }
  iVar2 = FUN_7100ba7680(param_1);
  uVar3 = FUN_7100ba76a0(iVar2,1);
  return uVar3;
}



void FUN_7100ba6e84(undefined8 *param_1)

{
  *(undefined1 *)(param_1 + 1) = 0;
  *param_1 = 0;
  return;
}
