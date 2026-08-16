


void FUN_71005fb830(long param_1,undefined8 param_2,long *param_3)

{
  undefined1 *puVar1;
  long lVar2;
  long lVar3;
  
  if (0 < *(int *)(param_1 + 0x18)) {
    lVar2 = 0;
    lVar3 = 0x98;
    do {
      puVar1 = (undefined1 *)(*(long *)(param_1 + 8) + lVar3);
      FUN_71006022e4(puVar1 + -0x78);
      *puVar1 = 0;
      lVar2 = lVar2 + 1;
      lVar3 = lVar3 + 0xa0;
    } while (lVar2 < *(int *)(param_1 + 0x18));
  }
  (**(code **)(*param_3 + 0x18))(param_3,*(undefined8 *)(param_1 + 8));
  (**(code **)(*param_3 + 0x18))(param_3,*(undefined8 *)(param_1 + 0x10));
  *(undefined8 *)(param_1 + 0x15) = 0;
  *(undefined8 *)(param_1 + 8) = 0;
  *(undefined8 *)(param_1 + 0x10) = 0;
  return;
}



void FUN_71005fbb20(undefined8 param_1,undefined8 param_2)

{
  thunk_EXT_FUN_02e95df0(&DAT_7103ff3668);
  thunk_EXT_FUN_02e95df0(&DAT_7103ff3668,param_1,param_2,0);
  DAT_7103ff3658 = param_1;
  DAT_7103ff3660 = param_2;
  return;
}



long FUN_71005fbb80(undefined8 param_1)

{
  long lVar1;
  undefined4 *puVar2;
  
  if ((DAT_7103ff3660 != 0) && (lVar1 = thunk_EXT_FUN_02e95df0(&DAT_7103ff3668,param_1), lVar1 != 0)
     ) {
    return lVar1;
  }
  puVar2 = (undefined4 *)thunk_EXT_FUN_02e95df0();
  *puVar2 = 0xc;
  return 0;
}



void FUN_71005fbbd0(long param_1)

{
  if (param_1 != 0) {
    thunk_EXT_FUN_02e95df0(&DAT_7103ff3668,param_1);
    return;
  }
  return;
}



long FUN_71005fbc60(undefined8 param_1,undefined8 param_2)

{
  long lVar1;
  undefined4 *puVar2;
  
  if ((DAT_7103ff3660 != 0) &&
     (lVar1 = thunk_EXT_FUN_02e95df0(&DAT_7103ff3668,param_1,param_2), lVar1 != 0)) {
    return lVar1;
  }
  puVar2 = (undefined4 *)thunk_EXT_FUN_02e95df0();
  *puVar2 = 0xc;
  return 0;
}



long FUN_71005fbcb0(undefined8 param_1,undefined8 param_2)

{
  long lVar1;
  undefined4 *puVar2;
  
  if ((DAT_7103ff3660 != 0) &&
     (lVar1 = thunk_EXT_FUN_02e95df0(&DAT_7103ff3668,param_2,param_1), lVar1 != 0)) {
    return lVar1;
  }
  puVar2 = (undefined4 *)thunk_EXT_FUN_02e95df0();
  *puVar2 = 0xc;
  return 0;
}



void FUN_71005fbcfc(undefined8 *param_1)

{
  *param_1 = 0;
  return;
}



void FUN_71005fbd04(undefined4 *param_1)

{
  *(undefined8 *)(param_1 + 1) = 0;
  *(undefined8 *)(param_1 + 3) = 0;
  *param_1 = 0x22;
  param_1[5] = 0;
  return;
}



void FUN_71005fbd1c(undefined8 *param_1)

{
  param_1[5] = 0;
  param_1[6] = 0;
  *param_1 = 0;
  param_1[3] = 0;
  param_1[4] = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  return;
}



undefined8 FUN_71005fbd30(undefined8 param_1)

{
  ulong uVar1;
  
  uVar1 = thunk_EXT_FUN_02e95df0();
  if ((uVar1 & 1) == 0) {
    thunk_EXT_FUN_02e95df0(param_1);
    thunk_EXT_FUN_02e95df0();
  }
  return param_1;
}



undefined8 FUN_71005fbd64(undefined8 param_1)

{
  ulong uVar1;
  
  uVar1 = thunk_EXT_FUN_02e95df0();
  if ((uVar1 & 1) == 0) {
    thunk_EXT_FUN_02e95df0(param_1);
    thunk_EXT_FUN_02e95df0();
  }
  return param_1;
}



void FUN_71005fbd98(undefined8 *param_1)

{
  *(undefined4 *)(param_1 + 2) = 0;
  *param_1 = 0x2a010000020202;
  param_1[1] = 0x447a0000c47a0000;
  return;
}



void FUN_71005fbdbc(undefined1 *param_1)

{
  *(ushort *)(param_1 + 2) = *(ushort *)(param_1 + 2) & 0xfffe;
  *param_1 = 1;
  *(undefined4 *)(param_1 + 4) = 0xffffffff;
  return;
}



void FUN_71005fbddc(undefined4 *param_1)

{
  param_1[4] = 0;
  *param_1 = 0x3020002;
  *(undefined8 *)(param_1 + 2) = 0;
  *(undefined1 *)((long)param_1 + 6) = 0;
  *(ushort *)(param_1 + 1) = *(ushort *)(param_1 + 1) & 0xfff0;
  *(ushort *)((long)param_1 + 0x1a) = *(ushort *)((long)param_1 + 0x1a) & 0xfffe;
  *(undefined1 *)(param_1 + 6) = 1;
  param_1[7] = 0xffffffff;
  return;
}



void FUN_71005fbe20(byte *param_1)

{
  param_1[5] = 0;
  param_1[6] = 0;
  param_1[1] = 1;
  param_1[2] = 0;
  param_1[3] = 0;
  param_1[4] = 1;
  *param_1 = *param_1 & 0xfe;
  param_1[7] = 0xf;
  return;
}



void FUN_71005fbe48(undefined2 *param_1)

{
  *(undefined8 *)(param_1 + 2) = 0;
  *(undefined8 *)(param_1 + 6) = 0x3f80000000000000;
  *(undefined8 *)(param_1 + 0xc) = 0;
  param_1[1] = param_1[1] & 0xfff0;
  *param_1 = 0x500;
  return;
}



void FUN_71005fbe70(undefined4 *param_1)

{
  *(undefined1 *)(param_1 + 1) = 0;
  *param_1 = 0x7000000;
  return;
}



void FUN_71005fbe80(undefined2 *param_1)

{
  *(undefined1 *)(param_1 + 6) = 0;
  *param_1 = 0xff01;
  *(undefined4 *)(param_1 + 4) = 0x7000000;
  *(undefined1 *)(param_1 + 1) = 0xff;
  *(undefined4 *)(param_1 + 0xc) = 0x7000000;
  *(undefined1 *)(param_1 + 0xe) = 0;
  param_1[2] = param_1[2] & 0xfff0;
  return;
}



void FUN_71005fbeb4(undefined4 *param_1)

{
  *param_1 = 0;
  return;
}



void FUN_71005fbebc(undefined1 *param_1)

{
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined8 *)(param_1 + 8) = 0;
  *param_1 = 0;
  return;
}



void FUN_71005fbecc(undefined1 *param_1)

{
  *param_1 = 0;
  *(undefined4 *)(param_1 + 2) = 0xffff;
  *(undefined8 *)(param_1 + 8) = 0;
  *(undefined8 *)(param_1 + 0x10) = 0;
  return;
}



void FUN_71005fbee0(undefined8 *param_1)

{
  *param_1 = 0;
  return;
}



void FUN_71005fbee8(undefined4 *param_1)

{
  *param_1 = 0;
  *(undefined8 *)(param_1 + 2) = 0;
  *(undefined8 *)(param_1 + 4) = 0;
  return;
}



void FUN_71005fbef4(undefined8 *param_1)

{
  *param_1 = 0;
  param_1[1] = 0;
  param_1[2] = 0x3f80000000000000;
  return;
}



void FUN_71005fbf04(undefined8 *param_1)

{
  *param_1 = 0;
  param_1[1] = 0;
  return;
}



void FUN_71005fbf0c(byte *param_1)

{
  param_1[2] = 0;
  param_1[3] = 0;
  param_1[4] = 0;
  param_1[5] = 0;
  param_1[8] = 0;
  param_1[9] = 0;
  param_1[10] = 0;
  param_1[0xb] = 0;
  param_1[0xc] = 0;
  param_1[0xd] = 0;
  param_1[0xe] = 0;
  param_1[0xf] = 0;
  param_1[0x10] = 0;
  param_1[0x11] = 0;
  param_1[0x12] = 0;
  param_1[0x13] = 0;
  param_1[0x14] = 0;
  param_1[0x15] = 0;
  param_1[0x16] = 0;
  param_1[0x17] = 0;
  *param_1 = *param_1 & 0xfe;
  return;
}



void FUN_71005fbf24(long param_1)

{
  *(undefined8 *)(param_1 + 0xc) = 0;
  *(undefined1 *)(param_1 + 1) = 2;
  *(undefined2 *)(param_1 + 2) = 0;
  *(undefined8 *)(param_1 + 0x14) = 0x100000001;
  *(undefined4 *)(param_1 + 4) = 0x10000;
  *(undefined8 *)(param_1 + 0x1c) = 1;
  *(undefined2 *)(param_1 + 8) = 1;
  return;
}



void FUN_71005fbf54(undefined2 *param_1)

{
  *(undefined8 *)(param_1 + 0x18) = 0;
  *param_1 = 1;
  *(undefined8 *)(param_1 + 2) = 0x504030200000000;
  *(undefined4 *)(param_1 + 8) = 0x10000;
  *(undefined8 *)(param_1 + 0x10) = 0x100000000;
  return;
}



void FUN_71005fbf80(undefined1 *param_1)

{
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined2 *)(param_1 + 2) = 0;
  *param_1 = 1;
  *(undefined8 *)(param_1 + 0x18) = 0;
  *(undefined8 *)(param_1 + 8) = 0x100000000;
  return;
}



void FUN_71005fbfa0(undefined1 *param_1)

{
  *(undefined2 *)(param_1 + 2) = 0;
  *(undefined8 *)(param_1 + 0x18) = 0;
  *param_1 = 1;
  *(undefined8 *)(param_1 + 8) = 0x100000000;
  return;
}



void FUN_71005fbfbc(undefined2 *param_1)

{
  *param_1 = 0;
  *(undefined4 *)(param_1 + 2) = 0;
  return;
}



void FUN_71005fbfc8(undefined8 *param_1)

{
  *(undefined2 *)(param_1 + 3) = 0;
  *param_1 = 0;
  param_1[1] = 0x100000000;
  param_1[2] = 0x100000001;
  *(undefined8 *)((long)param_1 + 0x1c) = 0x100000000;
  return;
}



uint FUN_71005fbfe4(undefined8 *param_1,long param_2)

{
  uint uVar1;
  undefined8 *puVar2;
  uint uVar3;
  uint uVar4;
  uint local_3c;
  uint local_38;
  uint local_34;
  
  puVar2 = DAT_7103a64b70;
  uVar1 = *(uint *)(param_2 + 4);
  uVar4 = 8;
  if ((uVar1 >> 4 & 1) != 0) {
    local_34 = 0;
    (*(code *)*DAT_7103a64b70)(*param_1,4,&local_34);
    uVar4 = local_34;
    if ((int)local_34 < 9) {
      uVar4 = 8;
    }
  }
  if ((uVar1 >> 9 & 1) != 0) {
    local_38 = 0;
    (*(code *)*puVar2)(*param_1,0xd,&local_38);
    if ((int)uVar4 <= (int)local_38) {
      uVar4 = local_38;
    }
    (*(code *)*puVar2)(*param_1,0x35,&local_38);
    if ((int)uVar4 <= (int)local_38) {
      uVar4 = local_38;
    }
  }
  if ((uVar1 >> 0xb & 1) != 0) {
    local_3c = 0;
    (*(code *)*puVar2)(*param_1,10,&local_3c);
    if ((int)uVar4 <= (int)local_3c) {
      uVar4 = local_3c;
    }
  }
  uVar3 = uVar4;
  if (uVar4 < 0x21) {
    uVar3 = 0x20;
  }
  if ((uVar1 & 0x40) != 0) {
    uVar4 = uVar3;
  }
  uVar3 = uVar4;
  if (uVar4 < 0x201) {
    uVar3 = 0x200;
  }
  if ((uVar1 & 0x1a0) != 0) {
    uVar4 = uVar3;
  }
  uVar3 = uVar4;
  if (uVar4 < 0x11) {
    uVar3 = 0x10;
  }
  if ((uVar1 & 0x4000) != 0) {
    uVar4 = uVar3;
  }
  return uVar4;
}



void FUN_71005fc110(undefined8 *param_1)

{
  param_1[7] = 0;
  param_1[8] = 0;
  *param_1 = 0;
  param_1[5] = 0;
  param_1[6] = 0;
  param_1[3] = 0;
  param_1[4] = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  return;
}
