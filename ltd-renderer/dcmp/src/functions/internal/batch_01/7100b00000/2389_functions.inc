


void FUN_7100ba7ea4(long param_1,long param_2)

{
  *(ulong *)(param_1 + 0x10) = (param_2 + *(long *)(param_1 + 0x10)) - 1U & -param_2;
  return;
}



undefined8 FUN_7100ba7ec0(undefined8 *param_1)

{
  return *param_1;
}



undefined8 FUN_7100ba7ec8(long param_1)

{
  return *(undefined8 *)(param_1 + 0x10);
}



void FUN_7100ba7ed0(long param_1,long param_2)

{
  *(long *)(param_1 + 0x10) = *(long *)(param_1 + 0x10) + param_2;
  return;
}



void FUN_7100ba7ee0(byte *param_1,long *param_2,uint *param_3,undefined4 *param_4)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  undefined4 uVar4;
  ushort uVar5;
  undefined2 uVar6;
  long lVar7;
  ushort uVar8;
  int iVar9;
  bool bVar10;
  byte bVar11;
  byte *pbVar12;
  int iVar13;
  ulong uVar14;
  int iVar15;
  ulong uVar16;
  ulong uVar17;
  
  uVar2 = *param_3;
  uVar3 = param_3[1];
  FUN_71005fbe20(param_1);
  param_1[7] = (byte)param_3[2];
  *param_1 = *param_1 & 0xfe | (uVar2 != 0 || uVar3 != 0);
  if (uVar2 != 0 || uVar3 != 0) {
    uVar2 = *param_3;
    param_1[3] = 0;
    param_1[1] = (byte)*(undefined4 *)(&DAT_71032a8c54 + (ulong)uVar2 * 0xc);
    param_1[2] = (byte)*(undefined4 *)(&DAT_71032a8c58 + (ulong)uVar2 * 0xc);
    lVar7 = (ulong)param_3[1] * 0xc;
    param_1[6] = (byte)*(undefined4 *)(&DAT_71032a8c80 + lVar7);
    param_1[4] = (byte)*(undefined4 *)(&DAT_71032a8c84 + lVar7);
    param_1[5] = (byte)*(undefined4 *)(&DAT_71032a8c88 + lVar7);
  }
  FUN_71005fbe48((undefined2 *)(param_1 + 0x20));
  *(byte **)(param_1 + 0x38) = param_1;
  param_1[0x20] = 1;
  FUN_71005fbe80((undefined2 *)(param_1 + 0x50));
  uVar2 = param_3[3];
  uVar5 = *(ushort *)(param_1 + 0x54);
  *(ushort *)(param_1 + 0x54) = uVar5 & 0xfffe | (ushort)(0 < (int)uVar2);
  uVar8 = (ushort)(0 < (int)uVar2) | (ushort)(param_3[3] == 2) << 1;
  *(ushort *)(param_1 + 0x54) = uVar5 & 0xfffc | uVar8;
  uVar2 = param_3[4];
  *(ushort *)(param_1 + 0x54) = uVar5 & 0xfff8 | uVar8 | (ushort)(uVar2 != 0) << 2;
  if (uVar2 != 0) {
    param_1[0x51] = 1;
    param_1[0x52] = 1;
    uVar2 = param_3[5];
    if (uVar2 == 2) {
      uVar2 = param_3[4];
      FUN_71005fbe70((undefined4 *)(param_1 + 0x58));
      if (2 < uVar2 - 1) goto ret_7100BA856C;
      uVar2 = (uVar2 - 1) * 8;
      param_1[0x58] = 0;
      param_1[0x59] = 0;
      param_1[0x5a] = (byte)(0x20002 >> (ulong)(uVar2 & 0x18));
      param_1[0x5b] = (byte)(0x50207 >> (ulong)(uVar2 & 0x18));
      pbVar12 = param_1 + 0x5c;
    }
    else {
      if (uVar2 == 1) {
        uVar2 = param_3[4];
        FUN_71005fbe70((undefined4 *)(param_1 + 0x68));
        if (2 < uVar2 - 1) goto ret_7100BA856C;
        uVar2 = (uVar2 - 1) * 8;
        param_1[0x68] = 0;
        param_1[0x69] = 0;
        param_1[0x6b] = (byte)(0x50207 >> (ulong)(uVar2 & 0x18));
        bVar11 = (byte)(0x20002 >> (ulong)(uVar2 & 0x18));
      }
      else {
        if (uVar2 != 0) {
ret_7100BA856C:
          thunk_EXT_FUN_02e95df0();
          return;
        }
        uVar2 = param_3[4];
        FUN_71005fbe70((undefined4 *)(param_1 + 0x58));
        if (2 < uVar2 - 1) goto ret_7100BA856C;
        param_1[0x58] = 0;
        param_1[0x59] = 0;
        uVar2 = (uVar2 - 1) * 8;
        param_1[0x5a] = (byte)(0x20002 >> (ulong)(uVar2 & 0x18));
        param_1[0x5b] = (byte)(0x50207 >> (ulong)(uVar2 & 0x18));
        param_1[0x5c] = 1;
        uVar2 = param_3[4];
        FUN_71005fbe70((undefined4 *)(param_1 + 0x68));
        if (2 < uVar2 - 1) goto ret_7100BA856C;
        uVar2 = (uVar2 - 1) * 8;
        param_1[0x68] = 0;
        param_1[0x69] = 0;
        bVar11 = (byte)(0x20002 >> (ulong)(uVar2 & 0x18));
        param_1[0x6b] = (byte)(0x50207 >> (ulong)(uVar2 & 0x18));
      }
      param_1[0x6a] = bVar11;
      pbVar12 = param_1 + 0x6c;
    }
    *pbVar12 = 1;
  }
  FUN_71005fbddc((undefined4 *)(param_1 + 0x90));
  uVar2 = param_3[5];
  param_1[0x91] = 0;
  param_1[0x93] = 3;
  param_1[0x92] = (byte)uVar2;
  *(ushort *)(param_1 + 0x94) = *(ushort *)(param_1 + 0x94) & 0xfffe | 8;
  FUN_71005fbeb4((undefined4 *)(param_1 + 0xd0));
  *(undefined4 *)(param_1 + 0xd0) = *param_4;
  FUN_71005fbebc(param_1 + 0xf0);
  *(byte **)(param_1 + 0xf8) = param_1 + 0xd0;
  param_1[0xf0] = 1;
  *(undefined4 *)(param_1 + 0xf4) = param_4[1];
  uVar2 = param_3[6];
  uVar14 = (ulong)uVar2;
  FUN_71005fbee8((undefined4 *)(param_1 + 0x260));
  if ((&DAT_71032a8cc8)[uVar14 * 0x10] == '\0') {
    uVar6 = *(undefined2 *)(&DAT_71032a8ccc + uVar14 * 0x10);
    *(byte **)(param_1 + 0x268) = param_1 + 0x110;
    *(byte **)(param_1 + 0x270) = param_1 + 0x200;
    *(undefined2 *)(param_1 + 0x260) = uVar6;
    *(undefined2 *)(param_1 + 0x262) = uVar6;
    FUN_71005fbecc(param_1 + 0x110);
    param_1[0x112] = 0;
    param_1[0x113] = 0;
    param_1[0x114] = 0;
    param_1[0x115] = 0;
    param_1[0x118] = 0;
    param_1[0x119] = 0;
    param_1[0x11a] = 0;
    param_1[0x11b] = 0;
    param_1[0x11c] = 5;
    param_1[0x11d] = 0x15;
    param_1[0x11e] = 0;
    param_1[0x11f] = 0;
    FUN_71005fbee0((undefined8 *)(param_1 + 0x200));
    param_1[0x200] = 8;
    param_1[0x201] = 0;
    param_1[0x202] = 0;
    param_1[0x203] = 0;
    if (uVar14 - 7 < 0xfffffffffffffffb) {
      uVar16 = 1;
    }
    else {
      FUN_71005fbecc(param_1 + 0x138);
      param_1[0x140] = 0;
      param_1[0x141] = 0;
      param_1[0x142] = 0;
      param_1[0x143] = 0;
      param_1[0x144] = 2;
      param_1[0x145] = 0xe;
      param_1[0x146] = 0;
      param_1[0x147] = 0;
      param_1[0x13a] = 1;
      param_1[0x13b] = 0;
      param_1[0x13c] = 1;
      param_1[0x13d] = 0;
      FUN_71005fbee0((undefined8 *)(param_1 + 0x210));
      uVar16 = 2;
      param_1[0x210] = 4;
      param_1[0x211] = 0;
      param_1[0x212] = 0;
      param_1[0x213] = 0;
    }
    if ((uVar2 & 0xfffffffd) != 0) {
      FUN_71005fbecc(param_1 + uVar16 * 0x28 + 0x110);
      *(short *)(param_1 + uVar16 * 0x28 + 0x114) = (short)uVar16;
      pbVar12 = param_1 + uVar16 * 0x28 + 0x118;
      pbVar12[0] = 0;
      pbVar12[1] = 0;
      pbVar12[2] = 0;
      pbVar12[3] = 0;
      pbVar12[4] = 5;
      pbVar12[5] = 0x12;
      pbVar12[6] = 0;
      pbVar12[7] = 0;
      *(short *)(param_1 + uVar16 * 0x28 + 0x112) = (short)uVar16;
      FUN_71005fbee0((undefined8 *)(param_1 + uVar16 * 0x10 + 0x200));
      pbVar12 = param_1 + uVar16 * 0x10 + 0x200;
      pbVar12[0] = 4;
      pbVar12[1] = 0;
      pbVar12[2] = 0;
      pbVar12[3] = 0;
      uVar3 = (int)uVar16 + 1;
      if (0xfffffffd < uVar2 - 7) {
        FUN_71005fbecc(param_1 + (ulong)uVar3 * 0x28 + 0x110);
        *(short *)(param_1 + (ulong)uVar3 * 0x28 + 0x114) = (short)uVar3;
        pbVar12 = param_1 + (ulong)uVar3 * 0x28 + 0x118;
        pbVar12[0] = 0;
        pbVar12[1] = 0;
        pbVar12[2] = 0;
        pbVar12[3] = 0;
        pbVar12[4] = 2;
        pbVar12[5] = 0xb;
        pbVar12[6] = 0;
        pbVar12[7] = 0;
        *(short *)(param_1 + (ulong)uVar3 * 0x28 + 0x112) = (short)uVar3;
        FUN_71005fbee0((undefined8 *)(param_1 + (ulong)uVar3 * 0x10 + 0x200));
        pbVar12 = param_1 + (ulong)uVar3 * 0x10 + 0x200;
        pbVar12[0] = 4;
        pbVar12[1] = 0;
        pbVar12[2] = 0;
        pbVar12[3] = 0;
        uVar3 = (int)uVar16 + 2;
      }
      uVar16 = (ulong)uVar3;
    }
    uVar17 = uVar16;
    if (0xfffffffffffffffc < uVar14 - 7) {
      FUN_71005fbecc(param_1 + uVar16 * 0x28 + 0x110);
      *(short *)(param_1 + uVar16 * 0x28 + 0x114) = (short)uVar16;
      pbVar12 = param_1 + uVar16 * 0x28 + 0x118;
      pbVar12[0] = 0;
      pbVar12[1] = 0;
      pbVar12[2] = 0;
      pbVar12[3] = 0;
      pbVar12[4] = 1;
      pbVar12[5] = 0xb;
      pbVar12[6] = 0;
      pbVar12[7] = 0;
      *(short *)(param_1 + uVar16 * 0x28 + 0x112) = (short)uVar16;
      FUN_71005fbee0((undefined8 *)(param_1 + uVar16 * 0x10 + 0x200));
      uVar17 = (ulong)((int)uVar16 + 1);
      pbVar12 = param_1 + uVar16 * 0x10 + 0x200;
      pbVar12[0] = 4;
      pbVar12[1] = 0;
      pbVar12[2] = 0;
      pbVar12[3] = 0;
    }
    if (uVar2 == 6) {
      FUN_71005fbecc(param_1 + uVar17 * 0x28 + 0x110);
      *(short *)(param_1 + uVar17 * 0x28 + 0x114) = (short)uVar17;
      pbVar12 = param_1 + uVar17 * 0x28 + 0x118;
      pbVar12[0] = 0;
      pbVar12[1] = 0;
      pbVar12[2] = 0;
      pbVar12[3] = 0;
      pbVar12[4] = 3;
      pbVar12[5] = 2;
      pbVar12[6] = 0;
      pbVar12[7] = 0;
      *(short *)(param_1 + uVar17 * 0x28 + 0x112) = (short)uVar17;
      FUN_71005fbee0((undefined8 *)(param_1 + uVar17 * 0x10 + 0x200));
      pbVar12 = param_1 + uVar17 * 0x10 + 0x200;
      pbVar12[0] = 1;
      pbVar12[1] = 0;
      pbVar12[2] = 0;
      pbVar12[3] = 0;
    }
  }
  else {
    *(byte **)(param_1 + 0x270) = param_1 + 0x200;
    bVar10 = uVar2 - 7 < 0xfffffffe;
    uVar16 = 1;
    param_1[0x262] = 1;
    param_1[0x263] = 0;
    uVar4 = *(undefined4 *)(&DAT_71032a8ccc + uVar14 * 0x10);
    iVar15 = 8;
    iVar13 = 8;
    iVar9 = iVar13;
    if (bVar10) {
      iVar9 = 4;
    }
    uVar14 = uVar14 - 7;
    *(byte **)(param_1 + 0x268) = param_1 + 0x110;
    *(short *)(param_1 + 0x260) = (short)uVar4;
    iVar1 = 0;
    if ((uVar2 & 0xfffffffd) != 0) {
      iVar1 = iVar9;
    }
    if (0xfffffffffffffffa < uVar14) {
      iVar13 = 0xc;
    }
    uVar3 = iVar13 + iVar1;
    if (0xfffffffffffffffc < uVar14) {
      uVar3 = iVar13 + iVar1 + 4;
    }
    FUN_71005fbee0((undefined8 *)(param_1 + 0x200));
    *(uint *)(param_1 + 0x200) = uVar3 | uVar2 == 6;
    FUN_71005fbecc(param_1 + 0x110);
    param_1[0x112] = 0;
    param_1[0x113] = 0;
    param_1[0x114] = 0;
    param_1[0x115] = 0;
    param_1[0x118] = 0;
    param_1[0x119] = 0;
    param_1[0x11a] = 0;
    param_1[0x11b] = 0;
    param_1[0x11c] = 5;
    param_1[0x11d] = 0x15;
    param_1[0x11e] = 0;
    param_1[0x11f] = 0;
    if (0xfffffffffffffffa < uVar14) {
      FUN_71005fbecc(param_1 + 0x138);
      param_1[0x13a] = 1;
      param_1[0x13b] = 0;
      param_1[0x13c] = 0;
      param_1[0x13d] = 0;
      uVar16 = 2;
      param_1[0x140] = 8;
      param_1[0x141] = 0;
      param_1[0x142] = 0;
      param_1[0x143] = 0;
      param_1[0x144] = 2;
      param_1[0x145] = 0xe;
      param_1[0x146] = 0;
      param_1[0x147] = 0;
      iVar15 = 0xc;
    }
    iVar13 = iVar15;
    if ((uVar2 & 0xfffffffd) != 0) {
      FUN_71005fbecc(param_1 + uVar16 * 0x28 + 0x110);
      iVar13 = iVar15 + 4;
      (param_1 + uVar16 * 0x28 + 0x114)[0] = 0;
      (param_1 + uVar16 * 0x28 + 0x114)[1] = 0;
      uVar3 = (int)uVar16 + 1;
      pbVar12 = param_1 + uVar16 * 0x28 + 0x11c;
      pbVar12[0] = 5;
      pbVar12[1] = 0x12;
      pbVar12[2] = 0;
      pbVar12[3] = 0;
      *(int *)(param_1 + uVar16 * 0x28 + 0x118) = iVar15;
      *(short *)(param_1 + uVar16 * 0x28 + 0x112) = (short)uVar16;
      if (bVar10 || (uVar2 & 0xfffffffd) == 0) {
        uVar16 = (ulong)uVar3;
      }
      else {
        FUN_71005fbecc(param_1 + (ulong)uVar3 * 0x28 + 0x110);
        (param_1 + (ulong)uVar3 * 0x28 + 0x114)[0] = 0;
        (param_1 + (ulong)uVar3 * 0x28 + 0x114)[1] = 0;
        uVar16 = (ulong)((int)uVar16 + 2);
        pbVar12 = param_1 + (ulong)uVar3 * 0x28 + 0x11c;
        pbVar12[0] = 2;
        pbVar12[1] = 0xb;
        pbVar12[2] = 0;
        pbVar12[3] = 0;
        *(int *)(param_1 + (ulong)uVar3 * 0x28 + 0x118) = iVar13;
        *(short *)(param_1 + (ulong)uVar3 * 0x28 + 0x112) = (short)uVar3;
        iVar13 = iVar15 + 8;
      }
    }
    uVar17 = uVar16;
    if (0xfffffffffffffffc < uVar14) {
      FUN_71005fbecc(param_1 + uVar16 * 0x28 + 0x110);
      *(int *)(param_1 + uVar16 * 0x28 + 0x118) = iVar13;
      iVar13 = iVar13 + 4;
      *(short *)(param_1 + uVar16 * 0x28 + 0x112) = (short)uVar16;
      uVar17 = (ulong)((int)uVar16 + 1);
      (param_1 + uVar16 * 0x28 + 0x114)[0] = 0;
      (param_1 + uVar16 * 0x28 + 0x114)[1] = 0;
      pbVar12 = param_1 + uVar16 * 0x28 + 0x11c;
      pbVar12[0] = 1;
      pbVar12[1] = 0xb;
      pbVar12[2] = 0;
      pbVar12[3] = 0;
    }
    if (uVar2 == 6) {
      FUN_71005fbecc(param_1 + uVar17 * 0x28 + 0x110);
      (param_1 + uVar17 * 0x28 + 0x114)[0] = 0;
      (param_1 + uVar17 * 0x28 + 0x114)[1] = 0;
      *(int *)(param_1 + uVar17 * 0x28 + 0x118) = iVar13;
      pbVar12 = param_1 + uVar17 * 0x28 + 0x11c;
      pbVar12[0] = 3;
      pbVar12[1] = 2;
      pbVar12[2] = 0;
      pbVar12[3] = 0;
      *(short *)(param_1 + uVar17 * 0x28 + 0x112) = (short)uVar17;
    }
  }
  FUN_71005fbd1c((undefined8 *)(param_1 + 0x290));
  *(byte **)(param_1 + 0x2b0) = param_1 + 0x260;
  *(byte **)(param_1 + 0x298) = param_1 + 0x20;
  *(byte **)(param_1 + 0x2a0) = param_1 + 0x50;
  *(byte **)(param_1 + 0x290) = param_1 + 0x90;
  *(byte **)(param_1 + 0x2a8) = param_1 + 0xf0;
  *(undefined8 *)(param_1 + 0x2b8) =
       *(undefined8 *)
        (*(long *)(*(long *)(*param_2 + 0x20) + (long)(int)param_3[7] * 0x40 +
                  *(long *)(DAT_7103a64d30 + (ulong)*(uint *)(param_2 + 1) * 8)) + 0x68);
  return;
}



void FUN_7100ba8570(undefined8 *param_1)

{
  FUN_710060420c(param_1);
  FUN_710060438c(param_1 + 0x1b);
  param_1[0x24] = 0xffffffffffffffff;
  return;
}



void FUN_7100ba85a0(void)

{
  ret_71006043A4();
  ret_7100604248();
  return;
}



void FUN_7100ba85c8(undefined1 *param_1,undefined8 *param_2,byte *param_3,undefined8 *param_4)

{
  byte local_70 [4];
  undefined4 uStack_6c;
  undefined8 uStack_68;
  undefined8 local_60;
  undefined8 uStack_58;
  undefined8 local_50;
  undefined8 uStack_48;
  undefined1 *local_40;
  undefined8 uStack_38;
  
  FUN_7100ba75e0(param_1,param_4,param_2,param_3);
  local_40 = (undefined1 *)0x0;
  uStack_38 = 0;
  local_50 = 0;
  uStack_48 = 0;
  local_60 = 0;
  uStack_58 = 0;
  _local_70 = 0;
  uStack_68 = 0;
  FUN_71005fbf54((undefined2 *)local_70);
  _local_70 = CONCAT71(stack0xffffffffffffff91,1);
  _local_70 = CONCAT44(*(undefined4 *)(param_3 + 0xc),local_70);
  uStack_68 = CONCAT44(uStack_68._4_4_,0x5040302);
  local_60 = (ulong)CONCAT42(local_60._4_4_,*(undefined2 *)(param_3 + 6)) << 0x10;
  local_40 = param_1;
  FUN_71006043a8(param_1 + 0xd8,param_2,local_70);
  return;
}
