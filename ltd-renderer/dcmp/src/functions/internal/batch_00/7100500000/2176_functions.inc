


int FUN_71005c5d10(uint param_1,char *param_2,long param_3,int *param_4,int param_5,uint param_6,
                  uint param_7,undefined8 *param_8,undefined8 *param_9,undefined4 param_10,
                  int param_11,undefined4 param_12,undefined4 param_13,uint param_14,uint param_15)

{
  int iVar1;
  
  if (param_1 < 3) {
    iVar1 = FUN_71005c51d0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                           param_10,param_11,param_12,param_13,param_14,param_15);
    return iVar1;
  }
  return -1;
}



void FUN_71005c5d60(char *param_1,undefined1 *param_2,int *param_3,int param_4)

{
  FUN_71005c58a0(param_1,param_2,param_3,param_4,0,0);
  return;
}



undefined8 FUN_71005c663c(long param_1)

{
  if ((ulong)*(byte *)(param_1 + 0x20) == 8) {
    return 0;
  }
  return *(undefined8 *)
          (*(long *)(*(long *)(param_1 + 8) + 0x40) + (ulong)*(byte *)(param_1 + 0x20) * 8 + 0x10);
}



void FUN_71005c6664(long param_1)

{
  FUN_71005c95d4(*(long **)(param_1 + 8));
  return;
}



bool FUN_71005c6680(long *param_1)

{
  char cVar1;
  long lVar2;
  long lVar3;
  long lVar4;
  long lVar5;
  long local_40;
  undefined8 uStack_38;
  
  lVar4 = *(long *)(param_1[1] + 0x40);
  if ((ulong)*(byte *)(param_1 + 4) == 8) {
    lVar2 = 0;
    lVar5 = *(long *)(lVar4 + 0x498);
  }
  else {
    lVar2 = *(long *)(lVar4 + (ulong)*(byte *)(param_1 + 4) * 8 + 0x10);
    lVar5 = *(long *)(lVar4 + 0x498);
  }
  if (lVar5 != 0) {
    cVar1 = *(char *)(lVar2 + 0x80);
    uStack_38 = *(undefined8 *)(*(long *)(lVar4 + 0x70) + 400);
    local_40 = *(long *)(*(long *)(lVar4 + 0x70) + 0x188) + (ulong)*(uint *)(lVar4 + 0x4f8);
    lVar3 = *param_1;
    if (*(char *)(lVar2 + 0x3e) != -1) {
      FUN_71005fd4d4(lVar3,(int)*(char *)(lVar2 + 0x3e),0,&local_40,(ulong)*(uint *)(lVar4 + 0x500))
      ;
    }
    if (cVar1 != -1) {
      FUN_71005fd4d4(lVar3,(int)cVar1,4,&local_40,(ulong)*(uint *)(lVar4 + 0x500));
    }
  }
  return lVar5 != 0;
}



byte FUN_71005c6740(long *param_1,long *param_2,long param_3)

{
  byte bVar1;
  uint uVar2;
  long lVar3;
  long lVar4;
  
  if (*(char *)((long)param_2 + 0xe6) != '\0') {
    bVar1 = *(char *)((long)param_2 + 0xe6) - 1;
    param_1[1] = param_3 + (ulong)bVar1 * 0x70 + 0x1e78;
    param_1[8] = *(long *)(param_3 + (ulong)bVar1 * 8 + 0x21f8);
  }
  if (*(int *)(*param_2 + 0xec0) == 0) {
    bVar1 = 0;
    if (*(char *)(param_3 + 0xf70) != '\0') {
      uVar2 = 0x20;
      goto LAB_71005c67a8;
    }
  }
  else {
    uVar2 = *(int *)(*param_2 + 0xec0) + 0x20U & 0xff;
    if (*(char *)(param_3 + (ulong)uVar2 * 0x78 + 0x70) == '\0') {
      bVar1 = 1;
    }
    else {
LAB_71005c67a8:
      bVar1 = 0;
      param_1[3] = param_3 + (ulong)uVar2 * 0x78;
    }
  }
  if (0 < *(int *)(*param_2 + 0xf98)) {
    if (param_2[0x94] != 0) {
      uVar2 = *(int *)(*param_2 + 0xf98) - 1U & 0xff;
      if (*(char *)(param_3 + (ulong)uVar2 * 0x78 + 0x70) == '\0') {
        bVar1 = bVar1 | 2;
        lVar3 = param_2[0x84];
      }
      else {
        param_1[2] = param_3 + (ulong)uVar2 * 0x78;
        lVar3 = param_2[0x84];
      }
      goto joined_r0x0071005c6868;
    }
    bVar1 = bVar1 | 4;
  }
  lVar3 = param_2[0x84];
joined_r0x0071005c6868:
  if (lVar3 != 0) {
    *param_1 = param_3 + 0x2238;
  }
  param_1[4] = param_3 + 0x22a8;
  lVar3 = *(long *)(param_3 + 0x2310);
  param_1[10] = lVar3;
  lVar4 = *(long *)(param_3 + 0x2308);
  param_1[9] = lVar4;
  if (lVar3 == 0 && lVar4 == 0) {
    param_1[10] = (long)&LAB_71005e0b58;
  }
  param_1[0xb] = *(long *)(param_3 + 0x2318);
  param_1[0xc] = *(long *)(param_3 + 0x2320);
  return bVar1;
}



void FUN_71005c6870(long *param_1,undefined8 param_2)

{
  code *UNRECOVERED_JUMPTABLE;
  
  if ((*param_1 != 0) &&
     (UNRECOVERED_JUMPTABLE = *(code **)(*param_1 + 0x10), UNRECOVERED_JUMPTABLE != (code *)0x0)) {
    (*UNRECOVERED_JUMPTABLE)(param_2);
  }
  if ((param_1[1] != 0) &&
     (UNRECOVERED_JUMPTABLE = *(code **)(param_1[1] + 0x10), UNRECOVERED_JUMPTABLE != (code *)0x0))
  {
    (*UNRECOVERED_JUMPTABLE)(param_2);
  }
  if ((param_1[2] != 0) &&
     (UNRECOVERED_JUMPTABLE = *(code **)(param_1[2] + 0x10), UNRECOVERED_JUMPTABLE != (code *)0x0))
  {
    (*UNRECOVERED_JUMPTABLE)(param_2);
  }
  if ((param_1[3] != 0) &&
     (UNRECOVERED_JUMPTABLE = *(code **)(param_1[3] + 0x10), UNRECOVERED_JUMPTABLE != (code *)0x0))
  {
                    // WARNING: Could not recover jumptable at 0x0071005c68e8. Too many branches
                    // WARNING: Treating indirect jump as call
    (*UNRECOVERED_JUMPTABLE)(param_2);
    return;
  }
  return;
}



void FUN_71005c68f8(long *param_1,undefined8 param_2)

{
  code *UNRECOVERED_JUMPTABLE;
  
  if ((*param_1 != 0) &&
     (UNRECOVERED_JUMPTABLE = *(code **)(*param_1 + 0x18), UNRECOVERED_JUMPTABLE != (code *)0x0)) {
    (*UNRECOVERED_JUMPTABLE)(param_2);
  }
  if ((param_1[1] != 0) &&
     (UNRECOVERED_JUMPTABLE = *(code **)(param_1[1] + 0x18), UNRECOVERED_JUMPTABLE != (code *)0x0))
  {
    (*UNRECOVERED_JUMPTABLE)(param_2);
  }
  if ((param_1[2] != 0) &&
     (UNRECOVERED_JUMPTABLE = *(code **)(param_1[2] + 0x18), UNRECOVERED_JUMPTABLE != (code *)0x0))
  {
    (*UNRECOVERED_JUMPTABLE)(param_2);
  }
  if ((param_1[3] != 0) &&
     (UNRECOVERED_JUMPTABLE = *(code **)(param_1[3] + 0x18), UNRECOVERED_JUMPTABLE != (code *)0x0))
  {
                    // WARNING: Could not recover jumptable at 0x0071005c6970. Too many branches
                    // WARNING: Treating indirect jump as call
    (*UNRECOVERED_JUMPTABLE)(param_2);
    return;
  }
  return;
}



void FUN_71005c6980(long *param_1,long param_2)

{
  code *UNRECOVERED_JUMPTABLE;
  
  if ((*param_1 != 0) &&
     (UNRECOVERED_JUMPTABLE = *(code **)(*param_1 + 0x20), UNRECOVERED_JUMPTABLE != (code *)0x0)) {
    (*UNRECOVERED_JUMPTABLE)(param_2);
  }
  *(long *)(param_2 + 8) = param_1[8];
  if ((param_1[1] != 0) &&
     (UNRECOVERED_JUMPTABLE = *(code **)(param_1[1] + 0x20), UNRECOVERED_JUMPTABLE != (code *)0x0))
  {
    (*UNRECOVERED_JUMPTABLE)(param_2);
  }
  if ((param_1[2] != 0) &&
     (UNRECOVERED_JUMPTABLE = *(code **)(param_1[2] + 0x20), UNRECOVERED_JUMPTABLE != (code *)0x0))
  {
    (*UNRECOVERED_JUMPTABLE)(param_2);
  }
  if ((param_1[3] != 0) &&
     (UNRECOVERED_JUMPTABLE = *(code **)(param_1[3] + 0x20), UNRECOVERED_JUMPTABLE != (code *)0x0))
  {
                    // WARNING: Could not recover jumptable at 0x0071005c6a00. Too many branches
                    // WARNING: Treating indirect jump as call
    (*UNRECOVERED_JUMPTABLE)(param_2);
    return;
  }
  return;
}



void FUN_71005c6a10(long *param_1,long param_2)

{
  code *UNRECOVERED_JUMPTABLE;
  
  if ((*param_1 != 0) &&
     (UNRECOVERED_JUMPTABLE = *(code **)(*param_1 + 0x28), UNRECOVERED_JUMPTABLE != (code *)0x0)) {
    (*UNRECOVERED_JUMPTABLE)(param_2);
  }
  *(long *)(param_2 + 8) = param_1[8];
  if ((param_1[1] != 0) &&
     (UNRECOVERED_JUMPTABLE = *(code **)(param_1[1] + 0x28), UNRECOVERED_JUMPTABLE != (code *)0x0))
  {
    (*UNRECOVERED_JUMPTABLE)(param_2);
  }
  if ((param_1[2] != 0) &&
     (UNRECOVERED_JUMPTABLE = *(code **)(param_1[2] + 0x28), UNRECOVERED_JUMPTABLE != (code *)0x0))
  {
    (*UNRECOVERED_JUMPTABLE)(param_2);
  }
  if ((param_1[3] != 0) &&
     (UNRECOVERED_JUMPTABLE = *(code **)(param_1[3] + 0x28), UNRECOVERED_JUMPTABLE != (code *)0x0))
  {
                    // WARNING: Could not recover jumptable at 0x0071005c6a90. Too many branches
                    // WARNING: Treating indirect jump as call
    (*UNRECOVERED_JUMPTABLE)(param_2);
    return;
  }
  return;
}



undefined8 FUN_71005c6aa0(long *param_1,long param_2)

{
  ulong uVar1;
  code *pcVar2;
  
  if (((*param_1 != 0) && (pcVar2 = *(code **)(*param_1 + 0x30), pcVar2 != (code *)0x0)) &&
     (uVar1 = (*pcVar2)(param_2), (uVar1 & 1) != 0)) {
    return 1;
  }
  *(long *)(param_2 + 0x20) = param_1[8];
  if (((param_1[1] != 0) && (pcVar2 = *(code **)(param_1[1] + 0x30), pcVar2 != (code *)0x0)) &&
     (uVar1 = (*pcVar2)(param_2), (uVar1 & 1) != 0)) {
    return 1;
  }
  if (((param_1[2] != 0) && (pcVar2 = *(code **)(param_1[2] + 0x30), pcVar2 != (code *)0x0)) &&
     (uVar1 = (*pcVar2)(param_2), (uVar1 & 1) != 0)) {
    return 1;
  }
  if (((param_1[3] != 0) && (pcVar2 = *(code **)(param_1[3] + 0x30), pcVar2 != (code *)0x0)) &&
     (uVar1 = (*pcVar2)(param_2), (uVar1 & 1) != 0)) {
    return 1;
  }
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint FUN_71005c6b7c(long *param_1,long *param_2)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  long lVar4;
  undefined1 uVar5;
  char cVar6;
  uint uVar7;
  uint uVar8;
  byte bVar9;
  byte bVar10;
  uint uVar11;
  undefined8 *puVar12;
  uint *puVar13;
  ulong uVar14;
  long *plVar15;
  long lVar16;
  long *plVar17;
  long lVar18;
  code *pcVar19;
  undefined4 uVar20;
  float fVar21;
  undefined1 auVar22 [16];
  long *local_50;
  long local_48;
  
  plVar17 = param_1 + 0xda;
  *param_1 = param_2[2];
  plVar15 = (long *)*param_2;
  param_1[0x6e] = *plVar15;
  lVar16 = plVar15[1];
  lVar4 = plVar15[2];
  lVar18 = plVar15[3];
  param_1[0x72] = plVar15[4];
  param_1[0x71] = lVar18;
  param_1[0x70] = lVar4;
  param_1[0x6f] = lVar16;
  lVar16 = plVar15[5];
  lVar4 = plVar15[6];
  lVar18 = plVar15[7];
  param_1[0x76] = plVar15[8];
  param_1[0x75] = lVar18;
  param_1[0x74] = lVar4;
  param_1[0x73] = lVar16;
  lVar16 = plVar15[9];
  lVar4 = plVar15[10];
  lVar18 = plVar15[0xb];
  param_1[0x7a] = plVar15[0xc];
  param_1[0x79] = lVar18;
  param_1[0x78] = lVar4;
  param_1[0x77] = lVar16;
  bVar9 = *(byte *)(param_1 + 0xe2);
  param_1[8] = param_2[3];
  param_1[9] = *(long *)param_2[3];
  *(int *)((long)param_1 + 0xf4) = (int)param_2[7];
  auVar22 = _DAT_7102ebfbf0;
  lVar16 = param_2[6];
  *(undefined4 *)(param_1 + 0xe) = 1;
  param_1[0xdf] = 0;
  param_1[0xe0] = 0;
  param_1[6] = 0x1000;
  param_1[0x95] = lVar16;
  lVar18 = auVar22._8_8_;
  param_1[0x21] = lVar18;
  lVar16 = auVar22._0_8_;
  param_1[0x20] = lVar16;
  param_1[0x23] = 0;
  param_1[0x22] = 0x3f80000000000000;
  param_1[0x25] = 0x3f800000;
  param_1[0x24] = 0;
  param_1[0x27] = 0;
  param_1[0x26] = 0;
  param_1[0x29] = lVar18;
  param_1[0x28] = lVar16;
  param_1[0x2b] = 0;
  param_1[0x2a] = 0x3f80000000000000;
  param_1[0x2d] = 0x3f800000;
  param_1[0x2c] = 0;
  param_1[0x2f] = 0;
  param_1[0x2e] = 0;
  param_1[0xde] = param_2[4];
  thunk_EXT_FUN_02e95df0(plVar17);
  lVar16 = (**(code **)(*(long *)param_1[0xde] + 0x10))
                     ((long *)param_1[0xde],(ulong)bVar9 * 0x60,0x80);
  if (lVar16 == 0) {
LAB_71005c70a0:
    thunk_EXT_FUN_02e95df0(plVar17);
  }
  else {
    param_1[0xdf] = param_1[0xdf] + (ulong)bVar9 * 0x60;
    param_1[0xe0] = param_1[0xe0] + 1;
    thunk_EXT_FUN_02e95df0(plVar17);
    param_1[0x60] = lVar16;
    *(uint *)(param_1 + 0x61) = (uint)*(byte *)(param_1 + 0xe2);
    lVar16 = param_2[3];
    if (*(long *)(lVar16 + 0x350) != 0) {
      thunk_EXT_FUN_02e95df0(plVar17);
      lVar16 = (**(code **)(*(long *)param_1[0xde] + 0x10))((long *)param_1[0xde],0x188,0x80);
      if (lVar16 == 0) goto LAB_71005c70a0;
      param_1[0xdf] = param_1[0xdf] + 0x188;
      param_1[0xe0] = param_1[0xe0] + 1;
      thunk_EXT_FUN_02e95df0(plVar17);
      thunk_EXT_FUN_02e95df0(lVar16,0,0x188);
      param_1[10] = lVar16;
      lVar16 = param_2[3];
    }
    if (*(char *)(lVar16 + 0xef) == '\0') {
LAB_71005c6de0:
      uVar20 = 0;
      if ((*(char *)(param_1[9] + 0xcc9) == '\0') &&
         (uVar20 = 0x3f800000, *(char *)(param_1[9] + 0xcca) != '\0')) {
        uVar20 = 0;
      }
      *(undefined4 *)((long)param_1 + 0x7c) = uVar20;
      *(undefined4 *)(param_1 + 0xf) = 0x3f800000;
      if (*(long *)(param_2[3] + 0x350) != 0) {
        *(long *)param_1[10] = *(long *)(param_2[3] + 0x350);
        *(undefined8 *)(param_1[10] + 8) = *(undefined8 *)(param_2[3] + 0x358);
        *(undefined8 *)(param_1[10] + 0x10) = *(undefined8 *)(param_2[3] + 0x360);
        *(undefined8 *)(param_1[10] + 0x18) = *(undefined8 *)(param_2[3] + 0x368);
        *(undefined8 *)(param_1[10] + 0x20) = *(undefined8 *)(param_2[3] + 0x370);
        *(undefined8 *)(param_1[10] + 0x28) = *(undefined8 *)(param_2[3] + 0x378);
        *(undefined8 *)(param_1[10] + 0x30) = *(undefined8 *)(param_2[3] + 0x380);
        *(undefined8 *)(param_1[10] + 0x38) = *(undefined8 *)(param_2[3] + 0x388);
        *(undefined8 *)(param_1[10] + 0x40) = *(undefined8 *)(param_2[3] + 0x390);
        *(undefined8 *)(param_1[10] + 0x48) = *(undefined8 *)(param_2[3] + 0x398);
        *(undefined8 *)(param_1[10] + 0x50) = *(undefined8 *)(param_2[3] + 0x3a0);
        *(undefined8 *)(param_1[10] + 0x58) = *(undefined8 *)(param_2[3] + 0x3a8);
        *(undefined8 *)(param_1[10] + 0x60) = *(undefined8 *)(param_2[3] + 0x3b0);
        *(undefined8 *)(param_1[10] + 0x68) = *(undefined8 *)(param_2[3] + 0x3b8);
        *(undefined8 *)(param_1[10] + 0x70) = *(undefined8 *)(param_2[3] + 0x3c0);
        *(undefined8 *)(param_1[10] + 0x78) = *(undefined8 *)(param_2[3] + 0x3c8);
      }
      *(undefined4 *)((long)param_1 + 0xe4) = 0x3f800000;
      *(undefined8 *)((long)param_1 + 0xdc) = 0x3f8000003f800000;
      uVar11 = *(uint *)(param_1 + 6);
      uVar5 = *(undefined1 *)(*param_1 + 0x65);
      *(undefined1 *)(param_1 + 0x10) = 0;
      *(undefined1 *)((long)param_1 + 0x82) = uVar5;
      bVar9 = *(byte *)(param_2[3] + 0xef);
      *(undefined4 *)((long)param_1 + 0x3c) = 0xffffffff;
      uVar7 = uVar11 & 0xfffffffe | (uint)bVar9;
      *(uint *)(param_1 + 6) = uVar7 | 0x10c;
      uVar11 = uVar11 & 0xfff7fffe | (uint)bVar9 | 0x10c;
      if (*(char *)(*(long *)param_2[3] + 0xe18) != '\0') {
        uVar11 = uVar7 | 0x8010c;
      }
      *(uint *)(param_1 + 6) = uVar11;
      uVar1 = (uint)(*(char *)(*(long *)param_2[3] + 0xd68) != '\0') << 0x14;
      uVar7 = uVar11 & 0xfffff | uVar1;
      *(uint *)(param_1 + 6) = uVar11 & 0xffe00000 | uVar7;
      uVar2 = (uint)(*(char *)(*(long *)param_2[3] + 0xd6a) != '\0') << 0x15;
      uVar8 = uVar11 & 0xffc00000;
      *(uint *)(param_1 + 6) = uVar8 | uVar7 | uVar2;
      uVar3 = uVar11 & 0x1fff | (uint)(*(char *)(*(long *)param_2[3] + 0xcc0) != '\0') << 0xd;
      *(uint *)(param_1 + 6) = uVar8 | uVar11 & 0xfc000 | uVar1 | uVar2 | uVar3;
      uVar3 = uVar3 | (uint)(*(char *)(*(long *)param_2[3] + 0xcc2) == '\0') << 0xe;
      *(uint *)(param_1 + 6) = uVar8 | uVar11 & 0xf8000 | uVar1 | uVar2 | uVar3;
      uVar3 = uVar3 | (uint)(*(char *)(*(long *)param_2[3] + 0xcc2) == '\x01') << 0xf;
      *(uint *)(param_1 + 6) = uVar8 | uVar11 & 0xf0000 | uVar1 | uVar2 | uVar3;
      uVar3 = uVar3 | (uint)(*(char *)(*(long *)param_2[3] + 0xcc2) == '\x02') << 0x10;
      *(uint *)(param_1 + 6) = uVar8 | uVar11 & 0xe0000 | uVar1 | uVar2 | uVar3;
      uVar7 = (uint)*(byte *)(param_2[3] + 0xe7) << 0x12;
      *(uint *)(param_1 + 6) = uVar8 | uVar11 & 0xa0000 | uVar1 | uVar2 | uVar3 | uVar7;
      *(uint *)(param_1 + 6) =
           uVar8 | uVar11 & 0x80000 | uVar1 | uVar2 | uVar7 |
           uVar3 | (uint)(*(char *)(*(long *)param_2[3] + 0xd5c) != '\0') << 0x11;
      puVar13 = (uint *)FUN_71005e46b0();
      cVar6 = *(char *)(param_1[9] + 0xcc4);
      if (cVar6 == '\x02') {
        uVar11 = *(int *)(param_1[9] + 0xcd0) * -0x2023e3cb;
LAB_71005c70d0:
        FUN_71005e4740((undefined2 *)(param_1 + 0x94),uVar11);
      }
      else {
        if (cVar6 == '\x01') {
          uVar11 = *(uint *)(*param_1 + 0x264);
          goto LAB_71005c70d0;
        }
        if (cVar6 == '\0') {
          uVar7 = puVar13[3];
          uVar11 = *puVar13 ^ *puVar13 << 0xb;
          *puVar13 = puVar13[1];
          puVar13[1] = puVar13[2];
          uVar11 = uVar11 >> 8 ^ uVar7 >> 0x13 ^ uVar11 ^ uVar7;
          puVar13[2] = uVar7;
          puVar13[3] = uVar11;
          goto LAB_71005c70d0;
        }
      }
      uVar11 = FUN_71005c7270((long)param_1,(undefined8 *)param_2[1],param_2[5]);
      if ((uVar11 & 1) != 0) {
        lVar18 = *param_1;
        fVar21 = (float)*(int *)(param_1[9] + 0xd80) + 1.0;
        *(float *)(param_1 + 0x1b) = fVar21;
        *(float *)(param_1 + 0x1a) = fVar21;
        lVar16 = *(long *)(lVar18 + 0x130);
        param_1[0x91] = *(long *)(lVar18 + 0x138);
        param_1[0x90] = lVar16;
        param_1[0x93] = 0;
        param_1[0x92] = 0;
        auVar22 = NEON_fmov(0x3f800000,4);
        *(undefined4 *)(param_1 + 0x1e) = *(undefined4 *)(lVar18 + 0x234);
        param_1[0x17] = auVar22._8_8_;
        param_1[0x16] = auVar22._0_8_;
        param_1[0x19] = auVar22._8_8_;
        param_1[0x18] = auVar22._0_8_;
        local_50 = param_1;
        if ((param_1[0x6e] == 0) ||
           (pcVar19 = *(code **)(param_1[0x6e] + 8), pcVar19 == (code *)0x0)) {
          bVar9 = 1;
          bVar10 = 1;
          local_48 = param_1[0x76];
          lVar16 = param_1[0x6f];
          if (lVar16 != 0) goto LAB_71005c717c;
LAB_71005c7158:
          lVar16 = param_1[0x70];
        }
        else {
          bVar9 = (*pcVar19)(&local_50);
          local_48 = param_1[0x76];
          lVar16 = param_1[0x6f];
          bVar10 = bVar9;
          if (lVar16 == 0) goto LAB_71005c7158;
LAB_71005c717c:
          pcVar19 = *(code **)(lVar16 + 8);
          bVar9 = bVar10 & pcVar19 == (code *)0x0;
          if ((pcVar19 != (code *)0x0) && (((bVar10 ^ 1) & 1) == 0)) {
            bVar9 = (*pcVar19)(&local_50);
          }
          lVar16 = param_1[0x70];
        }
        bVar10 = bVar9;
        if (lVar16 != 0) {
          pcVar19 = *(code **)(lVar16 + 8);
          bVar10 = bVar9 & pcVar19 == (code *)0x0;
          if ((pcVar19 != (code *)0x0) && (((bVar9 ^ 1) & 1) == 0)) {
            bVar10 = (*pcVar19)(&local_50);
          }
        }
        bVar9 = bVar10;
        if (param_1[0x71] == 0) {
LAB_71005c720c:
          if ((bVar9 & 1) != 0) {
LAB_71005c7210:
            uVar11 = FUN_71005c8030((long)param_1);
            goto LAB_71005c7250;
          }
        }
        else {
          pcVar19 = *(code **)(param_1[0x71] + 8);
          bVar9 = bVar10 & pcVar19 == (code *)0x0;
          if ((pcVar19 == (code *)0x0) || (((bVar10 ^ 1) & 1) != 0)) goto LAB_71005c720c;
          uVar14 = (*pcVar19)(&local_50);
          if ((uVar14 & 1) != 0) goto LAB_71005c7210;
        }
        uVar11 = 0;
        goto LAB_71005c7250;
      }
    }
    else {
      thunk_EXT_FUN_02e95df0(plVar17);
      puVar12 = (undefined8 *)
                (**(code **)(*(long *)param_1[0xde] + 0x10))((long *)param_1[0xde],0xa0,0x80);
      if (puVar12 == (undefined8 *)0x0) goto LAB_71005c70a0;
      param_1[0xdf] = param_1[0xdf] + 0xa0;
      param_1[0xe0] = param_1[0xe0] + 1;
      thunk_EXT_FUN_02e95df0(plVar17);
      puVar12[0x12] = 0;
      puVar12[0x13] = 0;
      puVar12[0x10] = 0;
      puVar12[0x11] = 0;
      *(undefined4 *)((long)puVar12 + 0x84) = 0xffffffff;
      *(undefined4 *)((long)puVar12 + 0x8c) = 0;
      puVar12[0xe] = 0;
      puVar12[0xf] = 0;
      *(undefined8 *)((long)puVar12 + 0x7c) = 0xffffffffffffffff;
      puVar12[0xc] = 0;
      puVar12[0xd] = 0;
      puVar12[10] = 0;
      puVar12[0xb] = 0;
      puVar12[8] = 0;
      puVar12[9] = 0;
      puVar12[6] = 0;
      puVar12[7] = 0;
      puVar12[4] = 0;
      puVar12[5] = 0;
      puVar12[2] = 0;
      puVar12[3] = 0;
      *puVar12 = 0;
      puVar12[1] = 0;
      param_1[0xb] = (long)puVar12;
      plVar17 = (long *)param_2[3];
      if ((((*(char *)((long)plVar17 + 0xef) == '\0') || (*(char *)(*plVar17 + 0xd5c) != '\0')) ||
          (plVar17[0x3f] == 0)) || ((*(byte *)((long)plVar17 + 0xe6) & 0xfe) != 2))
      goto LAB_71005c6de0;
      FUN_71005dee10();
    }
  }
  uVar11 = 0;
  *(uint *)(param_1 + 6) = *(uint *)(param_1 + 6) | 0x20;
LAB_71005c7250:
  return uVar11 & 1;
}



undefined4 FUN_71005c7270(long param_1,undefined8 *param_2,long param_3)

{
  long lVar1;
  ulong uVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  uint uVar6;
  undefined4 uVar7;
  char cVar8;
  bool bVar9;
  uint uVar10;
  uint uVar11;
  long lVar12;
  long lVar13;
  ulong uVar14;
  int *piVar15;
  undefined8 *puVar16;
  long lVar17;
  uint uVar18;
  long lVar19;
  undefined8 uVar20;
  long lVar21;
  ulong uVar22;
  undefined8 local_70;
  undefined8 uStack_68;
  
  uVar3 = *(uint *)(param_1 + 0x30);
  if (((uVar3 >> 0xe & 1) == 0) ||
     (((((*(long *)(*(long *)(param_1 + 0x40) + 0x420) == 0 || (*(long *)(param_1 + 0x370) == 0)) ||
        (*(long *)(*(long *)(param_1 + 0x370) + 0x50) == 0)) &&
       ((((*(int *)(*(long *)(param_1 + 0x48) + 0xf98) < 1 || (*(long *)(param_1 + 0x380) == 0)) ||
         (*(long *)(*(long *)(param_1 + 0x380) + 0x50) == 0)) &&
        (((*(int *)(*(long *)(param_1 + 0x48) + 0xec0) == 0 || (*(long *)(param_1 + 0x388) == 0)) ||
         (*(long *)(*(long *)(param_1 + 0x388) + 0x50) == 0)))))) &&
      (((*(char *)(*(long *)(param_1 + 0x40) + 0xe6) == '\0' || (*(long *)(param_1 + 0x378) == 0))
       || (*(long *)(*(long *)(param_1 + 0x378) + 0x50) == 0)))))) {
    uVar10 = *(uint *)(param_1 + 0xf4);
    *(uint *)(param_1 + 0x30) = uVar3 & 0xfffffdff;
    if (uVar10 != 0) goto LAB_71005c72b0;
LAB_71005c7354:
    uVar10 = FUN_71005c87b8(param_1,param_3);
    if (uVar10 == 0) {
      return 0;
    }
LAB_71005c7368:
    if (*(uint *)(param_1 + 0x98) == uVar10) goto LAB_71005c7db0;
  }
  else {
    uVar10 = *(uint *)(param_1 + 0xf4);
    *(uint *)(param_1 + 0x30) = uVar3 | 0x200;
    if (uVar10 == 0) goto LAB_71005c7354;
LAB_71005c72b0:
    lVar13 = *(long *)(param_1 + 0x48);
    if (*(int *)(lVar13 + 0xdec) != 0) goto LAB_71005c7368;
    if (*(char *)(lVar13 + 0xdb0) == '\r') {
      piVar15 = (int *)(lVar13 + 0xe00);
    }
    else {
      if (*(char *)(lVar13 + 0xdb0) != '\x02') goto LAB_71005c7368;
      piVar15 = (int *)(lVar13 + 0xdf8);
    }
    uVar10 = *piVar15 * uVar10;
    if (*(uint *)(param_1 + 0x98) == uVar10) goto LAB_71005c7db0;
  }
  FUN_71005c88f0(param_1);
  lVar13 = *(long *)(param_1 + 0x4b0);
  if (lVar13 != 0) {
    thunk_EXT_FUN_02e95df0(param_1 + 0x6d0);
    *(long *)(param_1 + 0x700) = *(long *)(param_1 + 0x700) + -1;
    (**(code **)(**(long **)(param_1 + 0x6f0) + 0x18))(*(long **)(param_1 + 0x6f0),lVar13);
    thunk_EXT_FUN_02e95df0(param_1 + 0x6d0);
    *(undefined8 *)(param_1 + 0x4b0) = 0;
  }
  if (*(long *)(param_1 + 0x4c0) != 0) {
    FUN_71005cefc0(*(long *)(param_1 + 0x658),*(long *)(param_1 + 0x4c0),0);
    *(undefined8 *)(param_1 + 0x4c0) = 0;
  }
  uVar4 = *(uint *)(param_1 + 0x30);
  cVar8 = *(char *)(param_1 + 0x710);
  uVar3 = uVar10;
  if ((uVar10 & 0x80000001) == 1) {
    uVar3 = uVar10 + 1;
  }
  local_70 = 0;
  uStack_68 = 0;
  if ((uVar4 & 0x10000) != 0) {
    uVar3 = uVar3 + 0x1f & 0xffffffe0;
  }
  FUN_71005fbcfc(&local_70);
  local_70 = CONCAT44(0x44,(undefined4)local_70);
  uVar11 = FUN_71005fbfe4(param_2,(long)&local_70);
  uVar22 = -(ulong)(uVar3 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar3 << 4;
  uVar14 = (uVar22 + uVar11) - 1 & -(ulong)uVar11;
  if ((uVar4 >> 0xe & 1) == 0) {
    lVar13 = 7;
    if ((*(byte *)(param_1 + 0x30) & 1) != 0) {
      lVar13 = 9;
    }
  }
  else {
    lVar13 = 0x13;
    if (cVar8 != '\x03') {
      lVar13 = 0xd;
    }
    lVar17 = 0x19;
    if (cVar8 != '\x03') {
      lVar17 = 0x11;
    }
    if ((*(byte *)(param_1 + 0x30) & 1) != 0) {
      lVar13 = lVar17;
    }
  }
  lVar17 = 0;
  if (*(char *)(*(long *)(param_1 + 0x48) + 0xcc3) != '\0') {
    lVar17 = uVar14 * 3;
  }
  uVar14 = lVar17 + uVar14 * lVar13;
  *(int *)(param_1 + 0x4cc) = (int)uVar14;
  uVar14 = FUN_71005cedd0(*(long *)(param_1 + 0x658),uVar14 & 0xffffffff,
                          *(long *)(*(long *)(param_1 + 0x658) + 0x1d8));
  *(ulong *)(param_1 + 0x4c0) = uVar14;
  if (uVar14 == 0) {
    return 0;
  }
  lVar13 = 0;
  iVar5 = *(int *)(*(long *)(param_1 + 0x658) + 0x1d8);
  uVar11 = ((int)((ulong)uVar3 << 4) + iVar5) - 1U & -iVar5;
  bVar9 = uVar11 <= *(uint *)(param_1 + 0x4cc);
  uVar18 = 0;
  if (bVar9) {
    uVar18 = uVar11;
  }
  *(uint *)(param_1 + 0x4c8) = uVar18;
  uVar2 = 0;
  if (bVar9) {
    uVar2 = uVar14;
  }
  **(ulong **)(param_1 + 0x300) = uVar2;
  uVar6 = *(uint *)(param_1 + 0x4c8);
  uVar18 = uVar6 + uVar11;
  if (uVar18 <= *(uint *)(param_1 + 0x4cc)) {
    *(uint *)(param_1 + 0x4c8) = uVar18;
    lVar13 = *(long *)(param_1 + 0x4c0) + (ulong)uVar6;
  }
  *(long *)(*(long *)(param_1 + 0x300) + 8) = lVar13;
  uVar6 = *(uint *)(param_1 + 0x4c8);
  uVar18 = uVar6 + uVar11;
  if (*(uint *)(param_1 + 0x4cc) < uVar18) {
    *(undefined8 *)(*(long *)(param_1 + 0x300) + 0x10) = 0;
    if ((uVar4 >> 0xe & 1) != 0) goto LAB_71005c7528;
LAB_71005c755c:
    if (1 < *(int *)(param_1 + 0x308)) {
      lVar17 = 0;
      lVar13 = 1;
      do {
        lVar13 = lVar13 + 1;
        *(undefined8 *)((long)*(undefined8 **)(param_1 + 0x300) + lVar17 + 0x60) =
             **(undefined8 **)(param_1 + 0x300);
        *(undefined8 *)(*(long *)(param_1 + 0x300) + lVar17 + 0x68) =
             *(undefined8 *)(*(long *)(param_1 + 0x300) + 8);
        lVar19 = *(long *)(param_1 + 0x300) + lVar17;
        lVar17 = lVar17 + 0x60;
        *(undefined8 *)(lVar19 + 0x70) = *(undefined8 *)(*(long *)(param_1 + 0x300) + 0x10);
      } while (lVar13 < *(int *)(param_1 + 0x308));
    }
LAB_71005c7640:
    uVar6 = *(uint *)(param_1 + 0x4c8);
    uVar18 = uVar6 + uVar11;
    if (uVar18 <= *(uint *)(param_1 + 0x4cc)) goto LAB_71005c771c;
LAB_71005c7654:
    lVar13 = 0;
  }
  else {
    *(uint *)(param_1 + 0x4c8) = uVar18;
    *(ulong *)(*(long *)(param_1 + 0x300) + 0x10) = *(long *)(param_1 + 0x4c0) + (ulong)uVar6;
    if ((uVar4 >> 0xe & 1) == 0) goto LAB_71005c755c;
LAB_71005c7528:
    uVar6 = *(uint *)(param_1 + 0x4c8);
    uVar18 = uVar6 + uVar11;
    if (*(uint *)(param_1 + 0x4cc) < uVar18) {
      lVar13 = 0;
    }
    else {
      *(uint *)(param_1 + 0x4c8) = uVar18;
      lVar13 = *(long *)(param_1 + 0x4c0) + (ulong)uVar6;
    }
    *(long *)(*(long *)(param_1 + 0x300) + 0x60) = lVar13;
    uVar6 = *(uint *)(param_1 + 0x4c8);
    uVar18 = uVar6 + uVar11;
    if (*(uint *)(param_1 + 0x4cc) < uVar18) {
      lVar13 = 0;
    }
    else {
      *(uint *)(param_1 + 0x4c8) = uVar18;
      lVar13 = *(long *)(param_1 + 0x4c0) + (ulong)uVar6;
    }
    *(long *)(*(long *)(param_1 + 0x300) + 0x68) = lVar13;
    uVar6 = *(uint *)(param_1 + 0x4c8);
    uVar18 = uVar6 + uVar11;
    if (*(uint *)(param_1 + 0x4cc) < uVar18) {
      *(undefined8 *)(*(long *)(param_1 + 0x300) + 0x70) = 0;
    }
    else {
      *(uint *)(param_1 + 0x4c8) = uVar18;
      *(ulong *)(*(long *)(param_1 + 0x300) + 0x70) = *(long *)(param_1 + 0x4c0) + (ulong)uVar6;
    }
    if (cVar8 != '\x03') goto LAB_71005c7640;
    uVar6 = *(uint *)(param_1 + 0x4c8);
    uVar18 = uVar6 + uVar11;
    if (*(uint *)(param_1 + 0x4cc) < uVar18) {
      lVar13 = 0;
    }
    else {
      *(uint *)(param_1 + 0x4c8) = uVar18;
      lVar13 = *(long *)(param_1 + 0x4c0) + (ulong)uVar6;
    }
    *(long *)(*(long *)(param_1 + 0x300) + 0xc0) = lVar13;
    uVar6 = *(uint *)(param_1 + 0x4c8);
    uVar18 = uVar6 + uVar11;
    if (*(uint *)(param_1 + 0x4cc) < uVar18) {
      lVar13 = 0;
    }
    else {
      *(uint *)(param_1 + 0x4c8) = uVar18;
      lVar13 = *(long *)(param_1 + 0x4c0) + (ulong)uVar6;
    }
    *(long *)(*(long *)(param_1 + 0x300) + 200) = lVar13;
    uVar6 = *(uint *)(param_1 + 0x4c8);
    uVar18 = uVar6 + uVar11;
    if (*(uint *)(param_1 + 0x4cc) < uVar18) {
      lVar13 = 0;
    }
    else {
      *(uint *)(param_1 + 0x4c8) = uVar18;
      lVar13 = *(long *)(param_1 + 0x4c0) + (ulong)uVar6;
    }
    *(long *)(*(long *)(param_1 + 0x300) + 0xd0) = lVar13;
    uVar6 = *(uint *)(param_1 + 0x4c8);
    uVar18 = uVar6 + uVar11;
    if (*(uint *)(param_1 + 0x4cc) < uVar18) goto LAB_71005c7654;
LAB_71005c771c:
    *(uint *)(param_1 + 0x4c8) = uVar18;
    lVar13 = *(long *)(param_1 + 0x4c0) + (ulong)uVar6;
  }
  *(long *)(*(long *)(param_1 + 0x300) + 0x18) = lVar13;
  uVar6 = *(uint *)(param_1 + 0x4c8);
  uVar18 = uVar6 + uVar11;
  if (*(uint *)(param_1 + 0x4cc) < uVar18) {
    lVar13 = 0;
  }
  else {
    *(uint *)(param_1 + 0x4c8) = uVar18;
    lVar13 = *(long *)(param_1 + 0x4c0) + (ulong)uVar6;
  }
  *(long *)(*(long *)(param_1 + 0x300) + 0x28) = lVar13;
  uVar6 = *(uint *)(param_1 + 0x4c8);
  uVar18 = uVar6 + uVar11;
  if (*(uint *)(param_1 + 0x4cc) < uVar18) {
    *(undefined8 *)(*(long *)(param_1 + 0x300) + 0x58) = 0;
    if ((uVar4 >> 0xe & 1) != 0) goto LAB_71005c7784;
LAB_71005c77b8:
    if (1 < *(int *)(param_1 + 0x308)) {
      lVar17 = 0;
      lVar13 = 1;
      do {
        lVar13 = lVar13 + 1;
        *(undefined8 *)(*(long *)(param_1 + 0x300) + lVar17 + 0x78) =
             *(undefined8 *)(*(long *)(param_1 + 0x300) + 0x18);
        *(undefined8 *)(*(long *)(param_1 + 0x300) + lVar17 + 0x88) =
             *(undefined8 *)(*(long *)(param_1 + 0x300) + 0x28);
        lVar19 = *(long *)(param_1 + 0x300) + lVar17;
        lVar17 = lVar17 + 0x60;
        *(undefined8 *)(lVar19 + 0xb8) = *(undefined8 *)(*(long *)(param_1 + 0x300) + 0x58);
      } while (lVar13 < *(int *)(param_1 + 0x308));
    }
LAB_71005c7884:
    uVar6 = *(uint *)(param_1 + 0x4c8);
    uVar18 = uVar6 + uVar11;
    if (uVar18 <= *(uint *)(param_1 + 0x4cc)) goto LAB_71005c7974;
LAB_71005c7898:
    *(undefined8 *)(*(long *)(param_1 + 0x300) + 0x20) = 0;
    iVar5 = *(int *)(param_1 + 0x308);
  }
  else {
    *(uint *)(param_1 + 0x4c8) = uVar18;
    *(ulong *)(*(long *)(param_1 + 0x300) + 0x58) = *(long *)(param_1 + 0x4c0) + (ulong)uVar6;
    if ((uVar4 >> 0xe & 1) == 0) goto LAB_71005c77b8;
LAB_71005c7784:
    uVar6 = *(uint *)(param_1 + 0x4c8);
    uVar18 = uVar6 + uVar11;
    if (*(uint *)(param_1 + 0x4cc) < uVar18) {
      lVar13 = 0;
    }
    else {
      *(uint *)(param_1 + 0x4c8) = uVar18;
      lVar13 = *(long *)(param_1 + 0x4c0) + (ulong)uVar6;
    }
    *(long *)(*(long *)(param_1 + 0x300) + 0x78) = lVar13;
    uVar6 = *(uint *)(param_1 + 0x4c8);
    uVar18 = uVar6 + uVar11;
    if (*(uint *)(param_1 + 0x4cc) < uVar18) {
      lVar13 = 0;
    }
    else {
      *(uint *)(param_1 + 0x4c8) = uVar18;
      lVar13 = *(long *)(param_1 + 0x4c0) + (ulong)uVar6;
    }
    *(long *)(*(long *)(param_1 + 0x300) + 0x88) = lVar13;
    uVar6 = *(uint *)(param_1 + 0x4c8);
    uVar18 = uVar6 + uVar11;
    if (*(uint *)(param_1 + 0x4cc) < uVar18) {
      *(undefined8 *)(*(long *)(param_1 + 0x300) + 0xb8) = 0;
    }
    else {
      *(uint *)(param_1 + 0x4c8) = uVar18;
      *(ulong *)(*(long *)(param_1 + 0x300) + 0xb8) = *(long *)(param_1 + 0x4c0) + (ulong)uVar6;
    }
    if (cVar8 != '\x03') goto LAB_71005c7884;
    uVar6 = *(uint *)(param_1 + 0x4c8);
    uVar18 = uVar6 + uVar11;
    if (*(uint *)(param_1 + 0x4cc) < uVar18) {
      lVar13 = 0;
    }
    else {
      *(uint *)(param_1 + 0x4c8) = uVar18;
      lVar13 = *(long *)(param_1 + 0x4c0) + (ulong)uVar6;
    }
    *(long *)(*(long *)(param_1 + 0x300) + 0xd8) = lVar13;
    uVar6 = *(uint *)(param_1 + 0x4c8);
    uVar18 = uVar6 + uVar11;
    if (*(uint *)(param_1 + 0x4cc) < uVar18) {
      lVar13 = 0;
    }
    else {
      *(uint *)(param_1 + 0x4c8) = uVar18;
      lVar13 = *(long *)(param_1 + 0x4c0) + (ulong)uVar6;
    }
    *(long *)(*(long *)(param_1 + 0x300) + 0xe8) = lVar13;
    uVar6 = *(uint *)(param_1 + 0x4c8);
    uVar18 = uVar6 + uVar11;
    if (*(uint *)(param_1 + 0x4cc) < uVar18) {
      lVar13 = 0;
    }
    else {
      *(uint *)(param_1 + 0x4c8) = uVar18;
      lVar13 = *(long *)(param_1 + 0x4c0) + (ulong)uVar6;
    }
    *(long *)(*(long *)(param_1 + 0x300) + 0x118) = lVar13;
    uVar6 = *(uint *)(param_1 + 0x4c8);
    uVar18 = uVar6 + uVar11;
    if (*(uint *)(param_1 + 0x4cc) < uVar18) goto LAB_71005c7898;
LAB_71005c7974:
    *(uint *)(param_1 + 0x4c8) = uVar18;
    *(ulong *)(*(long *)(param_1 + 0x300) + 0x20) = *(long *)(param_1 + 0x4c0) + (ulong)uVar6;
    iVar5 = *(int *)(param_1 + 0x308);
  }
  if (1 < iVar5) {
    lVar13 = 1;
    lVar17 = 0x80;
    do {
      lVar13 = lVar13 + 1;
      *(undefined8 *)(*(long *)(param_1 + 0x300) + lVar17) =
           *(undefined8 *)(*(long *)(param_1 + 0x300) + 0x20);
      lVar17 = lVar17 + 0x60;
    } while (lVar13 < *(int *)(param_1 + 0x308));
  }
  lVar13 = (long)(int)uVar3;
  if ((*(byte *)(param_1 + 0x30) & 1) == 0) {
    lVar17 = 0;
    *(undefined8 *)(*(long *)(param_1 + 0x300) + 0x30) = 0;
    *(undefined8 *)(*(long *)(param_1 + 0x300) + 0x38) = 0;
    *(undefined8 *)(*(long *)(param_1 + 0x300) + 0x90) = 0;
    lVar19 = 1;
LAB_71005c79ec:
    *(long *)(*(long *)(param_1 + 0x300) + lVar19 * 0x60 + 0x38) = lVar17;
  }
  else {
    uVar6 = *(uint *)(param_1 + 0x4c8);
    uVar18 = uVar6 + uVar11;
    if (*(uint *)(param_1 + 0x4cc) < uVar18) {
      lVar17 = 0;
    }
    else {
      *(uint *)(param_1 + 0x4c8) = uVar18;
      lVar17 = *(long *)(param_1 + 0x4c0) + (ulong)uVar6;
    }
    *(long *)(*(long *)(param_1 + 0x300) + 0x30) = lVar17;
    uVar6 = *(uint *)(param_1 + 0x4c8);
    uVar18 = uVar6 + uVar11;
    if (*(uint *)(param_1 + 0x4cc) < uVar18) {
      *(undefined8 *)(*(long *)(param_1 + 0x300) + 0x38) = 0;
    }
    else {
      *(uint *)(param_1 + 0x4c8) = uVar18;
      *(ulong *)(*(long *)(param_1 + 0x300) + 0x38) = *(long *)(param_1 + 0x4c0) + (ulong)uVar6;
    }
    if ((uVar4 >> 0xe & 1) == 0) {
      if (1 < *(int *)(param_1 + 0x308)) {
        lVar19 = 0;
        lVar17 = 1;
        do {
          lVar17 = lVar17 + 1;
          *(undefined8 *)(*(long *)(param_1 + 0x300) + lVar19 + 0x90) =
               *(undefined8 *)(*(long *)(param_1 + 0x300) + 0x30);
          lVar1 = *(long *)(param_1 + 0x300) + lVar19;
          lVar19 = lVar19 + 0x60;
          *(undefined8 *)(lVar1 + 0x98) = *(undefined8 *)(*(long *)(param_1 + 0x300) + 0x38);
        } while (lVar17 < *(int *)(param_1 + 0x308));
      }
    }
    else {
      uVar6 = *(uint *)(param_1 + 0x4c8);
      uVar18 = uVar6 + uVar11;
      if (*(uint *)(param_1 + 0x4cc) < uVar18) {
        lVar17 = 0;
      }
      else {
        *(uint *)(param_1 + 0x4c8) = uVar18;
        lVar17 = *(long *)(param_1 + 0x4c0) + (ulong)uVar6;
      }
      *(long *)(*(long *)(param_1 + 0x300) + 0x90) = lVar17;
      uVar6 = *(uint *)(param_1 + 0x4c8);
      uVar18 = uVar6 + uVar11;
      if (*(uint *)(param_1 + 0x4cc) < uVar18) {
        lVar17 = 0;
      }
      else {
        *(uint *)(param_1 + 0x4c8) = uVar18;
        lVar17 = *(long *)(param_1 + 0x4c0) + (ulong)uVar6;
      }
      *(long *)(*(long *)(param_1 + 0x300) + 0x98) = lVar17;
      if (cVar8 == '\x03') {
        uVar6 = *(uint *)(param_1 + 0x4c8);
        uVar18 = uVar6 + uVar11;
        if (*(uint *)(param_1 + 0x4cc) < uVar18) {
          lVar17 = 0;
        }
        else {
          *(uint *)(param_1 + 0x4c8) = uVar18;
          lVar17 = *(long *)(param_1 + 0x4c0) + (ulong)uVar6;
        }
        *(long *)(*(long *)(param_1 + 0x300) + 0xf0) = lVar17;
        uVar6 = *(uint *)(param_1 + 0x4c8);
        uVar18 = uVar6 + uVar11;
        if (*(uint *)(param_1 + 0x4cc) < uVar18) {
          lVar17 = 0;
          lVar19 = 2;
        }
        else {
          *(uint *)(param_1 + 0x4c8) = uVar18;
          lVar19 = 2;
          lVar17 = *(long *)(param_1 + 0x4c0) + (ulong)uVar6;
        }
        goto LAB_71005c79ec;
      }
    }
  }
  if (*(char *)(*(long *)(param_1 + 0x48) + 0xcc3) == '\0') {
    if (0 < *(int *)(param_1 + 0x308)) {
      lVar19 = 0;
      lVar17 = 0;
      do {
        lVar17 = lVar17 + 1;
        *(undefined8 *)(*(long *)(param_1 + 0x300) + lVar19 + 0x40) = 0;
        *(undefined8 *)(*(long *)(param_1 + 0x300) + lVar19 + 0x48) = 0;
        lVar1 = *(long *)(param_1 + 0x300) + lVar19;
        lVar19 = lVar19 + 0x60;
        *(undefined8 *)(lVar1 + 0x50) = 0;
      } while (lVar17 < *(int *)(param_1 + 0x308));
    }
  }
  else {
    uVar6 = *(uint *)(param_1 + 0x4c8);
    uVar18 = uVar6 + uVar11;
    if (*(uint *)(param_1 + 0x4cc) < uVar18) {
      lVar17 = 0;
    }
    else {
      *(uint *)(param_1 + 0x4c8) = uVar18;
      lVar17 = *(long *)(param_1 + 0x4c0) + (ulong)uVar6;
    }
    *(long *)(*(long *)(param_1 + 0x300) + 0x40) = lVar17;
    uVar6 = *(uint *)(param_1 + 0x4c8);
    uVar18 = uVar6 + uVar11;
    if (*(uint *)(param_1 + 0x4cc) < uVar18) {
      lVar17 = 0;
    }
    else {
      *(uint *)(param_1 + 0x4c8) = uVar18;
      lVar17 = *(long *)(param_1 + 0x4c0) + (ulong)uVar6;
    }
    *(long *)(*(long *)(param_1 + 0x300) + 0x48) = lVar17;
    uVar18 = *(uint *)(param_1 + 0x4c8);
    uVar11 = uVar18 + uVar11;
    if (*(uint *)(param_1 + 0x4cc) < uVar11) {
      *(undefined8 *)(*(long *)(param_1 + 0x300) + 0x50) = 0;
      iVar5 = *(int *)(param_1 + 0x308);
    }
    else {
      *(uint *)(param_1 + 0x4c8) = uVar11;
      *(ulong *)(*(long *)(param_1 + 0x300) + 0x50) = *(long *)(param_1 + 0x4c0) + (ulong)uVar18;
      iVar5 = *(int *)(param_1 + 0x308);
    }
    if (1 < iVar5) {
      lVar19 = 0;
      lVar17 = 1;
      do {
        lVar17 = lVar17 + 1;
        *(undefined8 *)(*(long *)(param_1 + 0x300) + lVar19 + 0xa0) =
             *(undefined8 *)(*(long *)(param_1 + 0x300) + 0x40);
        *(undefined8 *)(*(long *)(param_1 + 0x300) + lVar19 + 0xa8) =
             *(undefined8 *)(*(long *)(param_1 + 0x300) + 0x48);
        lVar1 = *(long *)(param_1 + 0x300) + lVar19;
        lVar19 = lVar19 + 0x60;
        *(undefined8 *)(lVar1 + 0xb0) = *(undefined8 *)(*(long *)(param_1 + 0x300) + 0x50);
      } while (lVar17 < *(int *)(param_1 + 0x308));
    }
  }
  uVar14 = 0;
  lVar17 = lVar13 * 0x20;
  *(ulong *)(param_1 + 0x68) = *(long *)(param_1 + 0x300) + (ulong)*(byte *)(param_1 + 0x80) * 0x60;
  lVar19 = 0;
  if (*(char *)(*(long *)(param_1 + 0x40) + 0xe5) != '\0') {
    lVar19 = (long)(int)uVar3 * 0x158;
  }
  if ((uVar4 >> 0xe & 1) != 0) {
    uVar11 = 7;
    if ((*(byte *)(param_1 + 0x30) & 1) != 0) {
      uVar11 = 9;
    }
    if (*(char *)(*(long *)(param_1 + 0x48) + 0xcc3) != '\0') {
      uVar11 = uVar11 + 6;
    }
    uVar14 = (ulong)uVar11;
  }
  lVar1 = param_1 + 0x6d0;
  lVar21 = lVar19 + lVar17 + uVar14 * uVar22;
  thunk_EXT_FUN_02e95df0(lVar1);
  lVar12 = (**(code **)(**(long **)(param_1 + 0x6f0) + 0x10))
                     (*(long **)(param_1 + 0x6f0),lVar21,0x20);
  if (lVar12 == 0) {
    thunk_EXT_FUN_02e95df0(lVar1);
    *(undefined8 *)(param_1 + 0x4b0) = 0;
    return 0;
  }
  *(long *)(param_1 + 0x6f8) = *(long *)(param_1 + 0x6f8) + lVar21;
  *(long *)(param_1 + 0x700) = *(long *)(param_1 + 0x700) + 1;
  thunk_EXT_FUN_02e95df0(lVar1);
  *(long *)(param_1 + 0x4b0) = lVar12;
  *(long *)(param_1 + 0x60) = lVar12;
  thunk_EXT_FUN_02e95df0(lVar12,0,lVar17);
  if ((uVar4 >> 0xe & 1) == 0) {
    puVar16 = *(undefined8 **)(param_1 + 0x300);
    *(undefined8 *)(param_1 + 0x310) = *puVar16;
    *(undefined8 *)(param_1 + 0x318) = puVar16[1];
    *(undefined8 *)(param_1 + 800) = puVar16[2];
    *(undefined8 *)(param_1 + 0x328) = puVar16[3];
    *(undefined8 *)(param_1 + 0x330) = puVar16[4];
    *(undefined8 *)(param_1 + 0x338) = puVar16[5];
    *(undefined8 *)(param_1 + 0x340) = puVar16[6];
    *(undefined8 *)(param_1 + 0x348) = puVar16[7];
    *(undefined8 *)(param_1 + 0x350) = puVar16[8];
    *(undefined8 *)(param_1 + 0x358) = puVar16[9];
    *(undefined8 *)(param_1 + 0x360) = puVar16[10];
    *(undefined8 *)(param_1 + 0x368) = puVar16[0xb];
    cVar8 = *(char *)(*(long *)(param_1 + 0x40) + 0xe5);
  }
  else {
    *(long *)(param_1 + 0x310) = lVar12 + lVar17;
    *(long *)(param_1 + 800) = lVar12 + lVar13 * 0x40;
    *(long *)(param_1 + 0x318) = lVar12 + (long)(int)uVar3 * 0x30;
    *(long *)(param_1 + 0x328) = lVar12 + (long)(int)uVar3 * 0x50;
    *(long *)(param_1 + 0x368) = lVar12 + lVar13 * 0x80;
    *(long *)(param_1 + 0x330) = lVar12 + (long)(int)uVar3 * 0x60;
    bVar9 = (*(uint *)(param_1 + 0x30) & 1) != 0;
    *(long *)(param_1 + 0x338) = lVar12 + (long)(int)uVar3 * 0x70;
    lVar17 = lVar13 * 0x90;
    if (bVar9) {
      lVar17 = (long)(int)uVar3 * 0xb0;
    }
    lVar1 = 0;
    if (bVar9) {
      lVar1 = lVar12 + lVar13 * 0x90;
    }
    lVar13 = 0;
    if (bVar9) {
      lVar13 = lVar12 + (long)(int)uVar3 * 0xa0;
    }
    *(long *)(param_1 + 0x340) = lVar1;
    *(long *)(param_1 + 0x348) = lVar13;
    if (*(char *)(*(long *)(param_1 + 0x48) + 0xcc3) == '\0') {
      *(undefined8 *)(param_1 + 0x360) = 0;
      *(undefined8 *)(param_1 + 0x358) = 0;
      *(undefined8 *)(param_1 + 0x350) = 0;
      cVar8 = *(char *)(*(long *)(param_1 + 0x40) + 0xe5);
    }
    else {
      *(long *)(param_1 + 0x350) = lVar12 + lVar17;
      lVar13 = lVar17 + uVar22 + uVar22;
      *(ulong *)(param_1 + 0x358) = lVar12 + lVar17 + uVar22;
      lVar17 = lVar13 + uVar22;
      *(long *)(param_1 + 0x360) = lVar12 + lVar13;
      cVar8 = *(char *)(*(long *)(param_1 + 0x40) + 0xe5);
    }
  }
  if (cVar8 != '\0') {
    *(long *)(*(long *)(param_1 + 0x50) + 0x180) = lVar12 + lVar17;
    thunk_EXT_FUN_02e95df0(*(undefined8 *)(*(long *)(param_1 + 0x50) + 0x180),0,lVar19);
  }
  *(uint *)(param_1 + 0x98) = uVar10;
  *(undefined4 *)(param_1 + 0x9c) = 0;
  *(undefined8 *)(param_1 + 0x90) = 0;
LAB_71005c7db0:
  FUN_71005c8a00(param_1);
  lVar13 = *(long *)(param_1 + 0x48);
  uVar20 = *(undefined8 *)(lVar13 + 0xd10);
  *(undefined4 *)(param_1 + 0x3e0) = *(undefined4 *)(lVar13 + 0xd18);
  *(undefined8 *)(param_1 + 0x3d8) = uVar20;
  uVar7 = *(undefined4 *)(lVar13 + 0xd00);
  *(undefined8 *)(param_1 + 0x3e4) = *(undefined8 *)(lVar13 + 0xcf8);
  *(undefined4 *)(param_1 + 0x3ec) = uVar7;
  uVar7 = *(undefined4 *)(lVar13 + 0xce8);
  *(undefined8 *)(param_1 + 0x3f0) = *(undefined8 *)(lVar13 + 0xce0);
  *(undefined4 *)(param_1 + 0x3f8) = uVar7;
  *(undefined4 *)(param_1 + 0x3fc) = *(undefined4 *)(lVar13 + 0xd1c);
  *(undefined4 *)(param_1 + 0x400) = *(undefined4 *)(lVar13 + 0xd20);
  *(undefined4 *)(param_1 + 0x404) = *(undefined4 *)(lVar13 + 0xd24);
  *(undefined4 *)(param_1 + 0x408) = *(undefined4 *)(lVar13 + 0xd2c);
  *(undefined4 *)(param_1 + 0x40c) = *(undefined4 *)(lVar13 + 0xd30);
  *(undefined4 *)(param_1 + 0x410) = *(undefined4 *)(lVar13 + 0xd34);
  uVar20 = *(undefined8 *)(lVar13 + 0x1008);
  *(undefined4 *)(param_1 + 0x464) = *(undefined4 *)(lVar13 + 0x1010);
  *(undefined8 *)(param_1 + 0x45c) = uVar20;
  uVar20 = *(undefined8 *)(lVar13 + 0xde0);
  *(undefined4 *)(param_1 + 0x470) = *(undefined4 *)(lVar13 + 0xde8);
  *(undefined8 *)(param_1 + 0x468) = uVar20;
  *(undefined4 *)(param_1 + 0x414) = *(undefined4 *)(*(long *)(param_1 + 0x40) + 0xf4);
  *(float *)(param_1 + 0x420) = (float)*(int *)(*(long *)(param_1 + 0x40) + 0xf0);
  *(undefined4 *)(param_1 + 0x42c) = *(undefined4 *)(lVar13 + 0xd28);
  *(undefined4 *)(param_1 + 0x438) = *(undefined4 *)(lVar13 + 0xd38);
  *(undefined4 *)(param_1 + 0x444) = *(undefined4 *)(lVar13 + 0xf9c);
  *(undefined4 *)(param_1 + 0x450) = *(undefined4 *)(lVar13 + 4000);
  *(undefined4 *)(param_1 + 0x474) = *(undefined4 *)(lVar13 + 0xd8c);
  return 1;
}



undefined4 FUN_71005c8030(long param_1)

{
  char cVar1;
  byte bVar2;
  byte bVar3;
  byte bVar4;
  byte bVar5;
  undefined4 uVar6;
  long lVar7;
  long lVar8;
  
  bVar2 = FUN_71005cf3e4((undefined1 *)(param_1 + 0x4d0));
  bVar3 = FUN_71005cf3e4((undefined1 *)(param_1 + 0x510));
  bVar4 = FUN_71005cf3e4((undefined1 *)(param_1 + 0x550));
  bVar5 = FUN_71005cf3e4((undefined1 *)(param_1 + 0x590));
  lVar7 = 0;
  uVar6 = 1;
  do {
    lVar8 = *(long *)(*(long *)(param_1 + 0x40) + lVar7 * 8 + 0x10);
    if (lVar8 != 0) {
      cVar1 = *(char *)(lVar8 + 0x88);
      if (*(char *)(lVar8 + 0x46) == -1) {
        if (cVar1 != -1 && (bVar2 & 1) == 0) {
LAB_71005c8144:
          FUN_71005dee10();
          uVar6 = 0;
        }
      }
      else if ((bVar2 & 1) == 0) {
        FUN_71005dee10();
        uVar6 = 0;
        if (cVar1 != -1) goto LAB_71005c8144;
      }
      cVar1 = *(char *)(lVar8 + 0x89);
      if (*(char *)(lVar8 + 0x47) == -1) {
        if (cVar1 != -1 && (bVar3 & 1) == 0) {
LAB_71005c81d0:
          FUN_71005dee10();
          goto LAB_71005c81f8;
        }
      }
      else if ((bVar3 & 1) == 0) {
        FUN_71005dee10();
        if (cVar1 != -1) goto LAB_71005c81d0;
LAB_71005c81f8:
        uVar6 = 0;
      }
      cVar1 = *(char *)(lVar8 + 0x8a);
      if (*(char *)(lVar8 + 0x48) == -1) {
        if (cVar1 != -1 && (bVar4 & 1) == 0) {
LAB_71005c8254:
          FUN_71005dee10();
          goto LAB_71005c827c;
        }
      }
      else if ((bVar4 & 1) == 0) {
        FUN_71005dee10();
        if (cVar1 != -1) goto LAB_71005c8254;
LAB_71005c827c:
        uVar6 = 0;
      }
      cVar1 = *(char *)(lVar8 + 0x8b);
      if (*(char *)(lVar8 + 0x49) == -1) {
        if (cVar1 != -1 && (bVar5 & 1) == 0) {
LAB_71005c80a0:
          FUN_71005dee10();
          goto LAB_71005c80c8;
        }
      }
      else if ((bVar5 & 1) == 0) {
        FUN_71005dee10();
        if (cVar1 != -1) goto LAB_71005c80a0;
LAB_71005c80c8:
        uVar6 = 0;
      }
    }
    lVar7 = lVar7 + 1;
  } while (lVar7 != 8);
  lVar7 = *(long *)(param_1 + 0x40);
  lVar8 = *(long *)(lVar7 + 0x50);
  if (lVar8 != 0) {
    if (*(char *)(lVar8 + 0x4f) == -1 || (bVar2 & 1) != 0) {
      if (*(char *)(lVar8 + 0x50) == -1 || (bVar3 & 1) != 0) goto LAB_71005c8318;
LAB_71005c84dc:
      FUN_71005dee10();
      uVar6 = 0;
      if (*(char *)(lVar8 + 0x51) != -1 && (bVar4 & 1) == 0) goto LAB_71005c851c;
LAB_71005c832c:
      if (*(char *)(lVar8 + 0x52) != -1 && (bVar5 & 1) == 0) {
LAB_71005c8340:
        FUN_71005dee10();
        uVar6 = 0;
      }
    }
    else {
      FUN_71005dee10();
      uVar6 = 0;
      if (*(char *)(lVar8 + 0x50) != -1 && (bVar3 & 1) == 0) goto LAB_71005c84dc;
LAB_71005c8318:
      if (*(char *)(lVar8 + 0x51) == -1 || (bVar4 & 1) != 0) goto LAB_71005c832c;
LAB_71005c851c:
      FUN_71005dee10();
      uVar6 = 0;
      if (*(char *)(lVar8 + 0x52) != -1 && (bVar5 & 1) == 0) goto LAB_71005c8340;
    }
    lVar7 = *(long *)(param_1 + 0x40);
  }
  lVar8 = *(long *)(lVar7 + 0x58);
  if (lVar8 != 0) {
    if (*(char *)(lVar8 + 0x4f) == -1 || (bVar2 & 1) != 0) {
      if (*(char *)(lVar8 + 0x50) == -1 || (bVar3 & 1) != 0) goto LAB_71005c83a0;
LAB_71005c85a0:
      FUN_71005dee10();
      uVar6 = 0;
      if (*(char *)(lVar8 + 0x51) != -1 && (bVar4 & 1) == 0) goto LAB_71005c85e0;
LAB_71005c83b4:
      if (*(char *)(lVar8 + 0x52) != -1 && (bVar5 & 1) == 0) {
LAB_71005c83c8:
        FUN_71005dee10();
        uVar6 = 0;
      }
    }
    else {
      FUN_71005dee10();
      uVar6 = 0;
      if (*(char *)(lVar8 + 0x50) != -1 && (bVar3 & 1) == 0) goto LAB_71005c85a0;
LAB_71005c83a0:
      if (*(char *)(lVar8 + 0x51) == -1 || (bVar4 & 1) != 0) goto LAB_71005c83b4;
LAB_71005c85e0:
      FUN_71005dee10();
      uVar6 = 0;
      if (*(char *)(lVar8 + 0x52) != -1 && (bVar5 & 1) == 0) goto LAB_71005c83c8;
    }
    lVar7 = *(long *)(param_1 + 0x40);
  }
  lVar7 = *(long *)(lVar7 + 0x60);
  if (lVar7 == 0) {
    return uVar6;
  }
  if (*(char *)(lVar7 + 0x4f) == -1 || (bVar2 & 1) != 0) {
    if (*(char *)(lVar7 + 0x50) == -1 || (bVar3 & 1) != 0) goto LAB_71005c8428;
LAB_71005c8664:
    FUN_71005dee10();
    uVar6 = 0;
    if (*(char *)(lVar7 + 0x51) != -1 && (bVar4 & 1) == 0) goto LAB_71005c86a4;
  }
  else {
    FUN_71005dee10();
    uVar6 = 0;
    if (*(char *)(lVar7 + 0x50) != -1 && (bVar3 & 1) == 0) goto LAB_71005c8664;
LAB_71005c8428:
    if (*(char *)(lVar7 + 0x51) != -1 && (bVar4 & 1) == 0) {
LAB_71005c86a4:
      FUN_71005dee10();
      if (*(char *)(lVar7 + 0x52) == -1 || (bVar5 & 1) != 0) {
        return 0;
      }
      goto LAB_71005c8450;
    }
  }
  if (*(char *)(lVar7 + 0x52) == -1 || (bVar5 & 1) != 0) {
    return uVar6;
  }
LAB_71005c8450:
  FUN_71005dee10();
  return 0;
}



void FUN_71005c86e8(long param_1)

{
  thunk_EXT_FUN_02e95df0(param_1,0,0x4c0);
  *(undefined1 *)(param_1 + 0x630) = 0;
  *(undefined8 *)(param_1 + 0x6f8) = 0;
  *(undefined8 *)(param_1 + 0x700) = 0;
  return;
}



ulong FUN_71005c871c(long param_1,ulong param_2,char param_3,long param_4)

{
  char *pcVar1;
  ulong uVar2;
  uint uVar3;
  
  if (param_3 == '\0') {
    uVar3 = 1;
  }
  else {
    if ((param_3 != '\x02') && (param_3 != '\x01')) {
      uVar2 = thunk_EXT_FUN_02e95df0();
      return uVar2;
    }
    uVar3 = (uint)*(byte *)(param_1 + 0x710);
  }
  pcVar1 = (char *)(param_1 + (param_2 & 0xff) * 0x40 + 0x4d0);
  uVar2 = FUN_71005cf290(pcVar1,*(long *)(param_1 + 0x658),param_3,uVar3,
                         (param_4 + 0xfU & 0xfffffffffffffff0) * (long)*(int *)(param_1 + 0x98));
  if ((uVar2 & 1) != 0) {
    FUN_71005cf534(pcVar1);
  }
  return (ulong)((uint)uVar2 & 1);
}



void FUN_71005c879c(long param_1,uint param_2,long param_3)

{
  FUN_71005cf290((char *)(param_1 + 0x660),*(long *)(param_1 + 0x658),'\x01',param_2,param_3);
  return;
}



int FUN_71005c87b8(long param_1,long param_2)

{
  uint uVar1;
  uint uVar2;
  char cVar3;
  bool bVar4;
  int iVar5;
  long lVar6;
  int iVar7;
  long lVar8;
  int iVar9;
  int *piVar10;
  float fVar11;
  float fVar12;
  float fVar13;
  
  lVar6 = *(long *)(param_1 + 0x48);
  uVar2 = *(uint *)(param_1 + 0x30);
  if ((uVar2 >> 0x15 & 1) != 0) {
    iVar7 = *(int *)(lVar6 + 0xdac);
    goto LAB_71005c88d4;
  }
  lVar8 = *(long *)(param_1 + 0x40);
  fVar11 = *(float *)(lVar8 + 0xf4);
  bVar4 = false;
  if ((*(long *)(lVar8 + 0x450) != 0) && (bVar4 = false, !NAN(fVar11))) {
    bVar4 = fVar11 < 1.0;
  }
  fVar12 = 1.0;
  if (!bVar4) {
    fVar12 = fVar11;
  }
  fVar11 = 1.0;
  if (*(int *)(lVar6 + 0xd74) != 0) {
    fVar11 = (float)*(int *)(lVar6 + 0xd74);
  }
  fVar13 = (float)(*(int *)(lVar6 + 0xd80) + 1);
  iVar7 = (int)(fVar11 / fVar13);
  iVar9 = (int)((float)*(int *)(lVar8 + 0xf0) / fVar13);
  uVar1 = (uint)(iVar7 < iVar9) & uVar2 >> 0x14;
  if (((uVar2 ^ 0xffffffff) & 0x180000) == 0) {
    uVar1 = 1;
  }
  if (uVar1 == 0) {
    iVar7 = iVar9;
  }
  fVar11 = (float)(int)fVar12;
  iVar7 = (int)((float)(int)(fVar12 * (float)iVar7) + fVar11 * 2.0);
  if (*(int *)(lVar6 + 0xdec) == 0) {
    cVar3 = *(char *)(lVar6 + 0xdb0);
    if (cVar3 == '\r') {
      piVar10 = (int *)(lVar6 + 0xe00);
LAB_71005c8894:
      iVar7 = *piVar10 * iVar7;
    }
    else if (cVar3 == '\x02') {
      piVar10 = (int *)(lVar6 + 0xdf8);
      goto LAB_71005c8894;
    }
    if ((uVar2 & 0x110000) != 0x10000) goto LAB_71005c88d4;
    iVar9 = (int)fVar11;
    if (cVar3 == '\r') {
      iVar5 = *(int *)(lVar6 + 0xe00);
    }
    else {
      if (cVar3 != '\x02') goto LAB_71005c88d0;
      iVar5 = *(int *)(lVar6 + 0xdf8);
    }
    iVar9 = iVar5 * iVar9;
  }
  else {
    if ((uVar2 & 0x110000) != 0x10000) goto LAB_71005c88d4;
    iVar9 = (int)fVar11;
  }
LAB_71005c88d0:
  iVar7 = iVar9 + iVar7;
LAB_71005c88d4:
  if ((uVar2 & 0x20001) == 1) {
    iVar7 = *(int *)(param_2 + 0x98) * iVar7;
  }
  return iVar7;
}



void FUN_71005c88f0(long param_1)

{
  long lVar1;
  code *pcVar2;
  long lVar3;
  long lVar4;
  undefined8 local_60;
  undefined8 local_58;
  
  if (0 < *(int *)(param_1 + 0x90)) {
    lVar4 = 0;
    lVar3 = 0;
    do {
      lVar1 = *(long *)(param_1 + 0x60) + lVar4;
      branch_71005E43E0_0x71005e3d20
                (*(float *)(param_1 + 0x28) - *(float *)(lVar1 + 8),*(undefined4 *)(lVar1 + 0xc),
                 &local_60,param_1,(int)lVar3);
      lVar1 = *(long *)(param_1 + 0x60) + lVar4;
      local_60 = *(undefined8 *)(lVar1 + 0x10);
      local_58 = *(undefined8 *)(lVar1 + 0x18);
      if ((*(long *)(param_1 + 0x370) != 0) &&
         (pcVar2 = *(code **)(*(long *)(param_1 + 0x370) + 0x48), pcVar2 != (code *)0x0)) {
        (*pcVar2)(&local_60);
      }
      if ((*(long *)(param_1 + 0x378) != 0) &&
         (pcVar2 = *(code **)(*(long *)(param_1 + 0x378) + 0x48), pcVar2 != (code *)0x0)) {
        (*pcVar2)(&local_60);
      }
      if ((*(long *)(param_1 + 0x380) != 0) &&
         (pcVar2 = *(code **)(*(long *)(param_1 + 0x380) + 0x48), pcVar2 != (code *)0x0)) {
        (*pcVar2)(&local_60);
      }
      if ((*(long *)(param_1 + 0x388) != 0) &&
         (pcVar2 = *(code **)(*(long *)(param_1 + 0x388) + 0x48), pcVar2 != (code *)0x0)) {
        (*pcVar2)(&local_60);
      }
      lVar3 = lVar3 + 1;
      *(undefined8 *)(*(long *)(param_1 + 0x60) + lVar4 + 0x18) = 0;
      lVar1 = *(long *)(param_1 + 0x60) + lVar4;
      lVar4 = lVar4 + 0x20;
      *(undefined8 *)(lVar1 + 0x10) = 0;
    } while (lVar3 < *(int *)(param_1 + 0x90));
  }
  return;
}



void FUN_71005c8a00(long param_1)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  undefined1 auVar5 [16];
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  undefined1 auVar10 [16];
  long lVar11;
  float fVar12;
  undefined8 uVar13;
  ulong uVar14;
  float fVar15;
  undefined1 auVar16 [16];
  undefined1 auVar17 [16];
  undefined1 auVar18 [16];
  float fVar19;
  float fVar20;
  undefined1 auVar21 [16];
  undefined1 auVar22 [16];
  undefined1 auVar23 [16];
  float fVar24;
  float fVar25;
  float fVar26;
  float fVar27;
  float fVar28;
  float fVar29;
  float fVar30;
  float fVar31;
  byte bVar32;
  byte bVar33;
  byte bVar34;
  byte bVar35;
  byte bVar36;
  byte bVar37;
  byte bVar38;
  byte bVar39;
  byte bVar40;
  float fVar41;
  float fVar42;
  float fVar43;
  float fVar44;
  undefined1 auVar45 [16];
  float fVar46;
  float fVar47;
  float fVar48;
  
  uVar1 = *(uint *)(param_1 + 0x4a4);
  uVar2 = uVar1 * 0x41c64e6d + 0x3039;
  lVar11 = *(long *)(param_1 + 0x48);
  uVar3 = uVar2 * 0x41c64e6d + 0x3039;
  fVar24 = *(float *)(lVar11 + 0xcf8);
  *(uint *)(param_1 + 0x4a4) = uVar2;
  uVar4 = uVar3 * 0x41c64e6d + 0x3039;
  fVar24 = fVar24 + *(float *)(lVar11 + 0xd04) * ((float)uVar1 * 2.3283064e-10 * 2.0 + -1.0);
  fVar19 = *(float *)(lVar11 + 0xcfc);
  *(uint *)(param_1 + 0x4a4) = uVar3;
  fVar19 = fVar19 + *(float *)(lVar11 + 0xd08) * ((float)uVar2 * 2.3283064e-10 * 2.0 + -1.0);
  fVar25 = *(float *)(lVar11 + 0xd00);
  *(uint *)(param_1 + 0x4a4) = uVar4;
  fVar25 = fVar25 + *(float *)(lVar11 + 0xd0c) * ((float)uVar3 * 2.3283064e-10 * 2.0 + -1.0);
  fVar26 = *DAT_7103a66e90;
  fVar20 = *DAT_7103a66e88;
  fVar12 = *DAT_7103a66e68;
  fVar43 = *DAT_7103a66e80;
  fVar15 = DAT_7103a66e80[1];
  fVar41 = DAT_7103a66e80[3];
  fVar46 = *DAT_7103a66e78;
  auVar17._0_4_ = fVar24 - (float)(int)(fVar24 * fVar20) * fVar26;
  auVar17._4_4_ = fVar19 - (float)(int)(fVar19 * fVar20) * fVar26;
  auVar17._8_4_ = fVar25 - (float)(int)(fVar25 * fVar20) * fVar26;
  auVar17._12_4_ = 0.0 - (float)(int)(fVar20 * 0.0) * fVar26;
  fVar25 = *DAT_7103a66e70;
  fVar19 = -fVar12;
  fVar20 = -fVar25;
  fVar48 = -DAT_7103a66e80[2];
  auVar21._0_4_ = -(uint)(fVar12 < auVar17._0_4_);
  auVar21._4_4_ = -(uint)(fVar12 < auVar17._4_4_);
  auVar21._8_4_ = -(uint)(fVar12 < auVar17._8_4_);
  auVar21._12_4_ = -(uint)(fVar12 < auVar17._12_4_);
  auVar10._4_4_ = fVar25 - auVar17._4_4_;
  auVar10._0_4_ = fVar25 - auVar17._0_4_;
  auVar10._8_4_ = fVar25 - auVar17._8_4_;
  auVar10._12_4_ = fVar25 - auVar17._12_4_;
  auVar17 = auVar17 ^ (auVar17 ^ auVar10) & auVar21;
  fVar42 = (float)*(undefined8 *)(DAT_7103a66e78 + 3);
  fVar28 = (float)*(undefined8 *)(DAT_7103a66e78 + 1);
  iVar6 = -(uint)(auVar17._0_4_ < fVar19);
  iVar7 = -(uint)(auVar17._4_4_ < fVar19);
  bVar32 = (byte)((uint)iVar7 >> 8);
  bVar33 = (byte)((uint)iVar7 >> 0x10);
  bVar34 = (byte)((uint)iVar7 >> 0x18);
  iVar8 = -(uint)(auVar17._8_4_ < fVar19);
  bVar35 = (byte)((uint)iVar8 >> 8);
  bVar36 = (byte)((uint)iVar8 >> 0x10);
  bVar37 = (byte)((uint)iVar8 >> 0x18);
  iVar9 = -(uint)(auVar17._12_4_ < fVar19);
  bVar38 = (byte)((uint)iVar9 >> 8);
  bVar39 = (byte)((uint)iVar9 >> 0x10);
  bVar40 = (byte)((uint)iVar9 >> 0x18);
  auVar22[0] = (byte)iVar6 | (byte)auVar21._0_4_;
  auVar22[1] = (byte)((uint)iVar6 >> 8) | (byte)((uint)auVar21._0_4_ >> 8);
  auVar22[2] = (byte)((uint)iVar6 >> 0x10) | (byte)((uint)auVar21._0_4_ >> 0x10);
  auVar22[3] = (byte)((uint)iVar6 >> 0x18) | (byte)((uint)auVar21._0_4_ >> 0x18);
  auVar22[4] = (byte)iVar7 | (byte)auVar21._4_4_;
  auVar22[5] = bVar32 | (byte)((uint)auVar21._4_4_ >> 8);
  auVar22[6] = bVar33 | (byte)((uint)auVar21._4_4_ >> 0x10);
  auVar22[7] = bVar34 | (byte)((uint)auVar21._4_4_ >> 0x18);
  auVar22[8] = (byte)iVar8 | (byte)auVar21._8_4_;
  auVar22[9] = bVar35 | (byte)((uint)auVar21._8_4_ >> 8);
  auVar22[10] = bVar36 | (byte)((uint)auVar21._8_4_ >> 0x10);
  auVar22[0xb] = bVar37 | (byte)((uint)auVar21._8_4_ >> 0x18);
  auVar22[0xc] = (byte)iVar9 | (byte)auVar21._12_4_;
  auVar22[0xd] = bVar38 | (byte)((uint)auVar21._12_4_ >> 8);
  auVar22[0xe] = bVar39 | (byte)((uint)auVar21._12_4_ >> 0x10);
  auVar22[0xf] = bVar40 | (byte)((uint)auVar21._12_4_ >> 0x18);
  auVar45._4_4_ = fVar20 - auVar17._4_4_;
  auVar45._0_4_ = fVar20 - auVar17._0_4_;
  auVar45._8_4_ = fVar20 - auVar17._8_4_;
  auVar45._12_4_ = fVar20 - auVar17._12_4_;
  auVar16[4] = (byte)iVar7;
  auVar16._0_4_ = iVar6;
  auVar16[5] = bVar32;
  auVar16[6] = bVar33;
  auVar16[7] = bVar34;
  auVar16[8] = (byte)iVar8;
  auVar16[9] = bVar35;
  auVar16[10] = bVar36;
  auVar16[0xb] = bVar37;
  auVar16[0xc] = (byte)iVar9;
  auVar16[0xd] = bVar38;
  auVar16[0xe] = bVar39;
  auVar16[0xf] = bVar40;
  auVar17 = auVar17 ^ (auVar17 ^ auVar45) & auVar16;
  fVar25 = auVar17._0_4_;
  fVar27 = fVar25 * fVar25;
  fVar20 = auVar17._4_4_;
  fVar29 = fVar20 * fVar20;
  fVar24 = auVar17._8_4_;
  fVar30 = fVar24 * fVar24;
  fVar26 = auVar17._12_4_;
  fVar31 = fVar26 * fVar26;
  fVar44 = -(float)((ulong)*(undefined8 *)(DAT_7103a66e78 + 1) >> 0x20);
  fVar19 = -DAT_7103a66e80[4];
  fVar47 = -(float)((ulong)*(undefined8 *)(DAT_7103a66e78 + 3) >> 0x20);
  auVar45 = NEON_fmov(0x3f800000,4);
  uVar1 = uVar4 * 0x41c64e6d + 0x3039;
  uVar2 = uVar1 * 0x41c64e6d + 0x3039;
  auVar23._0_4_ =
       auVar45._0_4_ +
       fVar27 * (fVar19 + fVar27 * (fVar41 + fVar27 * (fVar48 + fVar27 * (fVar15 - fVar27 * fVar43))
                                   ));
  auVar23._4_4_ =
       auVar45._4_4_ +
       fVar29 * (fVar19 + fVar29 * (fVar41 + fVar29 * (fVar48 + fVar29 * (fVar15 - fVar29 * fVar43))
                                   ));
  auVar23._8_4_ =
       auVar45._8_4_ +
       fVar30 * (fVar19 + fVar30 * (fVar41 + fVar30 * (fVar48 + fVar30 * (fVar15 - fVar30 * fVar43))
                                   ));
  auVar23._12_4_ =
       auVar45._12_4_ +
       fVar31 * (fVar19 + fVar31 * (fVar41 + fVar31 * (fVar48 + fVar31 * (fVar15 - fVar31 * fVar43))
                                   ));
  fVar41 = *(float *)(lVar11 + 0xce0);
  *(uint *)(param_1 + 0x4a4) = uVar1;
  fVar48 = *(float *)(lVar11 + 0xcec);
  fVar19 = -auVar23._4_4_;
  fVar12 = -auVar23._8_4_;
  fVar15 = -auVar23._12_4_;
  auVar5[4] = SUB41(fVar19,0);
  auVar5._0_4_ = -auVar23._0_4_;
  auVar5[5] = (char)((uint)fVar19 >> 8);
  auVar5[6] = (char)((uint)fVar19 >> 0x10);
  auVar5[7] = (char)((uint)fVar19 >> 0x18);
  auVar5[8] = SUB41(fVar12,0);
  auVar5[9] = (char)((uint)fVar12 >> 8);
  auVar5[10] = (char)((uint)fVar12 >> 0x10);
  auVar5[0xb] = (char)((uint)fVar12 >> 0x18);
  auVar5[0xc] = SUB41(fVar15,0);
  auVar5[0xd] = (char)((uint)fVar15 >> 8);
  auVar5[0xe] = (char)((uint)fVar15 >> 0x10);
  auVar5[0xf] = (char)((uint)fVar15 >> 0x18);
  auVar23 = auVar23 ^ (auVar23 ^ auVar5) & auVar22;
  fVar43 = auVar23._4_4_;
  auVar18._0_4_ =
       fVar25 * (auVar45._0_4_ +
                fVar27 * (fVar47 + fVar27 * (fVar42 + fVar27 * (fVar44 + fVar27 * (fVar28 - fVar27 *
                                                                                            fVar46))
                                            )));
  auVar18._4_4_ =
       fVar20 * (auVar45._4_4_ +
                fVar29 * (fVar47 + fVar29 * (fVar42 + fVar29 * (fVar44 + fVar29 * (fVar28 - fVar29 *
                                                                                            fVar46))
                                            )));
  auVar18._8_4_ =
       fVar24 * (auVar45._8_4_ +
                fVar30 * (fVar47 + fVar30 * (fVar42 + fVar30 * (fVar44 + fVar30 * (fVar28 - fVar30 *
                                                                                            fVar46))
                                            )));
  auVar18._12_4_ =
       fVar26 * (auVar45._12_4_ +
                fVar31 * (fVar47 + fVar31 * (fVar42 + fVar31 * (fVar44 + fVar31 * (fVar28 - fVar31 *
                                                                                            fVar46))
                                            )));
  fVar25 = *(float *)(lVar11 + 0xce4);
  *(uint *)(param_1 + 0x4a4) = uVar2;
  auVar45 = NEON_ext(auVar18,auVar18,8,1);
  auVar16 = NEON_ext(auVar23,auVar23,8,1);
  fVar12 = auVar16._0_4_;
  fVar15 = auVar45._0_4_;
  fVar19 = fVar15 * fVar43;
  fVar20 = auVar23._0_4_;
  uVar13 = CONCAT44(fVar25 + *(float *)(lVar11 + 0xcf0) *
                             ((float)uVar1 * 2.3283064e-10 * 2.0 + -1.0),
                    fVar41 + fVar48 * ((float)uVar4 * 2.3283064e-10 * 2.0 + -1.0));
  fVar28 = *(float *)(lVar11 + 0xce8);
  *(uint *)(param_1 + 0x4a4) = uVar2 * 0x41c64e6d + 0x3039;
  fVar42 = *(float *)(lVar11 + 0xd10);
  fVar24 = fVar15 * fVar20 * -1.0 + fVar12 * auVar18._4_4_ * auVar18._0_4_;
  fVar26 = fVar12 * fVar20 * 1.0 + fVar15 * auVar18._4_4_ * auVar18._0_4_;
  fVar27 = fVar20 * 0.0 * 0.0 + fVar43 * 1.0 * auVar18._0_4_;
  fVar29 = fVar20 * 0.0 * 0.0 + auVar18._0_4_ * 0.0;
  fVar30 = *(float *)(lVar11 + 0xd14);
  fVar41 = fVar15 * auVar18._0_4_ * 1.0 + fVar12 * auVar18._4_4_ * fVar20;
  fVar15 = fVar12 * auVar18._0_4_ * -1.0 + fVar15 * auVar18._4_4_ * fVar20;
  fVar25 = auVar18._0_4_ * 0.0 * 0.0 + fVar43 * 1.0 * fVar20;
  fVar20 = auVar18._0_4_ * 0.0 * 0.0 + fVar20 * 0.0;
  fVar31 = *(float *)(lVar11 + 0xd18);
  uVar14 = (ulong)(uint)(fVar28 + *(float *)(lVar11 + 0xcf4) *
                                  ((float)uVar2 * 2.3283064e-10 * 2.0 + -1.0));
  *(ulong *)(param_1 + 0x188) = CONCAT44(fVar42 * 0.0,auVar18._4_4_ * -1.0 * fVar42);
  *(ulong *)(param_1 + 0x180) = CONCAT44(fVar19 * fVar42,fVar12 * fVar43 * fVar42);
  *(float *)(param_1 + 0x1a0) = fVar27 * fVar30;
  *(float *)(param_1 + 0x1a4) = fVar29 * fVar30;
  *(float *)(param_1 + 400) = fVar24 * fVar30;
  *(float *)(param_1 + 0x194) = fVar26 * fVar30;
  *(ulong *)(param_1 + 0x1a8) = CONCAT44(fVar20 * fVar31,fVar25 * fVar31);
  *(ulong *)(param_1 + 0x1a0) = CONCAT44(fVar15 * fVar31,fVar41 * fVar31);
  *(ulong *)(param_1 + 0x1b8) = uVar14;
  *(undefined8 *)(param_1 + 0x1b0) = uVar13;
  *(ulong *)(param_1 + 0x1c8) = (ulong)(uint)(auVar18._4_4_ * -1.0);
  *(ulong *)(param_1 + 0x1c0) =
       CONCAT17((char)((uint)fVar19 >> 0x18),
                CONCAT16((char)((uint)fVar19 >> 0x10),
                         CONCAT15((char)((uint)fVar19 >> 8),
                                  CONCAT14(SUB41(fVar19,0),fVar12 * fVar43))));
  *(float *)(param_1 + 0x1e0) = fVar27;
  *(float *)(param_1 + 0x1e4) = fVar29;
  *(float *)(param_1 + 0x1d0) = fVar24;
  *(float *)(param_1 + 0x1d4) = fVar26;
  *(float *)(param_1 + 0x1f0) = fVar25;
  *(float *)(param_1 + 500) = fVar20;
  *(float *)(param_1 + 0x1e0) = fVar41;
  *(float *)(param_1 + 0x1e4) = fVar15;
  *(ulong *)(param_1 + 0x1f8) = uVar14;
  *(undefined8 *)(param_1 + 0x1f0) = uVar13;
  return;
}



void FUN_71005c8cc8(long param_1,undefined8 param_2,ulong param_3)

{
  code *pcVar1;
  long lVar2;
  undefined8 uVar3;
  long local_40;
  undefined8 local_38;
  
  if ((param_3 & 1) != 0) {
    FUN_71005c88f0(param_1);
    local_40 = param_1;
    if ((*(long *)(param_1 + 0x370) != 0) &&
       (pcVar1 = *(code **)(*(long *)(param_1 + 0x370) + 0x38), pcVar1 != (code *)0x0)) {
      (*pcVar1)(&local_40);
    }
    local_38 = *(undefined8 *)(param_1 + 0x3b0);
    if ((*(long *)(param_1 + 0x378) != 0) &&
       (pcVar1 = *(code **)(*(long *)(param_1 + 0x378) + 0x38), pcVar1 != (code *)0x0)) {
      (*pcVar1)(&local_40);
    }
    if ((*(long *)(param_1 + 0x380) != 0) &&
       (pcVar1 = *(code **)(*(long *)(param_1 + 0x380) + 0x38), pcVar1 != (code *)0x0)) {
      (*pcVar1)(&local_40);
    }
    if ((*(long *)(param_1 + 0x388) != 0) &&
       (pcVar1 = *(code **)(*(long *)(param_1 + 0x388) + 0x38), pcVar1 != (code *)0x0)) {
      (*pcVar1)(&local_40);
    }
  }
  lVar2 = *(long *)(param_1 + 0x4b0);
  if (lVar2 != 0) {
    thunk_EXT_FUN_02e95df0(param_1 + 0x6d0);
    *(long *)(param_1 + 0x700) = *(long *)(param_1 + 0x700) + -1;
    (**(code **)(**(long **)(param_1 + 0x6f0) + 0x18))(*(long **)(param_1 + 0x6f0),lVar2);
    thunk_EXT_FUN_02e95df0(param_1 + 0x6d0);
    *(undefined8 *)(param_1 + 0x4b0) = 0;
  }
  if (*(long *)(param_1 + 0x4c0) != 0) {
    FUN_71005cefc0(*(long *)(param_1 + 0x658),*(long *)(param_1 + 0x4c0),0);
    *(undefined8 *)(param_1 + 0x4c0) = 0;
  }
  if (*(long *)(param_1 + 0x5d0) != 0) {
    FUN_71005cefc0(*(long *)(param_1 + 0x658),*(long *)(param_1 + 0x5d0),0);
    *(undefined8 *)(param_1 + 0x5d0) = 0;
  }
  if (*(long *)(param_1 + 0x5e0) != 0) {
    FUN_71005cefc0(*(long *)(param_1 + 0x658),*(long *)(param_1 + 0x5e0),0);
    *(undefined8 *)(param_1 + 0x5e0) = 0;
  }
  if (*(long *)(param_1 + 0x5f0) != 0) {
    FUN_71005cefc0(*(long *)(param_1 + 0x658),*(long *)(param_1 + 0x5f0),0);
    *(undefined8 *)(param_1 + 0x5f0) = 0;
  }
  if (*(long *)(param_1 + 0x600) != 0) {
    FUN_71005cefc0(*(long *)(param_1 + 0x658),*(long *)(param_1 + 0x600),0);
    *(undefined8 *)(param_1 + 0x600) = 0;
  }
  if (*(long *)(param_1 + 0x610) != 0) {
    FUN_71005cefc0(*(long *)(param_1 + 0x658),*(long *)(param_1 + 0x610),0);
    *(undefined8 *)(param_1 + 0x610) = 0;
  }
  if (*(long *)(param_1 + 0x620) != 0) {
    FUN_71005cefc0(*(long *)(param_1 + 0x658),*(long *)(param_1 + 0x620),0);
    *(undefined8 *)(param_1 + 0x620) = 0;
  }
  FUN_71005cf3ec((undefined1 *)(param_1 + 0x660),*(long *)(param_1 + 0x658));
  FUN_71005cf3ec((undefined1 *)(param_1 + 0x4d0),*(long *)(param_1 + 0x658));
  FUN_71005cf3ec((undefined1 *)(param_1 + 0x510),*(long *)(param_1 + 0x658));
  FUN_71005cf3ec((undefined1 *)(param_1 + 0x550),*(long *)(param_1 + 0x658));
  FUN_71005cf3ec((undefined1 *)(param_1 + 0x590),*(long *)(param_1 + 0x658));
  lVar2 = *(long *)(param_1 + 0x50);
  if (lVar2 != 0) {
    thunk_EXT_FUN_02e95df0(param_1 + 0x6d0);
    *(long *)(param_1 + 0x700) = *(long *)(param_1 + 0x700) + -1;
    (**(code **)(**(long **)(param_1 + 0x6f0) + 0x18))(*(long **)(param_1 + 0x6f0),lVar2);
    thunk_EXT_FUN_02e95df0(param_1 + 0x6d0);
    *(undefined8 *)(param_1 + 0x50) = 0;
  }
  lVar2 = *(long *)(param_1 + 0x58);
  if (lVar2 != 0) {
    thunk_EXT_FUN_02e95df0(param_1 + 0x6d0);
    *(long *)(param_1 + 0x700) = *(long *)(param_1 + 0x700) + -1;
    (**(code **)(**(long **)(param_1 + 0x6f0) + 0x18))(*(long **)(param_1 + 0x6f0),lVar2);
    thunk_EXT_FUN_02e95df0(param_1 + 0x6d0);
    *(undefined8 *)(param_1 + 0x58) = 0;
  }
  if (0 < *(int *)(param_1 + 0x308)) {
    uVar3 = *(undefined8 *)(param_1 + 0x300);
    *(undefined8 *)(param_1 + 0x300) = 0;
    *(undefined4 *)(param_1 + 0x308) = 0;
    thunk_EXT_FUN_02e95df0(param_1 + 0x6d0);
    *(long *)(param_1 + 0x700) = *(long *)(param_1 + 0x700) + -1;
    (**(code **)(**(long **)(param_1 + 0x6f0) + 0x18))(*(long **)(param_1 + 0x6f0),uVar3);
    thunk_EXT_FUN_02e95df0(param_1 + 0x6d0);
  }
  return;
}



void FUN_71005c8f5c(long *param_1,float *param_2)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  float fVar4;
  
  uVar1 = *(uint *)((long)param_1 + 0x4a4);
  iVar3 = *(int *)(param_1[9] + 0xd80);
  iVar2 = *(int *)(param_1[9] + 0xd84);
  *(uint *)((long)param_1 + 0x4a4) = uVar1 * 0x41c64e6d + 0x3039;
  fVar4 = (float)iVar3 + 1.0 + (float)(int)((ulong)uVar1 * (long)iVar2 >> 0x20);
  *param_2 = fVar4;
  fVar4 = *(float *)(param_1 + 0x1c) * fVar4;
  *param_2 = fVar4;
  *param_2 = *(float *)(*param_1 + 0x250) * fVar4;
  if (*(char *)(param_1[9] + 0xcc5) != '\0') {
    FUN_71005c8a00((long)param_1);
    return;
  }
  return;
}



undefined8 FUN_71005c8fd0(long param_1,char param_2)

{
  byte bVar1;
  uint uVar2;
  uint uVar3;
  
  if (param_2 == '\x02') {
    uVar3 = *(uint *)(param_1 + 0x30);
    if ((uVar3 & 0x180) == 0) {
      return 0;
    }
  }
  else {
    if (param_2 != '\x01') {
      return 0;
    }
    uVar3 = *(uint *)(param_1 + 0x30);
  }
  *(uint *)(param_1 + 0x30) = uVar3 & 0xfffffe7f;
  bVar1 = *(byte *)(param_1 + 0x710);
  uVar3 = *(byte *)(param_1 + 0x80) + 1;
  uVar2 = 0;
  if (bVar1 != 0) {
    uVar2 = uVar3 / bVar1;
  }
  uVar3 = uVar3 - uVar2 * bVar1;
  *(char *)(param_1 + 0x80) = (char)uVar3;
  *(ulong *)(param_1 + 0x68) = *(long *)(param_1 + 0x300) + (ulong)uVar3 * 0x60;
  return 1;
}



undefined8 FUN_71005c9038(long param_1)

{
  undefined8 uVar1;
  long lVar2;
  long lVar3;
  
  lVar2 = *(long *)(param_1 + 0x40);
  lVar3 = *(long *)(lVar2 + 0x10);
  if ((lVar3 == 0) || ((*(char *)(lVar3 + 0x50) == -1 && (*(char *)(lVar3 + 0xe) == -1)))) {
    uVar1 = 0;
    lVar3 = *(long *)(lVar2 + 0x18);
  }
  else {
    uVar1 = 1;
    lVar3 = *(long *)(lVar2 + 0x18);
  }
  if ((lVar3 != 0) && ((*(char *)(lVar3 + 0x50) != -1 || (*(char *)(lVar3 + 0xe) != -1)))) {
    uVar1 = 1;
  }
  lVar3 = *(long *)(lVar2 + 0x20);
  if ((lVar3 != 0) && ((*(char *)(lVar3 + 0x50) != -1 || (*(char *)(lVar3 + 0xe) != -1)))) {
    uVar1 = 1;
  }
  lVar3 = *(long *)(lVar2 + 0x28);
  if ((lVar3 != 0) && ((*(char *)(lVar3 + 0x50) != -1 || (*(char *)(lVar3 + 0xe) != -1)))) {
    uVar1 = 1;
  }
  lVar3 = *(long *)(lVar2 + 0x30);
  if ((lVar3 != 0) && ((*(char *)(lVar3 + 0x50) != -1 || (*(char *)(lVar3 + 0xe) != -1)))) {
    uVar1 = 1;
  }
  lVar3 = *(long *)(lVar2 + 0x38);
  if ((lVar3 != 0) && ((*(char *)(lVar3 + 0x50) != -1 || (*(char *)(lVar3 + 0xe) != -1)))) {
    uVar1 = 1;
  }
  lVar3 = *(long *)(lVar2 + 0x40);
  if ((lVar3 != 0) && ((*(char *)(lVar3 + 0x50) != -1 || (*(char *)(lVar3 + 0xe) != -1)))) {
    uVar1 = 1;
  }
  lVar2 = *(long *)(lVar2 + 0x48);
  if ((lVar2 != 0) && ((*(char *)(lVar2 + 0x50) != -1 || (*(char *)(lVar2 + 0xe) != -1)))) {
    uVar1 = 1;
  }
  return uVar1;
}



undefined8 FUN_71005c9170(long param_1)

{
  undefined8 uVar1;
  long lVar2;
  long lVar3;
  
  lVar2 = *(long *)(param_1 + 0x40);
  lVar3 = *(long *)(lVar2 + 0x10);
  if ((lVar3 == 0) || ((*(char *)(lVar3 + 0x51) == -1 && (*(char *)(lVar3 + 0xf) == -1)))) {
    uVar1 = 0;
    lVar3 = *(long *)(lVar2 + 0x18);
  }
  else {
    uVar1 = 1;
    lVar3 = *(long *)(lVar2 + 0x18);
  }
  if ((lVar3 != 0) && ((*(char *)(lVar3 + 0x51) != -1 || (*(char *)(lVar3 + 0xf) != -1)))) {
    uVar1 = 1;
  }
  lVar3 = *(long *)(lVar2 + 0x20);
  if ((lVar3 != 0) && ((*(char *)(lVar3 + 0x51) != -1 || (*(char *)(lVar3 + 0xf) != -1)))) {
    uVar1 = 1;
  }
  lVar3 = *(long *)(lVar2 + 0x28);
  if ((lVar3 != 0) && ((*(char *)(lVar3 + 0x51) != -1 || (*(char *)(lVar3 + 0xf) != -1)))) {
    uVar1 = 1;
  }
  lVar3 = *(long *)(lVar2 + 0x30);
  if ((lVar3 != 0) && ((*(char *)(lVar3 + 0x51) != -1 || (*(char *)(lVar3 + 0xf) != -1)))) {
    uVar1 = 1;
  }
  lVar3 = *(long *)(lVar2 + 0x38);
  if ((lVar3 != 0) && ((*(char *)(lVar3 + 0x51) != -1 || (*(char *)(lVar3 + 0xf) != -1)))) {
    uVar1 = 1;
  }
  lVar3 = *(long *)(lVar2 + 0x40);
  if ((lVar3 != 0) && ((*(char *)(lVar3 + 0x51) != -1 || (*(char *)(lVar3 + 0xf) != -1)))) {
    uVar1 = 1;
  }
  lVar2 = *(long *)(lVar2 + 0x48);
  if ((lVar2 != 0) && ((*(char *)(lVar2 + 0x51) != -1 || (*(char *)(lVar2 + 0xf) != -1)))) {
    uVar1 = 1;
  }
  return uVar1;
}



void FUN_71005c92a8(long param_1,undefined4 param_2)

{
  *(undefined4 *)(param_1 + 0x38) = param_2;
  return;
}



bool FUN_71005c92b0(long *param_1)

{
  long lVar1;
  
  lVar1 = *param_1;
  if ((*(char *)(lVar1 + 0x38) < '\0') &&
     ((*(int *)(lVar1 + 0x60) < 0 ||
      (*(float *)(param_1 + 0x15) + (float)*(int *)(lVar1 + 0x240) + (float)*(int *)(lVar1 + 0x60) <
       *(float *)(param_1 + 5))))) {
    return (*(byte *)((long)param_1 + 0x31) & 0x40) == 0 || (int)param_1[0x14] < 1;
  }
  return false;
}



float FUN_71005c9308(long param_1)

{
  char cVar1;
  float fVar2;
  float fVar3;
  
  fVar3 = *(float *)(param_1 + 0x7c);
  fVar2 = 1.0;
  if ((fVar3 < 1.0) &&
     (cVar1 = *(char *)(*(long *)(param_1 + 0x48) + 0xcc9), 0.0 <= fVar3 && cVar1 != '\0')) {
    if (cVar1 == '\x01') {
      return fVar3;
    }
    if (cVar1 == '\x03') {
      fVar2 = fVar3 * fVar3 * fVar3 * fVar3;
    }
    else if (cVar1 == '\x02') {
      return fVar3 * fVar3;
    }
  }
  return fVar2;
}



float FUN_71005c9360(long param_1)

{
  char cVar1;
  float fVar2;
  float fVar3;
  
  fVar3 = *(float *)(param_1 + 0x78);
  fVar2 = 1.0;
  if ((fVar3 < 1.0) &&
     (cVar1 = *(char *)(*(long *)(param_1 + 0x48) + 0xccb), 0.0 <= fVar3 && cVar1 != '\0')) {
    if (cVar1 == '\x01') {
      return fVar3;
    }
    if (cVar1 == '\x03') {
      fVar2 = fVar3 * fVar3 * fVar3 * fVar3;
    }
    else if (cVar1 == '\x02') {
      return fVar3 * fVar3;
    }
  }
  return fVar2;
}



bool FUN_71005c93b8(long param_1)

{
  uint uVar1;
  char cVar2;
  int iVar3;
  float fVar4;
  
  uVar1 = *(uint *)(param_1 + 0x30);
  cVar2 = *(char *)(*(long *)(param_1 + 0x40) + 0xe6);
  fVar4 = *(float *)(param_1 + 0xa8) + (float)*(int *)(*(long *)(param_1 + 0x40) + 0xf0);
  if (cVar2 == '\x03') {
    iVar3 = FUN_71005ef1b0(param_1);
  }
  else {
    if (cVar2 != '\x02') goto LAB_71005c9414;
    iVar3 = FUN_71005ebb88(param_1);
  }
  fVar4 = fVar4 + (float)iVar3;
LAB_71005c9414:
  return (uVar1 & 2) == 0 ||
         fVar4 < *(float *)(param_1 + 0x28) - *(float *)(param_1 + 0x2c) &&
         (*(byte *)(param_1 + 0x32) & 8) == 0;
}



float FUN_71005c9448(long param_1)

{
  long lVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  
  fVar4 = *(float *)(param_1 + 0x7c);
  fVar2 = 1.0;
  fVar3 = 1.0;
  lVar1 = *(long *)(param_1 + 0x48);
  if ((fVar4 < 1.0) && (fVar3 = 1.0, 0.0 <= fVar4 && *(char *)(lVar1 + 0xcca) != '\0')) {
    fVar3 = *(float *)(lVar1 + 0xd48) + (1.0 - *(float *)(lVar1 + 0xd48)) * fVar4;
  }
  fVar4 = *(float *)(param_1 + 0x78);
  if ((fVar4 < 1.0) && (0.0 <= fVar4 && *(char *)(lVar1 + 0xccc) != '\0')) {
    fVar2 = *(float *)(lVar1 + 0xd4c) + (1.0 - *(float *)(lVar1 + 0xd4c)) * fVar4;
  }
  return fVar3 * fVar2;
}



float FUN_71005c94b8(long param_1)

{
  char cVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  
  fVar4 = *(float *)(param_1 + 0x7c);
  fVar2 = 1.0;
  fVar3 = 1.0;
  if (fVar4 < 1.0) {
    cVar1 = *(char *)(*(long *)(param_1 + 0x48) + 0xcc9);
    fVar3 = 1.0;
    if (0.0 <= fVar4 && cVar1 != '\0') {
      if (cVar1 == '\x01') {
        fVar5 = *(float *)(param_1 + 0x78);
        fVar2 = fVar4;
        goto joined_r0x0071005c9508;
      }
      if (cVar1 != '\x03') {
        if (cVar1 == '\x02') {
          fVar5 = *(float *)(param_1 + 0x78);
          fVar2 = fVar4 * fVar4;
        }
        else {
          fVar5 = *(float *)(param_1 + 0x78);
        }
        goto joined_r0x0071005c9508;
      }
      fVar3 = fVar4 * fVar4 * fVar4 * fVar4;
    }
  }
  fVar5 = *(float *)(param_1 + 0x78);
  fVar2 = fVar3;
joined_r0x0071005c9508:
  if ((fVar5 < 1.0) &&
     (cVar1 = *(char *)(*(long *)(param_1 + 0x48) + 0xccb), 0.0 <= fVar5 && cVar1 != '\0')) {
    if (cVar1 == '\x01') {
      return fVar2 * fVar5;
    }
    if (cVar1 == '\x03') {
      return fVar2 * fVar5 * fVar5 * fVar5 * fVar5;
    }
    if (cVar1 == '\x02') {
      return fVar2 * fVar5 * fVar5;
    }
  }
  return fVar2 * 1.0;
}



ulong FUN_71005c959c(long param_1)

{
  char cVar1;
  
  cVar1 = *(char *)(*(long *)(param_1 + 0x40) + 0xe6);
  if ((cVar1 != '\x03') && (cVar1 != '\x02')) {
    return (ulong)*(uint *)(param_1 + 0x4cc);
  }
  return (ulong)*(uint *)(*(long *)(param_1 + 0x3a8) + 0x2c) + (ulong)*(uint *)(param_1 + 0x4cc);
}



undefined8 FUN_71005c95d4(long *param_1)

{
  return *(undefined8 *)(*param_1 + 0x68);
}



undefined8 FUN_71005c95e0(long param_1)

{
  byte bVar1;
  
  bVar1 = *(byte *)(*(long *)(param_1 + 0x48) + 0xdb0);
  if ((bVar1 < 0xe && (1 << (ulong)(bVar1 & 0x1f) & 0x2064U) != 0) &&
     (*(int *)(*(long *)(param_1 + 0x48) + 0xdec) == 0)) {
    return 1;
  }
  return 0;
}



void FUN_71005c961c(long *param_1,long param_2,uint param_3,undefined8 param_4,long *param_5,
                   char *param_6,long param_7,int *param_8)

{
  int local_50 [3];
  undefined2 local_44;
  
  if ((((*(byte *)((long)param_1 + 0x32) & 1) != 0) && (*(char *)(param_7 + 0x11) == '\0')) &&
     (*(char *)(param_7 + 0x10) != '\0')) {
    local_50[0] = -1;
    local_50[1] = -1;
    local_50[2] = 0xffffffff;
    local_44 = 0x100;
    FUN_71005cfc34((long *)param_1[0xe1],param_2,param_1,*(long **)(param_1[8] + 0x50),0,
                   *(int *)(*param_1 + 0x3c),param_3 & 1,param_4,1,param_5,local_50,(undefined *)0x0
                  );
  }
  if (*param_6 != '\0') {
    FUN_71005d0378((long *)param_1[0xe1],param_2,param_1,param_4,param_5,param_8);
  }
  return;
}



undefined8
FUN_71005c97d0(float param_1,long param_2,long *param_3,uint *param_4,undefined1 param_5,int param_6
              ,long param_7)

{
  undefined1 (*pauVar1) [12];
  long lVar2;
  long *plVar3;
  undefined4 *puVar4;
  undefined4 *puVar5;
  float fVar6;
  char cVar7;
  undefined1 auVar8 [16];
  float *pfVar9;
  int iVar10;
  ulong uVar11;
  long lVar12;
  long lVar13;
  long lVar14;
  float fVar15;
  float fVar17;
  undefined8 uVar16;
  undefined8 uVar18;
  float fVar19;
  float fVar20;
  float fVar21;
  float fVar22;
  undefined4 uVar23;
  undefined8 uVar24;
  float fVar25;
  undefined8 uVar26;
  float fVar27;
  undefined1 auVar28 [16];
  undefined1 auStack_38 [4];
  undefined1 auStack_34 [4];
  undefined1 auStack_18 [4];
  undefined1 auStack_14 [4];
  
  iVar10 = *(int *)(*(long *)(param_2 + 0x4a8) + 0x40);
  if (iVar10 < *(int *)(param_2 + 0x90)) {
    FUN_71005dee10();
    *param_3 = 0;
    *param_4 = 0;
    return 0;
  }
  *param_3 = *(long *)(*(long *)(param_2 + 0x4a8) + 8) + (long)(iVar10 * param_6) * 8;
  *param_4 = 0;
  plVar3 = *(long **)(param_2 + 0x68);
  if ((*(byte *)(param_2 + 0x31) & 0x40) != 0) {
    plVar3 = (long *)(param_2 + 0x310);
  }
  switch(param_5) {
  case 1:
    iVar10 = *(int *)(param_2 + 0x90);
    if (iVar10 < 1) {
      uVar11 = 0;
    }
    else {
      lVar12 = 0;
      uVar11 = 0;
      lVar13 = 0;
      lVar14 = 0xc;
      do {
        lVar2 = *(long *)(param_2 + 0x60) + lVar12;
        if (param_1 - *(float *)(lVar2 + 8) < *(float *)(lVar2 + 0xc)) {
          *(undefined4 *)(*param_3 + (-(uVar11 >> 0x1f) & 0xfffffff800000000 | uVar11 << 3)) =
               *(undefined4 *)(plVar3[1] + lVar14);
          *(int *)(*param_3 + (long)(int)*param_4 * 8 + 4) = (int)lVar13;
          uVar11 = (ulong)(*param_4 + 1);
          *param_4 = *param_4 + 1;
          iVar10 = *(int *)(param_2 + 0x90);
        }
        lVar13 = lVar13 + 1;
        lVar14 = lVar14 + 0x10;
        lVar12 = lVar12 + 0x20;
      } while (lVar13 < iVar10);
    }
    iVar10 = (int)uVar11;
    lVar13 = 0;
    if (iVar10 != 0) {
      lVar13 = LZCOUNT((long)iVar10) * -2 + 0x7e;
    }
    FUN_71005cb420((float *)*param_3,(float *)*param_3 + (long)iVar10 * 2,auStack_34,lVar13,1);
    return 1;
  case 2:
    break;
  case 3:
    iVar10 = *(int *)(param_2 + 0x90);
    if (iVar10 < 1) {
      uVar11 = 0;
    }
    else {
      lVar12 = 0;
      uVar11 = 0;
      lVar13 = 0;
      lVar14 = 0xc;
      do {
        lVar2 = *(long *)(param_2 + 0x60) + lVar12;
        if (param_1 - *(float *)(lVar2 + 8) < *(float *)(lVar2 + 0xc)) {
          *(undefined4 *)(*param_3 + (-(uVar11 >> 0x1f) & 0xfffffff800000000 | uVar11 << 3)) =
               *(undefined4 *)(plVar3[1] + lVar14);
          *(int *)(*param_3 + (long)(int)*param_4 * 8 + 4) = (int)lVar13;
          uVar11 = (ulong)(*param_4 + 1);
          *param_4 = *param_4 + 1;
          iVar10 = *(int *)(param_2 + 0x90);
        }
        lVar13 = lVar13 + 1;
        lVar14 = lVar14 + 0x10;
        lVar12 = lVar12 + 0x20;
      } while (lVar13 < iVar10);
    }
    iVar10 = (int)uVar11;
    lVar13 = 0;
    if (iVar10 != 0) {
      lVar13 = LZCOUNT((long)iVar10) * -2 + 0x7e;
    }
    FUN_71005ca3c0((float *)*param_3,(float *)*param_3 + (long)iVar10 * 2,auStack_38,lVar13,1);
    return 1;
  case 4:
    if (*(code **)(param_2 + 0x3d0) == (code *)0x0) {
      FUN_71005dee10();
      return 0;
    }
    (**(code **)(param_2 + 0x3d0))(param_3,param_4,param_2,param_7);
  default:
    return 1;
  }
  iVar10 = *(int *)(param_2 + 0x90);
  if (iVar10 < 1) {
    uVar11 = 0;
  }
  else {
    lVar12 = 0;
    lVar14 = 0;
    uVar11 = 0;
    lVar13 = 0;
    do {
      lVar2 = *(long *)(param_2 + 0x60) + lVar12;
      if (param_1 - *(float *)(lVar2 + 8) < *(float *)(lVar2 + 0xc)) {
        cVar7 = *(char *)(*(long *)(param_2 + 0x48) + 0xcc3);
        uVar16 = *(undefined8 *)(*plVar3 + lVar14);
        fVar6 = *(float *)((undefined8 *)(*plVar3 + lVar14) + 1);
        if (cVar7 == '\0') {
LAB_71005c9930:
          fVar19 = (float)*(undefined8 *)(param_2 + 0x108);
          uVar18 = *(undefined8 *)(param_2 + 0x100);
          fVar25 = (float)*(undefined8 *)(param_2 + 0x118);
          uVar24 = *(undefined8 *)(param_2 + 0x110);
          fVar27 = (float)*(undefined8 *)(param_2 + 0x128);
          uVar26 = *(undefined8 *)(param_2 + 0x120);
          fVar22 = (float)*(undefined8 *)(param_2 + 0x138);
          fVar20 = (float)*(undefined8 *)(param_2 + 0x130);
          fVar21 = (float)((ulong)*(undefined8 *)(param_2 + 0x130) >> 0x20);
        }
        else {
          puVar4 = (undefined4 *)0x0;
          if (*(long *)(param_2 + 0x350) != 0) {
            puVar4 = (undefined4 *)(*(long *)(param_2 + 0x350) + lVar14);
          }
          puVar5 = (undefined4 *)0x0;
          if (*(long *)(param_2 + 0x358) != 0) {
            puVar5 = (undefined4 *)(*(long *)(param_2 + 0x358) + lVar14);
          }
          pfVar9 = (float *)0x0;
          if (*(long *)(param_2 + 0x360) != 0) {
            pfVar9 = (float *)(*(long *)(param_2 + 0x360) + lVar14);
          }
          if (((puVar4 == (undefined4 *)0x0) || (puVar5 == (undefined4 *)0x0)) ||
             (pfVar9 == (float *)0x0)) goto LAB_71005c9930;
          if (cVar7 == '\x02') {
            pauVar1 = (undefined1 (*) [12])(param_2 + 0x130);
            uVar23 = (undefined4)((ulong)*(undefined8 *)(param_2 + 0x138) >> 0x20);
            fVar20 = (float)*(undefined8 *)*pauVar1;
            fVar21 = (float)((ulong)*(undefined8 *)*pauVar1 >> 0x20);
            auVar28._12_4_ = uVar23;
            auVar28._0_12_ = *pauVar1;
            auVar8._12_4_ = uVar23;
            auVar8._0_12_ = *pauVar1;
            auVar28 = NEON_ext(auVar28,auVar8,8,1);
            uVar18 = CONCAT44(*puVar5,*puVar4);
            fVar19 = *pfVar9;
            fVar22 = auVar28._0_4_;
            uVar26 = CONCAT44(puVar5[2],puVar4[2]);
            uVar24 = CONCAT44(puVar5[1],puVar4[1]);
            fVar27 = pfVar9[2];
            fVar25 = pfVar9[1];
          }
          else {
            uVar18 = CONCAT44(*puVar5,*puVar4);
            fVar19 = *pfVar9;
            fVar20 = (float)puVar4[3];
            uVar26 = CONCAT44(puVar5[2],puVar4[2]);
            fVar21 = (float)puVar5[3];
            uVar24 = CONCAT44(puVar5[1],puVar4[1]);
            fVar22 = pfVar9[3];
            fVar27 = pfVar9[2];
            fVar25 = pfVar9[1];
          }
        }
        fVar15 = (float)uVar16;
        fVar17 = (float)((ulong)uVar16 >> 0x20);
        *(float *)(*param_3 + (-(uVar11 >> 0x1f) & 0xfffffff800000000 | uVar11 << 3)) =
             *(float *)(param_7 + 0x2c) +
             *(float *)(param_7 + 0x24) *
             (fVar21 + (float)((ulong)uVar18 >> 0x20) * fVar15 +
                       (float)((ulong)uVar24 >> 0x20) * fVar17 +
                       (float)((ulong)uVar26 >> 0x20) * fVar6) +
             *(float *)(param_7 + 0x20) *
             (fVar20 + (float)uVar18 * fVar15 + (float)uVar24 * fVar17 + (float)uVar26 * fVar6) +
             *(float *)(param_7 + 0x28) *
             (fVar22 + fVar19 * fVar15 + fVar25 * fVar17 + fVar27 * fVar6);
        *(int *)(*param_3 + (long)(int)*param_4 * 8 + 4) = (int)lVar13;
        uVar11 = (ulong)(*param_4 + 1);
        *param_4 = *param_4 + 1;
        iVar10 = *(int *)(param_2 + 0x90);
      }
      lVar13 = lVar13 + 1;
      lVar14 = lVar14 + 0x10;
      lVar12 = lVar12 + 0x20;
    } while (lVar13 < iVar10);
  }
  pfVar9 = (float *)*param_3;
  iVar10 = (int)uVar11;
  lVar13 = 0;
  if (iVar10 != 0) {
    lVar13 = LZCOUNT((long)iVar10) * -2 + 0x7e;
  }
  if (*(char *)(*(long *)(param_2 + 0x48) + 0xe0b) != '\0') {
    FUN_71005cc480(pfVar9,pfVar9 + (long)iVar10 * 2,auStack_18,lVar13,1);
    return 1;
  }
  FUN_71005cd7e0(pfVar9,pfVar9 + (long)iVar10 * 2,auStack_14,lVar13,1);
  return 1;
}



void FUN_71005c9cb4(long param_1,long param_2)

{
  uint uVar1;
  long lVar2;
  
  lVar2 = *(long *)(param_1 + 0x4a8);
  uVar1 = 0;
  if ((long)*(int *)(lVar2 + 0x40) != 0) {
    uVar1 = (uint)((param_2 - *(long *)(lVar2 + 8) >> 3) / (long)*(int *)(lVar2 + 0x40));
  }
  thunk_EXT_FUN_02e95df0(lVar2 + 0x18);
  *(uint *)(lVar2 + 0x38) = *(uint *)(lVar2 + 0x38) & (1 << (ulong)(uVar1 & 0x1f) ^ 0xffffffffU);
  thunk_EXT_FUN_02e95df0(lVar2 + 0x18);
  return;
}



undefined8 FUN_71005c9d10(long *param_1,long param_2,byte param_3,undefined8 param_4,long param_5)

{
  int iVar1;
  uint uVar2;
  ulong uVar3;
  code *pcVar4;
  uint *puVar5;
  undefined8 uVar6;
  long lVar7;
  long lVar8;
  long local_58;
  long *local_50;
  undefined8 local_48;
  long lStack_40;
  byte local_38;
  undefined1 local_37;
  
  local_37 = param_3 == 8;
  lVar8 = *(long *)(*param_1 + 0x68);
  if (lVar8 != 0) {
    iVar1 = *(int *)(param_5 + 0x20);
    if (param_3 == 8) {
      uVar6 = 0;
    }
    else {
      uVar6 = *(undefined8 *)(param_1[8] + (ulong)param_3 * 8 + 0x10);
    }
    *(undefined8 *)(*(long *)(lVar8 + 0x98) + (long)iVar1 * 0x828 + 0x800) = uVar6;
    *(undefined1 *)(*(long *)(lVar8 + 0x98) + (long)iVar1 * 0x828 + 0x820) = 10;
  }
  local_58 = param_2;
  local_50 = param_1;
  local_48 = param_4;
  lStack_40 = param_5;
  local_38 = param_3;
  if ((((*(code **)(lVar8 + 0x9a8) != (code *)0x0) &&
       (uVar3 = (**(code **)(lVar8 + 0x9a8))(&local_58), (uVar3 & 1) == 0)) ||
      ((param_1[0x6e] != 0 &&
       ((pcVar4 = *(code **)(param_1[0x6e] + 0x58), pcVar4 != (code *)0x0 &&
        (uVar3 = (*pcVar4)(&local_58), (uVar3 & 1) == 0)))))) ||
     ((param_1[0x70] != 0 &&
      ((pcVar4 = *(code **)(param_1[0x70] + 0x58), pcVar4 != (code *)0x0 &&
       (uVar3 = (*pcVar4)(&local_58), (uVar3 & 1) == 0)))))) {
    return 0;
  }
  if ((param_1[0x71] == 0) || (pcVar4 = *(code **)(param_1[0x71] + 0x58), pcVar4 == (code *)0x0)) {
    if (*(long *)(local_50[8] + 0x498) != 0) {
      FUN_71005c6680(&local_58);
    }
  }
  else {
    uVar3 = (*pcVar4)(&local_58);
    if ((uVar3 & 1) == 0) {
      return 0;
    }
  }
  uVar2 = 1 << (ulong)(*(uint *)(param_1 + 7) & 0x1f);
  puVar5 = (uint *)param_1[0x72];
  if ((*puVar5 & uVar2) == 0) {
    if ((puVar5[1] & uVar2) == 0) {
      if ((puVar5[2] & uVar2) == 0) {
        if ((puVar5[3] & uVar2) == 0) {
          if ((puVar5[4] & uVar2) == 0) {
            if ((puVar5[5] & uVar2) == 0) {
              if ((puVar5[6] & uVar2) == 0) {
                if ((puVar5[7] & uVar2) == 0) goto LAB_71005c9eec;
                lVar7 = 7;
              }
              else {
                lVar7 = 6;
              }
            }
            else {
              lVar7 = 5;
            }
          }
          else {
            lVar7 = 4;
          }
        }
        else {
          lVar7 = 3;
        }
      }
      else {
        lVar7 = 2;
      }
    }
    else {
      lVar7 = 1;
    }
  }
  else {
    lVar7 = 0;
  }
  if (*(code **)(puVar5 + lVar7 * 2 + 8) != (code *)0x0) {
    (**(code **)(puVar5 + lVar7 * 2 + 8))(&local_58);
  }
LAB_71005c9eec:
  iVar1 = *(int *)(param_5 + 0x20);
  *(undefined8 *)(*(long *)(lVar8 + 0x98) + (long)iVar1 * 0x828 + 0x800) = 0;
  *(undefined1 *)(*(long *)(lVar8 + 0x98) + (long)iVar1 * 0x828 + 0x820) = 10;
  return 1;
}



void FUN_71005c9f28(long param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)

{
  code *pcVar1;
  undefined8 local_40;
  long lStack_38;
  undefined8 local_30;
  undefined8 uStack_28;
  
  local_40 = param_2;
  lStack_38 = param_1;
  local_30 = param_3;
  uStack_28 = param_4;
  if ((*(long *)(param_1 + 0x370) != 0) &&
     (pcVar1 = *(code **)(*(long *)(param_1 + 0x370) + 0x60), pcVar1 != (code *)0x0)) {
    (*pcVar1)(&local_40);
  }
  if ((*(long *)(param_1 + 0x380) != 0) &&
     (pcVar1 = *(code **)(*(long *)(param_1 + 0x380) + 0x60), pcVar1 != (code *)0x0)) {
    (*pcVar1)(&local_40);
  }
  if ((*(long *)(param_1 + 0x388) != 0) &&
     (pcVar1 = *(code **)(*(long *)(param_1 + 0x388) + 0x60), pcVar1 != (code *)0x0)) {
    (*pcVar1)(&local_40);
  }
  return;
}



void FUN_71005c9f9c(undefined4 param_1,undefined4 param_2,long param_3,int param_4)

{
  code *pcVar1;
  long lVar2;
  undefined8 local_50;
  undefined8 local_48;
  
  branch_71005E43E0_0x71005e3d20(param_1,param_2,&local_50,param_3,param_4);
  lVar2 = *(long *)(param_3 + 0x60) + (long)param_4 * 0x20;
  local_50 = *(undefined8 *)(lVar2 + 0x10);
  local_48 = *(undefined8 *)(lVar2 + 0x18);
  if ((*(long *)(param_3 + 0x370) != 0) &&
     (pcVar1 = *(code **)(*(long *)(param_3 + 0x370) + 0x48), pcVar1 != (code *)0x0)) {
    (*pcVar1)(&local_50);
  }
  if ((*(long *)(param_3 + 0x378) != 0) &&
     (pcVar1 = *(code **)(*(long *)(param_3 + 0x378) + 0x48), pcVar1 != (code *)0x0)) {
    (*pcVar1)(&local_50);
  }
  if ((*(long *)(param_3 + 0x380) != 0) &&
     (pcVar1 = *(code **)(*(long *)(param_3 + 0x380) + 0x48), pcVar1 != (code *)0x0)) {
    (*pcVar1)(&local_50);
  }
  if ((*(long *)(param_3 + 0x388) != 0) &&
     (pcVar1 = *(code **)(*(long *)(param_3 + 0x388) + 0x48), pcVar1 != (code *)0x0)) {
    (*pcVar1)(&local_50);
  }
  lVar2 = (long)param_4 * 0x20;
  *(undefined8 *)(*(long *)(param_3 + 0x60) + lVar2 + 0x18) = 0;
  *(undefined8 *)(*(long *)(param_3 + 0x60) + lVar2 + 0x10) = 0;
  return;
}



void FUN_71005ca070(undefined4 param_1,long param_2,int param_3,long param_4,undefined4 param_5,
                   undefined4 param_6)

{
  uint uVar1;
  int iVar2;
  long lVar3;
  code *pcVar4;
  long lVar5;
  long lVar6;
  long lVar7;
  float fVar8;
  float fVar9;
  undefined8 local_78;
  undefined8 local_70;
  undefined8 local_60;
  
  lVar7 = (long)param_3;
  fVar9 = *(float *)(*(long *)(param_2 + 0x60) + lVar7 * 0x20 + 0xc);
  FUN_71005e4394(0,fVar9,param_1,&local_78,param_2,param_3,param_5,param_6,param_4);
  if (param_4 == 0) {
    local_78 = 0;
    lVar3 = *(long *)(param_2 + 0x370);
  }
  else {
    local_78 = *(undefined8 *)(param_4 + 0x50);
    lVar3 = *(long *)(param_2 + 0x370);
  }
  if ((lVar3 == 0) || (*(code **)(lVar3 + 0x40) == (code *)0x0)) {
    uVar1 = 0;
    local_60 = *(undefined8 *)(param_2 + 0x3b0);
    lVar3 = *(long *)(param_2 + 0x378);
  }
  else {
    uVar1 = (**(code **)(lVar3 + 0x40))(&local_78);
    uVar1 = uVar1 ^ 1;
    local_60 = *(undefined8 *)(param_2 + 0x3b0);
    lVar3 = *(long *)(param_2 + 0x378);
  }
  if ((lVar3 != 0) && (*(code **)(lVar3 + 0x40) != (code *)0x0)) {
    uVar1 = (**(code **)(lVar3 + 0x40))(&local_78);
    uVar1 = uVar1 ^ 1;
  }
  if ((*(long *)(param_2 + 0x380) != 0) &&
     (pcVar4 = *(code **)(*(long *)(param_2 + 0x380) + 0x40), pcVar4 != (code *)0x0)) {
    uVar1 = (*pcVar4)(&local_78);
    uVar1 = uVar1 ^ 1;
  }
  if ((*(long *)(param_2 + 0x388) != 0) &&
     (pcVar4 = *(code **)(*(long *)(param_2 + 0x388) + 0x40), pcVar4 != (code *)0x0)) {
    uVar1 = (*pcVar4)(&local_78);
    uVar1 = uVar1 ^ 1;
  }
  *(undefined8 *)(*(long *)(param_2 + 0x60) + lVar7 * 0x20 + 0x18) = local_70;
  *(undefined8 *)(*(long *)(param_2 + 0x60) + lVar7 * 0x20 + 0x10) = local_78;
  fVar8 = (float)FUN_71005e3d4c((long)&local_78);
  fVar9 = fVar9 * fVar8;
  fVar8 = 1.0;
  if (0 < (int)fVar9) {
    fVar8 = fVar9;
  }
  fVar9 = 0.0;
  if ((uVar1 & 1) == 0) {
    fVar9 = fVar8;
  }
  if (*(long *)(param_2 + 0x60) != 0) {
    *(float *)(*(long *)(param_2 + 0x60) + lVar7 * 0x20 + 0xc) = fVar9;
  }
  if (*(long *)(param_2 + 0x310) != 0) {
    *(float *)(*(long *)(param_2 + 0x310) + lVar7 * 0x10 + 0xc) = fVar9;
  }
  iVar2 = *(int *)(param_2 + 0x308);
  if (0 < iVar2) {
    lVar5 = 0;
    lVar3 = 0;
    do {
      lVar6 = *(long *)(*(long *)(param_2 + 0x300) + lVar5);
      if (lVar6 != 0) {
        *(float *)(lVar6 + lVar7 * 0x10 + 0xc) = fVar9;
        iVar2 = *(int *)(param_2 + 0x308);
      }
      lVar3 = lVar3 + 1;
      lVar5 = lVar5 + 0x60;
    } while (lVar3 < iVar2);
  }
  return;
}



void FUN_71005ca244(undefined4 param_1,undefined4 param_2,long param_3,int param_4)

{
  long lVar1;
  code *pcVar2;
  undefined8 local_50;
  undefined8 local_48;
  
  branch_71005E3D1C_0x71005e3d20(param_1,param_2,&local_50,param_3,param_4);
  lVar1 = *(long *)(param_3 + 0x60) + (long)param_4 * 0x20;
  local_50 = *(undefined8 *)(lVar1 + 0x10);
  local_48 = *(undefined8 *)(lVar1 + 0x18);
  if ((*(long *)(param_3 + 0x370) != 0) &&
     (pcVar2 = *(code **)(*(long *)(param_3 + 0x370) + 0x50), pcVar2 != (code *)0x0)) {
    (*pcVar2)(&local_50);
  }
  if ((*(long *)(param_3 + 0x378) != 0) &&
     (pcVar2 = *(code **)(*(long *)(param_3 + 0x378) + 0x50), pcVar2 != (code *)0x0)) {
    (*pcVar2)(&local_50);
  }
  if ((*(long *)(param_3 + 0x380) != 0) &&
     (pcVar2 = *(code **)(*(long *)(param_3 + 0x380) + 0x50), pcVar2 != (code *)0x0)) {
    (*pcVar2)(&local_50);
  }
  if ((*(long *)(param_3 + 0x388) != 0) &&
     (pcVar2 = *(code **)(*(long *)(param_3 + 0x388) + 0x50), pcVar2 != (code *)0x0)) {
    (*pcVar2)(&local_50);
  }
  *(undefined8 *)(*(long *)(param_3 + 0x60) + (long)param_4 * 0x20 + 0x10) = local_50;
  return;
}



undefined8
FUN_71005ca308(long param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
              undefined8 param_5)

{
  ulong uVar1;
  code *pcVar2;
  undefined8 local_40;
  undefined8 uStack_38;
  undefined8 local_30;
  undefined8 uStack_28;
  
  local_40 = param_2;
  uStack_38 = param_3;
  local_30 = param_4;
  uStack_28 = param_5;
  if (((((*(long *)(param_1 + 0x370) == 0) ||
        (pcVar2 = *(code **)(*(long *)(param_1 + 0x370) + 0x68), pcVar2 == (code *)0x0)) ||
       (uVar1 = (*pcVar2)(&local_40), (uVar1 & 1) != 0)) &&
      ((((*(long *)(param_1 + 0x378) == 0 ||
         (pcVar2 = *(code **)(*(long *)(param_1 + 0x378) + 0x68), pcVar2 == (code *)0x0)) ||
        (uVar1 = (*pcVar2)(&local_40), (uVar1 & 1) != 0)) &&
       (((*(long *)(param_1 + 0x380) == 0 ||
         (pcVar2 = *(code **)(*(long *)(param_1 + 0x380) + 0x68), pcVar2 == (code *)0x0)) ||
        (uVar1 = (*pcVar2)(&local_40), (uVar1 & 1) != 0)))))) &&
     (((*(long *)(param_1 + 0x388) == 0 ||
       (pcVar2 = *(code **)(*(long *)(param_1 + 0x388) + 0x68), pcVar2 == (code *)0x0)) ||
      (uVar1 = (*pcVar2)(&local_40), (uVar1 & 1) != 0)))) {
    return 1;
  }
  return 0;
}



void FUN_71005ca3c0(float *param_1,float *param_2,undefined8 param_3,long param_4,uint param_5)

{
  float *pfVar1;
  undefined8 uVar2;
  float fVar3;
  bool bVar4;
  bool bVar5;
  float *pfVar6;
  ulong extraout_x1;
  long lVar7;
  ulong uVar8;
  undefined8 uVar9;
  float *pfVar10;
  float *pfVar11;
  long lVar12;
  ulong uVar13;
  float fVar14;
  float fVar15;
  
LAB_71005ca3f0:
  pfVar10 = param_2 + -2;
  do {
    lVar7 = -param_4;
    pfVar11 = param_1;
    do {
      param_1 = pfVar11;
      lVar7 = lVar7 + 1;
      uVar8 = (long)param_2 - (long)param_1;
      uVar13 = (long)uVar8 >> 3;
      switch(uVar13) {
      case 0:
      case 1:
        goto switchD_71005ca5cc_caseD_0;
      case 2:
        if (*param_1 < param_2[-2]) {
          return;
        }
        if ((*param_1 <= param_2[-2]) && ((int)param_1[1] <= (int)param_2[-1])) {
          return;
        }
        uVar9 = *(undefined8 *)param_1;
        *(undefined8 *)param_1 = *(undefined8 *)(param_2 + -2);
        *(undefined8 *)(param_2 + -2) = uVar9;
        return;
      case 3:
        FUN_71005ca920(param_1,param_1 + 2,pfVar10);
        return;
      case 4:
        pfVar10 = param_1 + 4;
        FUN_71005ca920(param_1,param_1 + 2,pfVar10);
        if (param_1[4] < param_2[-2]) {
          return;
        }
        if ((param_1[4] <= param_2[-2]) && ((int)param_1[5] <= (int)param_2[-1])) {
          return;
        }
        uVar9 = *(undefined8 *)pfVar10;
        *(undefined8 *)pfVar10 = *(undefined8 *)(param_2 + -2);
        *(undefined8 *)(param_2 + -2) = uVar9;
        fVar14 = param_1[2];
        if (fVar14 < *pfVar10) {
          return;
        }
        if ((fVar14 <= *pfVar10) && ((int)param_1[3] <= (int)param_1[5])) {
          return;
        }
        uVar9 = *(undefined8 *)(param_1 + 2);
        uVar2 = *(undefined8 *)(param_1 + 4);
        *(undefined8 *)(param_1 + 2) = uVar2;
        *(undefined8 *)(param_1 + 4) = uVar9;
        if (*param_1 < (float)uVar2) {
          return;
        }
        if ((*param_1 == (float)uVar2) && ((int)param_1[1] <= (int)((ulong)uVar2 >> 0x20))) {
          return;
        }
        uVar9 = *(undefined8 *)param_1;
        *(undefined8 *)param_1 = uVar2;
        *(undefined8 *)(param_1 + 2) = uVar9;
        return;
      case 5:
        FUN_71005cafa0(param_1,param_1 + 2,param_1 + 4,param_1 + 6,pfVar10);
        return;
      }
      if ((long)uVar8 < 0xc0) {
        pfVar10 = param_1 + 2;
        if ((param_5 & 1) == 0) {
          if (param_1 == param_2 || pfVar10 == param_2) {
            return;
          }
          do {
            fVar14 = *pfVar10;
            if ((fVar14 <= *param_1) &&
               ((fVar3 = param_1[3], fVar14 < *param_1 || ((int)fVar3 < (int)param_1[1])))) {
              *(undefined8 *)pfVar10 = *(undefined8 *)param_1;
              fVar15 = param_1[-2];
              pfVar11 = param_1;
              while ((fVar14 <= fVar15 && ((fVar14 < fVar15 || ((int)fVar3 < (int)pfVar11[-1]))))) {
                fVar15 = pfVar11[-4];
                *(undefined8 *)pfVar11 = *(undefined8 *)(pfVar11 + -2);
                pfVar11 = pfVar11 + -2;
              }
              *pfVar11 = fVar14;
              pfVar11[1] = fVar3;
            }
            pfVar10 = pfVar10 + 2;
            param_1 = param_1 + 2;
          } while (pfVar10 != param_2);
          return;
        }
        if (param_1 == param_2 || pfVar10 == param_2) {
          return;
        }
        lVar7 = 0;
        pfVar11 = param_1;
        goto LAB_71005ca7e8;
      }
      if (lVar7 == 1) {
        if (param_1 == param_2) {
          return;
        }
        uVar8 = uVar13 - 2 >> 1;
        pfVar10 = param_1 + uVar8 * 2;
        lVar7 = uVar8 + 1;
        do {
          FUN_71005cb150((long)param_1,param_3,uVar13,pfVar10);
          lVar7 = lVar7 + -1;
          pfVar10 = pfVar10 + -2;
        } while (lVar7 != 0);
        FUN_71005cb2a0(param_1,param_2);
        return;
      }
      uVar13 = uVar13 >> 1;
      pfVar11 = param_1 + uVar13 * 2;
      if (uVar8 < 0x401) {
        FUN_71005ca920(pfVar11,param_1,pfVar10);
      }
      else {
        FUN_71005ca920(param_1,pfVar11,pfVar10);
        pfVar1 = param_1 + uVar13 * 2;
        pfVar6 = param_1 + 2;
        FUN_71005ca920(pfVar6,pfVar1 + -2,param_2 + -4);
        FUN_71005ca920(param_1 + 4,pfVar6 + uVar13 * 2,param_2 + -6);
        FUN_71005ca920(pfVar1 + -2,pfVar11,pfVar6 + uVar13 * 2);
        uVar9 = *(undefined8 *)param_1;
        *(undefined8 *)param_1 = *(undefined8 *)pfVar1;
        *(undefined8 *)pfVar1 = uVar9;
      }
      if (((param_5 & 1) == 0) &&
         ((*param_1 < param_1[-2] ||
          ((*param_1 <= param_1[-2] && ((int)param_1[1] <= (int)param_1[-1])))))) {
        param_1 = FUN_71005caa40(param_1,param_2);
        goto LAB_71005ca59c;
      }
      pfVar6 = FUN_71005cab90(param_1,param_2);
      if ((extraout_x1 & 1) == 0) break;
      bVar4 = FUN_71005cace0(param_1,pfVar6);
      bVar5 = FUN_71005cace0(pfVar6 + 2,param_2);
      if (bVar5) {
        param_4 = -lVar7;
        param_2 = pfVar6;
        if (bVar4) {
          return;
        }
        goto LAB_71005ca3f0;
      }
      pfVar11 = pfVar6 + 2;
    } while (bVar4);
    FUN_71005ca3c0(param_1,pfVar6,param_3,-lVar7,param_5 & 1);
    param_1 = pfVar6 + 2;
LAB_71005ca59c:
    param_5 = 0;
    param_4 = -lVar7;
  } while( true );
LAB_71005ca7e8:
  pfVar6 = pfVar10;
  fVar14 = pfVar11[2];
  if ((fVar14 <= *pfVar11) &&
     ((fVar3 = pfVar11[3], fVar14 < *pfVar11 || ((int)fVar3 < (int)pfVar11[1])))) {
    *(undefined8 *)(pfVar11 + 2) = *(undefined8 *)pfVar11;
    pfVar10 = param_1;
    lVar12 = lVar7;
    if (pfVar11 != param_1) {
      do {
        pfVar1 = (float *)((long)param_1 + lVar12);
        pfVar10 = pfVar1;
        if ((pfVar1[-2] < fVar14) ||
           ((pfVar1[-2] == fVar14 && (pfVar10 = pfVar11, (int)pfVar1[-1] <= (int)fVar3)))) break;
        lVar12 = lVar12 + -8;
        *(undefined8 *)pfVar1 = *(undefined8 *)(pfVar1 + -2);
        pfVar10 = param_1;
        pfVar11 = pfVar11 + -2;
      } while (lVar12 != 0);
    }
    *pfVar10 = fVar14;
    pfVar10[1] = fVar3;
  }
  pfVar10 = pfVar6 + 2;
  lVar7 = lVar7 + 8;
  pfVar11 = pfVar6;
  if (pfVar10 == param_2) {
switchD_71005ca5cc_caseD_0:
    return;
  }
  goto LAB_71005ca7e8;
}



undefined8 FUN_71005ca920(float *param_1,float *param_2,float *param_3)

{
  undefined8 uVar1;
  float fVar2;
  
  fVar2 = *param_2;
  if ((*param_1 < fVar2) || ((*param_1 <= fVar2 && ((int)param_1[1] <= (int)param_2[1])))) {
    if ((fVar2 < *param_3) || ((fVar2 <= *param_3 && ((int)param_2[1] <= (int)param_3[1])))) {
      return 0;
    }
    uVar1 = *(undefined8 *)param_2;
    *(undefined8 *)param_2 = *(undefined8 *)param_3;
    *(undefined8 *)param_3 = uVar1;
    if ((*param_2 <= *param_1) && ((*param_2 < *param_1 || ((int)param_2[1] < (int)param_1[1])))) {
      uVar1 = *(undefined8 *)param_1;
      *(undefined8 *)param_1 = *(undefined8 *)param_2;
      *(undefined8 *)param_2 = uVar1;
      return 2;
    }
  }
  else {
    if ((*param_3 <= fVar2) && ((*param_3 < fVar2 || ((int)param_3[1] < (int)param_2[1])))) {
      uVar1 = *(undefined8 *)param_1;
      *(undefined8 *)param_1 = *(undefined8 *)param_3;
      *(undefined8 *)param_3 = uVar1;
      return 1;
    }
    uVar1 = *(undefined8 *)param_1;
    *(undefined8 *)param_1 = *(undefined8 *)param_2;
    *(undefined8 *)param_2 = uVar1;
    if ((*param_3 <= (float)uVar1) &&
       ((*param_3 < (float)uVar1 || ((int)param_3[1] < (int)((ulong)uVar1 >> 0x20))))) {
      *(undefined8 *)param_2 = *(undefined8 *)param_3;
      *(undefined8 *)param_3 = uVar1;
      return 2;
    }
  }
  return 1;
}



float * FUN_71005caa40(float *param_1,float *param_2)

{
  float fVar1;
  float fVar2;
  float *pfVar3;
  float *pfVar4;
  undefined8 uVar5;
  float fVar6;
  
  fVar1 = *param_1;
  fVar2 = param_1[1];
  fVar6 = param_2[-2];
  pfVar3 = param_1;
  if ((fVar6 < fVar1) || ((fVar6 == fVar1 && ((int)param_2[-1] <= (int)fVar2)))) {
    while (pfVar4 = pfVar3, pfVar3 = pfVar4 + 2, pfVar3 < param_2) {
      if ((fVar1 <= *pfVar3) && ((*pfVar3 != fVar1 || ((int)fVar2 < (int)pfVar4[3])))) break;
    }
  }
  else {
    do {
      do {
        pfVar4 = pfVar3;
        pfVar3 = pfVar4 + 2;
      } while (*pfVar3 < fVar1);
    } while ((*pfVar3 == fVar1) && ((int)pfVar4[3] <= (int)fVar2));
  }
  pfVar4 = param_2 + -2;
  if (pfVar3 < param_2) {
    while ((param_2 = pfVar4, fVar1 <= fVar6 && ((fVar1 < fVar6 || ((int)fVar2 < (int)param_2[1]))))
          ) {
      fVar6 = param_2[-2];
      pfVar4 = param_2 + -2;
    }
  }
  do {
    if (param_2 <= pfVar3) {
      if (pfVar3 + -2 != param_1) {
        *(undefined8 *)param_1 = *(undefined8 *)(pfVar3 + -2);
      }
      pfVar3[-2] = fVar1;
      pfVar3[-1] = fVar2;
      return pfVar3;
    }
    uVar5 = *(undefined8 *)pfVar3;
    *(undefined8 *)pfVar3 = *(undefined8 *)param_2;
    *(undefined8 *)param_2 = uVar5;
    do {
      do {
        pfVar4 = pfVar3;
        pfVar3 = pfVar4 + 2;
      } while (*pfVar3 < fVar1);
    } while ((*pfVar3 == fVar1) && ((int)pfVar4[3] <= (int)fVar2));
    do {
      pfVar4 = param_2;
      param_2 = pfVar4 + -2;
      if (*param_2 < fVar1) break;
    } while ((fVar1 < *param_2) || ((int)fVar2 < (int)pfVar4[-1]));
  } while( true );
}



float * FUN_71005cab90(float *param_1,float *param_2)

{
  float fVar1;
  float fVar2;
  float *pfVar3;
  float *pfVar4;
  undefined8 uVar5;
  float fVar6;
  
  fVar1 = *param_1;
  fVar2 = param_1[1];
  pfVar3 = param_1 + 2;
  fVar6 = *pfVar3;
  if (fVar6 <= fVar1) {
    do {
      pfVar4 = pfVar3;
      if ((fVar1 <= fVar6) && ((int)fVar2 <= (int)pfVar4[1])) {
        pfVar3 = pfVar4;
        pfVar4 = pfVar4 + -2;
        break;
      }
      pfVar3 = pfVar4 + 2;
      fVar6 = *pfVar3;
    } while (fVar6 <= fVar1);
    if (pfVar4 != param_1) {
      do {
        do {
          pfVar4 = param_2;
          param_2 = pfVar4 + -2;
        } while (fVar1 < *param_2);
      } while ((fVar1 <= *param_2) && ((int)fVar2 <= (int)pfVar4[-1]));
      goto LAB_71005cac34;
    }
  }
  while (pfVar4 = param_2, param_2 = pfVar4, pfVar3 < pfVar4) {
    param_2 = pfVar4 + -2;
    if ((*param_2 <= fVar1) && ((*param_2 < fVar1 || ((int)pfVar4[-1] < (int)fVar2)))) break;
  }
LAB_71005cac34:
  if (pfVar3 < param_2) {
    do {
      uVar5 = *(undefined8 *)pfVar3;
      *(undefined8 *)pfVar3 = *(undefined8 *)param_2;
      *(undefined8 *)param_2 = uVar5;
      do {
        pfVar4 = pfVar3;
        pfVar3 = pfVar4 + 2;
        if (fVar1 < *pfVar3) break;
      } while ((*pfVar3 < fVar1) || ((int)pfVar4[3] < (int)fVar2));
      do {
        do {
          pfVar4 = param_2;
          param_2 = pfVar4 + -2;
        } while (fVar1 < *param_2);
      } while ((fVar1 <= *param_2) && ((int)fVar2 <= (int)pfVar4[-1]));
    } while (pfVar3 < param_2);
  }
  pfVar4 = pfVar3 + -2;
  if (pfVar4 != param_1) {
    *(undefined8 *)param_1 = *(undefined8 *)pfVar4;
  }
  pfVar3[-2] = fVar1;
  pfVar3[-1] = fVar2;
  return pfVar4;
}



bool FUN_71005cace0(float *param_1,float *param_2)

{
  undefined8 uVar1;
  bool bVar2;
  float *pfVar3;
  undefined8 uVar4;
  long lVar5;
  int iVar6;
  float fVar7;
  long lVar8;
  long lVar9;
  float *pfVar10;
  float *pfVar11;
  float fVar12;
  float fVar13;
  
  bVar2 = true;
  switch((long)param_2 - (long)param_1 >> 3) {
  case 0:
  case 1:
    return bVar2;
  case 2:
    if (*param_1 < param_2[-2]) {
      return bVar2;
    }
    if ((*param_1 <= param_2[-2]) && ((int)param_1[1] <= (int)param_2[-1])) {
      return bVar2;
    }
    uVar4 = *(undefined8 *)param_1;
    *(undefined8 *)param_1 = *(undefined8 *)(param_2 + -2);
    *(undefined8 *)(param_2 + -2) = uVar4;
    return bVar2;
  case 3:
    FUN_71005ca920(param_1,param_1 + 2,param_2 + -2);
    break;
  case 4:
    pfVar10 = param_1 + 4;
    FUN_71005ca920(param_1,param_1 + 2,pfVar10);
    if ((param_2[-2] <= param_1[4]) &&
       ((param_2[-2] < param_1[4] || ((int)param_2[-1] < (int)param_1[5])))) {
      uVar4 = *(undefined8 *)pfVar10;
      *(undefined8 *)pfVar10 = *(undefined8 *)(param_2 + -2);
      *(undefined8 *)(param_2 + -2) = uVar4;
      fVar12 = param_1[2];
      if ((*pfVar10 <= fVar12) && ((*pfVar10 < fVar12 || ((int)param_1[5] < (int)param_1[3])))) {
        uVar4 = *(undefined8 *)(param_1 + 2);
        uVar1 = *(undefined8 *)(param_1 + 4);
        *(undefined8 *)(param_1 + 2) = uVar1;
        *(undefined8 *)(param_1 + 4) = uVar4;
        if (((float)uVar1 <= *param_1) &&
           ((*param_1 != (float)uVar1 || ((int)((ulong)uVar1 >> 0x20) < (int)param_1[1])))) {
          uVar4 = *(undefined8 *)param_1;
          *(undefined8 *)param_1 = uVar1;
          *(undefined8 *)(param_1 + 2) = uVar4;
          return true;
        }
      }
    }
    break;
  case 5:
    FUN_71005cafa0(param_1,param_1 + 2,param_1 + 4,param_1 + 6,param_2 + -2);
    return true;
  default:
    FUN_71005ca920(param_1,param_1 + 2,param_1 + 4);
    if (param_1 + 6 != param_2) {
      lVar5 = 0;
      iVar6 = 0;
      pfVar10 = param_1 + 6;
      pfVar11 = param_1 + 4;
      do {
        pfVar3 = pfVar10;
        fVar12 = *pfVar3;
        if (fVar12 <= *pfVar11) {
          if (*pfVar11 <= fVar12) {
            fVar7 = pfVar3[1];
            if ((int)pfVar11[1] <= (int)fVar7) goto LAB_71005cad80;
          }
          else {
            fVar7 = pfVar3[1];
          }
          *(undefined8 *)pfVar3 = *(undefined8 *)pfVar11;
          lVar9 = lVar5;
          pfVar10 = param_1;
          if (pfVar11 != param_1) {
            do {
              fVar13 = *(float *)((long)param_1 + lVar9 + 8);
              pfVar10 = pfVar11;
              if (fVar13 < fVar12) break;
              if ((fVar13 == fVar12) && (*(int *)((long)param_1 + lVar9 + 0xc) <= (int)fVar7)) {
                pfVar10 = (float *)((long)param_1 + lVar9 + 0x10);
                break;
              }
              lVar8 = lVar9 + -8;
              *(undefined8 *)((long)param_1 + lVar9 + 0x10) =
                   *(undefined8 *)((long)param_1 + lVar9 + 8);
              lVar9 = lVar8;
              pfVar10 = param_1;
              pfVar11 = pfVar11 + -2;
            } while (lVar8 != -0x10);
          }
          iVar6 = iVar6 + 1;
          *pfVar10 = fVar12;
          pfVar10[1] = fVar7;
          if (iVar6 == 8) {
            return pfVar3 + 2 == param_2;
          }
        }
LAB_71005cad80:
        lVar5 = lVar5 + 8;
        pfVar10 = pfVar3 + 2;
        pfVar11 = pfVar3;
      } while (pfVar3 + 2 != param_2);
    }
  }
  return true;
}



void FUN_71005cafa0(float *param_1,float *param_2,float *param_3,float *param_4,float *param_5)

{
  undefined8 uVar1;
  
  FUN_71005ca920(param_1,param_2,param_3);
  if ((*param_4 <= *param_3) && ((*param_4 < *param_3 || ((int)param_4[1] < (int)param_3[1])))) {
    uVar1 = *(undefined8 *)param_3;
    *(undefined8 *)param_3 = *(undefined8 *)param_4;
    *(undefined8 *)param_4 = uVar1;
    if ((*param_3 <= *param_2) && ((*param_3 < *param_2 || ((int)param_3[1] < (int)param_2[1])))) {
      uVar1 = *(undefined8 *)param_2;
      *(undefined8 *)param_2 = *(undefined8 *)param_3;
      *(undefined8 *)param_3 = uVar1;
      if ((*param_2 <= *param_1) && ((*param_2 < *param_1 || ((int)param_2[1] < (int)param_1[1]))))
      {
        uVar1 = *(undefined8 *)param_1;
        *(undefined8 *)param_1 = *(undefined8 *)param_2;
        *(undefined8 *)param_2 = uVar1;
      }
    }
  }
  if ((*param_5 <= *param_4) && ((*param_5 < *param_4 || ((int)param_5[1] < (int)param_4[1])))) {
    uVar1 = *(undefined8 *)param_4;
    *(undefined8 *)param_4 = *(undefined8 *)param_5;
    *(undefined8 *)param_5 = uVar1;
    if ((*param_4 <= *param_3) && ((*param_4 < *param_3 || ((int)param_4[1] < (int)param_3[1])))) {
      uVar1 = *(undefined8 *)param_3;
      *(undefined8 *)param_3 = *(undefined8 *)param_4;
      *(undefined8 *)param_4 = uVar1;
      if ((*param_3 <= *param_2) && ((*param_3 < *param_2 || ((int)param_3[1] < (int)param_2[1]))))
      {
        uVar1 = *(undefined8 *)param_2;
        *(undefined8 *)param_2 = *(undefined8 *)param_3;
        *(undefined8 *)param_3 = uVar1;
        if ((*param_2 <= *param_1) && ((*param_2 < *param_1 || ((int)param_2[1] < (int)param_1[1])))
           ) {
          uVar1 = *(undefined8 *)param_1;
          *(undefined8 *)param_1 = *(undefined8 *)param_2;
          *(undefined8 *)param_2 = uVar1;
        }
      }
    }
  }
  return;
}



void FUN_71005cb150(long param_1,undefined8 param_2,long param_3,float *param_4)

{
  ulong uVar1;
  ulong uVar2;
  ulong uVar3;
  float *pfVar4;
  ulong uVar5;
  float fVar6;
  long lVar7;
  float *pfVar8;
  float fVar9;
  float fVar10;
  
  if (1 < param_3) {
    uVar3 = param_3 - 2U >> 1;
    if ((long)param_4 - param_1 >> 3 <= (long)uVar3) {
      lVar7 = (long)param_4 - param_1 >> 2;
      uVar5 = lVar7 + 1;
      uVar1 = lVar7 + 2;
      pfVar4 = (float *)(param_1 + uVar5 * 8);
      if ((long)uVar1 < param_3) {
        fVar9 = pfVar4[2];
        if ((*pfVar4 <= fVar9) && ((*pfVar4 < fVar9 || ((int)pfVar4[1] < (int)pfVar4[3])))) {
          pfVar4 = pfVar4 + 2;
          uVar5 = uVar1;
        }
      }
      fVar9 = *param_4;
      if (*pfVar4 <= fVar9) {
        if (*pfVar4 < fVar9) {
          return;
        }
        fVar6 = param_4[1];
        if ((int)pfVar4[1] < (int)fVar6) {
          return;
        }
      }
      else {
        fVar6 = param_4[1];
      }
      *(undefined8 *)param_4 = *(undefined8 *)pfVar4;
      if ((long)uVar3 < (long)uVar5) {
        *pfVar4 = fVar9;
        pfVar4[1] = fVar6;
        return;
      }
      do {
        uVar2 = uVar5 << 1 | 1;
        uVar1 = uVar5 * 2 + 2;
        pfVar8 = (float *)(param_1 + uVar2 * 8);
        uVar5 = uVar2;
        if ((long)uVar1 < param_3) {
          fVar10 = pfVar8[2];
          if ((*pfVar8 <= fVar10) && ((*pfVar8 < fVar10 || ((int)pfVar8[1] < (int)pfVar8[3])))) {
            uVar5 = uVar1;
            pfVar8 = pfVar8 + 2;
          }
        }
        if (*pfVar8 <= fVar9) {
          if (*pfVar8 < fVar9) break;
          if ((int)pfVar8[1] < (int)fVar6) {
            *pfVar4 = fVar9;
            pfVar4[1] = fVar6;
            return;
          }
        }
        *(undefined8 *)pfVar4 = *(undefined8 *)pfVar8;
        pfVar4 = pfVar8;
      } while ((long)uVar5 <= (long)uVar3);
      *pfVar4 = fVar9;
      pfVar4[1] = fVar6;
      return;
    }
  }
  return;
}



void FUN_71005cb2a0(float *param_1,float *param_2)

{
  bool bVar1;
  float *pfVar2;
  ulong uVar3;
  ulong uVar4;
  float *pfVar5;
  float *pfVar6;
  undefined8 uVar7;
  float fVar8;
  ulong uVar9;
  ulong uVar10;
  float *pfVar11;
  float fVar12;
  
  if (8 < (long)param_2 - (long)param_1) {
    uVar4 = (ulong)((long)param_2 - (long)param_1) >> 3;
    do {
      uVar7 = *(undefined8 *)param_1;
      uVar9 = 0;
      pfVar6 = param_1;
      do {
        uVar3 = uVar9 << 1 | 1;
        pfVar2 = pfVar6 + (uVar9 + 1) * 2;
        uVar10 = uVar9 * 2 + 2;
        pfVar5 = pfVar2;
        uVar9 = uVar3;
        if ((long)uVar10 < (long)uVar4) {
          pfVar11 = pfVar2 + 2;
          if (((*pfVar2 <= *pfVar11) && (pfVar5 = pfVar11, uVar9 = uVar10, *pfVar11 <= *pfVar2)) &&
             ((int)pfVar2[3] <= (int)pfVar2[1])) {
            pfVar5 = pfVar2;
            uVar9 = uVar3;
          }
        }
        *(undefined8 *)pfVar6 = *(undefined8 *)pfVar5;
        pfVar6 = pfVar5;
      } while ((long)uVar9 <= (long)(uVar4 - 2 >> 1));
      param_2 = param_2 + -2;
      if (pfVar5 == param_2) {
        *(undefined8 *)pfVar5 = uVar7;
      }
      else {
        *(undefined8 *)pfVar5 = *(undefined8 *)param_2;
        *(undefined8 *)param_2 = uVar7;
        uVar9 = (long)pfVar5 + (8 - (long)param_1);
        if (8 < (long)uVar9) {
          fVar12 = *pfVar5;
          uVar10 = (uVar9 >> 3) - 2;
          uVar9 = uVar10 >> 1;
          pfVar6 = param_1 + uVar9 * 2;
          if (*pfVar6 <= fVar12) {
            if (fVar12 <= *pfVar6) {
              fVar8 = pfVar5[1];
              if ((int)fVar8 <= (int)pfVar6[1]) goto LAB_71005cb2b8;
            }
            else {
              fVar8 = pfVar5[1];
            }
            *(undefined8 *)pfVar5 = *(undefined8 *)pfVar6;
            while (1 < uVar10) {
              uVar10 = uVar9 - 1;
              uVar9 = uVar10 >> 1;
              pfVar2 = param_1 + uVar9 * 2;
              if ((fVar12 < *pfVar2) || ((fVar12 <= *pfVar2 && ((int)fVar8 <= (int)pfVar2[1]))))
              break;
              *(undefined8 *)pfVar6 = *(undefined8 *)pfVar2;
              pfVar6 = pfVar2;
            }
            *pfVar6 = fVar12;
            pfVar6[1] = fVar8;
          }
        }
      }
LAB_71005cb2b8:
      bVar1 = 2 < (long)uVar4;
      uVar4 = uVar4 - 1;
    } while (bVar1);
  }
  return;
}



void FUN_71005cb420(float *param_1,float *param_2,undefined8 param_3,long param_4,uint param_5)

{
  float *pfVar1;
  undefined8 uVar2;
  float fVar3;
  bool bVar4;
  bool bVar5;
  float *pfVar6;
  ulong extraout_x1;
  long lVar7;
  ulong uVar8;
  undefined8 uVar9;
  float *pfVar10;
  float *pfVar11;
  long lVar12;
  ulong uVar13;
  float fVar14;
  float fVar15;
  
LAB_71005cb450:
  pfVar10 = param_2 + -2;
  do {
    lVar7 = -param_4;
    pfVar11 = param_1;
    do {
      param_1 = pfVar11;
      lVar7 = lVar7 + 1;
      uVar8 = (long)param_2 - (long)param_1;
      uVar13 = (long)uVar8 >> 3;
      switch(uVar13) {
      case 0:
      case 1:
        goto switchD_71005cb62c_caseD_0;
      case 2:
        if (param_2[-2] < *param_1) {
          return;
        }
        if ((param_2[-2] == *param_1) && ((int)param_1[1] <= (int)param_2[-1])) {
          return;
        }
        uVar9 = *(undefined8 *)param_1;
        *(undefined8 *)param_1 = *(undefined8 *)(param_2 + -2);
        *(undefined8 *)(param_2 + -2) = uVar9;
        return;
      case 3:
        FUN_71005cb980(param_1,param_1 + 2,pfVar10);
        return;
      case 4:
        pfVar10 = param_1 + 4;
        FUN_71005cb980(param_1,param_1 + 2,pfVar10);
        if (param_2[-2] < param_1[4]) {
          return;
        }
        if ((param_2[-2] == param_1[4]) && ((int)param_1[5] <= (int)param_2[-1])) {
          return;
        }
        uVar9 = *(undefined8 *)pfVar10;
        *(undefined8 *)pfVar10 = *(undefined8 *)(param_2 + -2);
        *(undefined8 *)(param_2 + -2) = uVar9;
        fVar14 = param_1[2];
        if (*pfVar10 < fVar14) {
          return;
        }
        if ((*pfVar10 == fVar14) && ((int)param_1[3] <= (int)param_1[5])) {
          return;
        }
        uVar9 = *(undefined8 *)(param_1 + 2);
        uVar2 = *(undefined8 *)(param_1 + 4);
        *(undefined8 *)(param_1 + 2) = uVar2;
        *(undefined8 *)(param_1 + 4) = uVar9;
        if ((float)uVar2 < *param_1) {
          return;
        }
        if (((float)uVar2 <= *param_1) && ((int)param_1[1] <= (int)((ulong)uVar2 >> 0x20))) {
          return;
        }
        uVar9 = *(undefined8 *)param_1;
        *(undefined8 *)param_1 = uVar2;
        *(undefined8 *)(param_1 + 2) = uVar9;
        return;
      case 5:
        FUN_71005cc000(param_1,param_1 + 2,param_1 + 4,param_1 + 6,pfVar10);
        return;
      }
      if ((long)uVar8 < 0xc0) {
        pfVar10 = param_1 + 2;
        if ((param_5 & 1) == 0) {
          if (param_1 == param_2 || pfVar10 == param_2) {
            return;
          }
          do {
            fVar14 = *pfVar10;
            if ((*param_1 <= fVar14) &&
               ((fVar3 = param_1[3], fVar14 != *param_1 || ((int)fVar3 < (int)param_1[1])))) {
              *(undefined8 *)pfVar10 = *(undefined8 *)param_1;
              fVar15 = param_1[-2];
              pfVar11 = param_1;
              while ((fVar15 <= fVar14 && ((fVar15 < fVar14 || ((int)fVar3 < (int)pfVar11[-1]))))) {
                fVar15 = pfVar11[-4];
                *(undefined8 *)pfVar11 = *(undefined8 *)(pfVar11 + -2);
                pfVar11 = pfVar11 + -2;
              }
              *pfVar11 = fVar14;
              pfVar11[1] = fVar3;
            }
            pfVar10 = pfVar10 + 2;
            param_1 = param_1 + 2;
          } while (pfVar10 != param_2);
          return;
        }
        if (param_1 == param_2 || pfVar10 == param_2) {
          return;
        }
        lVar7 = 0;
        pfVar11 = param_1;
        goto LAB_71005cb848;
      }
      if (lVar7 == 1) {
        if (param_1 == param_2) {
          return;
        }
        uVar8 = uVar13 - 2 >> 1;
        pfVar10 = param_1 + uVar8 * 2;
        lVar7 = uVar8 + 1;
        do {
          FUN_71005cc1b0((long)param_1,param_3,uVar13,pfVar10);
          lVar7 = lVar7 + -1;
          pfVar10 = pfVar10 + -2;
        } while (lVar7 != 0);
        FUN_71005cc300(param_1,param_2);
        return;
      }
      uVar13 = uVar13 >> 1;
      pfVar11 = param_1 + uVar13 * 2;
      if (uVar8 < 0x401) {
        FUN_71005cb980(pfVar11,param_1,pfVar10);
      }
      else {
        FUN_71005cb980(param_1,pfVar11,pfVar10);
        pfVar1 = param_1 + uVar13 * 2;
        pfVar6 = param_1 + 2;
        FUN_71005cb980(pfVar6,pfVar1 + -2,param_2 + -4);
        FUN_71005cb980(param_1 + 4,pfVar6 + uVar13 * 2,param_2 + -6);
        FUN_71005cb980(pfVar1 + -2,pfVar11,pfVar6 + uVar13 * 2);
        uVar9 = *(undefined8 *)param_1;
        *(undefined8 *)param_1 = *(undefined8 *)pfVar1;
        *(undefined8 *)pfVar1 = uVar9;
      }
      if (((param_5 & 1) == 0) &&
         ((param_1[-2] < *param_1 ||
          ((param_1[-2] == *param_1 && ((int)param_1[1] <= (int)param_1[-1])))))) {
        param_1 = FUN_71005cbaa0(param_1,param_2);
        goto LAB_71005cb5fc;
      }
      pfVar6 = FUN_71005cbbf0(param_1,param_2);
      if ((extraout_x1 & 1) == 0) break;
      bVar4 = FUN_71005cbd40(param_1,pfVar6);
      bVar5 = FUN_71005cbd40(pfVar6 + 2,param_2);
      if (bVar5) {
        param_4 = -lVar7;
        param_2 = pfVar6;
        if (bVar4) {
          return;
        }
        goto LAB_71005cb450;
      }
      pfVar11 = pfVar6 + 2;
    } while (bVar4);
    FUN_71005cb420(param_1,pfVar6,param_3,-lVar7,param_5 & 1);
    param_1 = pfVar6 + 2;
LAB_71005cb5fc:
    param_5 = 0;
    param_4 = -lVar7;
  } while( true );
LAB_71005cb848:
  pfVar6 = pfVar10;
  fVar14 = pfVar11[2];
  if ((*pfVar11 <= fVar14) &&
     ((fVar3 = pfVar11[3], fVar14 != *pfVar11 || ((int)fVar3 < (int)pfVar11[1])))) {
    *(undefined8 *)(pfVar11 + 2) = *(undefined8 *)pfVar11;
    pfVar10 = param_1;
    lVar12 = lVar7;
    if (pfVar11 != param_1) {
      do {
        pfVar1 = (float *)((long)param_1 + lVar12);
        pfVar10 = pfVar1;
        if ((fVar14 < pfVar1[-2]) ||
           ((fVar14 <= pfVar1[-2] && (pfVar10 = pfVar11, (int)pfVar1[-1] <= (int)fVar3)))) break;
        lVar12 = lVar12 + -8;
        *(undefined8 *)pfVar1 = *(undefined8 *)(pfVar1 + -2);
        pfVar10 = param_1;
        pfVar11 = pfVar11 + -2;
      } while (lVar12 != 0);
    }
    *pfVar10 = fVar14;
    pfVar10[1] = fVar3;
  }
  pfVar10 = pfVar6 + 2;
  lVar7 = lVar7 + 8;
  pfVar11 = pfVar6;
  if (pfVar10 == param_2) {
switchD_71005cb62c_caseD_0:
    return;
  }
  goto LAB_71005cb848;
}



undefined8 FUN_71005cb980(float *param_1,float *param_2,float *param_3)

{
  undefined8 uVar1;
  float fVar2;
  
  fVar2 = *param_2;
  if ((fVar2 < *param_1) || ((fVar2 == *param_1 && ((int)param_1[1] <= (int)param_2[1])))) {
    if ((*param_3 < fVar2) || ((*param_3 <= fVar2 && ((int)param_2[1] <= (int)param_3[1])))) {
      return 0;
    }
    uVar1 = *(undefined8 *)param_2;
    *(undefined8 *)param_2 = *(undefined8 *)param_3;
    *(undefined8 *)param_3 = uVar1;
    if ((*param_1 <= *param_2) && ((*param_1 < *param_2 || ((int)param_2[1] < (int)param_1[1])))) {
      uVar1 = *(undefined8 *)param_1;
      *(undefined8 *)param_1 = *(undefined8 *)param_2;
      *(undefined8 *)param_2 = uVar1;
      return 2;
    }
  }
  else {
    if ((fVar2 <= *param_3) && ((fVar2 < *param_3 || ((int)param_3[1] < (int)param_2[1])))) {
      uVar1 = *(undefined8 *)param_1;
      *(undefined8 *)param_1 = *(undefined8 *)param_3;
      *(undefined8 *)param_3 = uVar1;
      return 1;
    }
    uVar1 = *(undefined8 *)param_1;
    *(undefined8 *)param_1 = *(undefined8 *)param_2;
    *(undefined8 *)param_2 = uVar1;
    if (((float)uVar1 <= *param_3) &&
       ((*param_3 != (float)uVar1 || ((int)param_3[1] < (int)((ulong)uVar1 >> 0x20))))) {
      *(undefined8 *)param_2 = *(undefined8 *)param_3;
      *(undefined8 *)param_3 = uVar1;
      return 2;
    }
  }
  return 1;
}



float * FUN_71005cbaa0(float *param_1,float *param_2)

{
  float fVar1;
  float fVar2;
  float *pfVar3;
  float *pfVar4;
  undefined8 uVar5;
  float fVar6;
  
  fVar1 = *param_1;
  fVar2 = param_1[1];
  fVar6 = param_2[-2];
  pfVar3 = param_1;
  if ((fVar1 < fVar6) || ((fVar1 <= fVar6 && ((int)param_2[-1] <= (int)fVar2)))) {
    while (pfVar4 = pfVar3, pfVar3 = pfVar4 + 2, pfVar3 < param_2) {
      if ((*pfVar3 <= fVar1) && ((*pfVar3 < fVar1 || ((int)fVar2 < (int)pfVar4[3])))) break;
    }
  }
  else {
    do {
      do {
        pfVar4 = pfVar3;
        pfVar3 = pfVar4 + 2;
      } while (fVar1 < *pfVar3);
    } while ((fVar1 <= *pfVar3) && ((int)pfVar4[3] <= (int)fVar2));
  }
  pfVar4 = param_2 + -2;
  if (pfVar3 < param_2) {
    while ((param_2 = pfVar4, fVar6 <= fVar1 && ((fVar6 < fVar1 || ((int)fVar2 < (int)param_2[1]))))
          ) {
      fVar6 = param_2[-2];
      pfVar4 = param_2 + -2;
    }
  }
  do {
    if (param_2 <= pfVar3) {
      if (pfVar3 + -2 != param_1) {
        *(undefined8 *)param_1 = *(undefined8 *)(pfVar3 + -2);
      }
      pfVar3[-2] = fVar1;
      pfVar3[-1] = fVar2;
      return pfVar3;
    }
    uVar5 = *(undefined8 *)pfVar3;
    *(undefined8 *)pfVar3 = *(undefined8 *)param_2;
    *(undefined8 *)param_2 = uVar5;
    do {
      do {
        pfVar4 = pfVar3;
        pfVar3 = pfVar4 + 2;
      } while (fVar1 < *pfVar3);
    } while ((fVar1 <= *pfVar3) && ((int)pfVar4[3] <= (int)fVar2));
    do {
      pfVar4 = param_2;
      param_2 = pfVar4 + -2;
      if (fVar1 < *param_2) break;
    } while ((*param_2 < fVar1) || ((int)fVar2 < (int)pfVar4[-1]));
  } while( true );
}



float * FUN_71005cbbf0(float *param_1,float *param_2)

{
  float fVar1;
  float fVar2;
  float *pfVar3;
  float *pfVar4;
  undefined8 uVar5;
  float fVar6;
  
  fVar1 = *param_1;
  fVar2 = param_1[1];
  pfVar3 = param_1 + 2;
  fVar6 = *pfVar3;
  if (fVar1 <= fVar6) {
    do {
      pfVar4 = pfVar3;
      if ((fVar6 <= fVar1) && ((int)fVar2 <= (int)pfVar4[1])) {
        pfVar3 = pfVar4;
        pfVar4 = pfVar4 + -2;
        break;
      }
      pfVar3 = pfVar4 + 2;
      fVar6 = *pfVar3;
    } while (fVar1 <= fVar6);
    if (pfVar4 != param_1) {
      do {
        do {
          pfVar4 = param_2;
          param_2 = pfVar4 + -2;
        } while (*param_2 < fVar1);
      } while ((*param_2 == fVar1) && ((int)fVar2 <= (int)pfVar4[-1]));
      goto LAB_71005cbc94;
    }
  }
  while (pfVar4 = param_2, param_2 = pfVar4, pfVar3 < pfVar4) {
    param_2 = pfVar4 + -2;
    if ((fVar1 <= *param_2) && ((*param_2 != fVar1 || ((int)pfVar4[-1] < (int)fVar2)))) break;
  }
LAB_71005cbc94:
  if (pfVar3 < param_2) {
    do {
      uVar5 = *(undefined8 *)pfVar3;
      *(undefined8 *)pfVar3 = *(undefined8 *)param_2;
      *(undefined8 *)param_2 = uVar5;
      do {
        pfVar4 = pfVar3;
        pfVar3 = pfVar4 + 2;
        if (*pfVar3 < fVar1) break;
      } while ((fVar1 < *pfVar3) || ((int)pfVar4[3] < (int)fVar2));
      do {
        do {
          pfVar4 = param_2;
          param_2 = pfVar4 + -2;
        } while (*param_2 < fVar1);
      } while ((*param_2 == fVar1) && ((int)fVar2 <= (int)pfVar4[-1]));
    } while (pfVar3 < param_2);
  }
  pfVar4 = pfVar3 + -2;
  if (pfVar4 != param_1) {
    *(undefined8 *)param_1 = *(undefined8 *)pfVar4;
  }
  pfVar3[-2] = fVar1;
  pfVar3[-1] = fVar2;
  return pfVar4;
}



bool FUN_71005cbd40(float *param_1,float *param_2)

{
  undefined8 uVar1;
  bool bVar2;
  float *pfVar3;
  undefined8 uVar4;
  long lVar5;
  int iVar6;
  float fVar7;
  long lVar8;
  long lVar9;
  float *pfVar10;
  float *pfVar11;
  float fVar12;
  float fVar13;
  
  bVar2 = true;
  switch((long)param_2 - (long)param_1 >> 3) {
  case 0:
  case 1:
    return bVar2;
  case 2:
    if (param_2[-2] < *param_1) {
      return bVar2;
    }
    if ((param_2[-2] == *param_1) && ((int)param_1[1] <= (int)param_2[-1])) {
      return bVar2;
    }
    uVar4 = *(undefined8 *)param_1;
    *(undefined8 *)param_1 = *(undefined8 *)(param_2 + -2);
    *(undefined8 *)(param_2 + -2) = uVar4;
    return bVar2;
  case 3:
    FUN_71005cb980(param_1,param_1 + 2,param_2 + -2);
    break;
  case 4:
    pfVar10 = param_1 + 4;
    FUN_71005cb980(param_1,param_1 + 2,pfVar10);
    if ((param_1[4] <= param_2[-2]) &&
       ((param_2[-2] != param_1[4] || ((int)param_2[-1] < (int)param_1[5])))) {
      uVar4 = *(undefined8 *)pfVar10;
      *(undefined8 *)pfVar10 = *(undefined8 *)(param_2 + -2);
      *(undefined8 *)(param_2 + -2) = uVar4;
      fVar12 = param_1[2];
      if ((fVar12 <= *pfVar10) && ((*pfVar10 != fVar12 || ((int)param_1[5] < (int)param_1[3])))) {
        uVar4 = *(undefined8 *)(param_1 + 2);
        uVar1 = *(undefined8 *)(param_1 + 4);
        *(undefined8 *)(param_1 + 2) = uVar1;
        *(undefined8 *)(param_1 + 4) = uVar4;
        if ((*param_1 <= (float)uVar1) &&
           ((*param_1 < (float)uVar1 || ((int)((ulong)uVar1 >> 0x20) < (int)param_1[1])))) {
          uVar4 = *(undefined8 *)param_1;
          *(undefined8 *)param_1 = uVar1;
          *(undefined8 *)(param_1 + 2) = uVar4;
          return true;
        }
      }
    }
    break;
  case 5:
    FUN_71005cc000(param_1,param_1 + 2,param_1 + 4,param_1 + 6,param_2 + -2);
    return true;
  default:
    FUN_71005cb980(param_1,param_1 + 2,param_1 + 4);
    if (param_1 + 6 != param_2) {
      lVar5 = 0;
      iVar6 = 0;
      pfVar10 = param_1 + 6;
      pfVar11 = param_1 + 4;
      do {
        pfVar3 = pfVar10;
        fVar12 = *pfVar3;
        if (*pfVar11 <= fVar12) {
          if (fVar12 <= *pfVar11) {
            fVar7 = pfVar3[1];
            if ((int)pfVar11[1] <= (int)fVar7) goto LAB_71005cbde0;
          }
          else {
            fVar7 = pfVar3[1];
          }
          *(undefined8 *)pfVar3 = *(undefined8 *)pfVar11;
          lVar9 = lVar5;
          pfVar10 = param_1;
          if (pfVar11 != param_1) {
            do {
              fVar13 = *(float *)((long)param_1 + lVar9 + 8);
              pfVar10 = pfVar11;
              if (fVar12 < fVar13) break;
              if ((fVar12 <= fVar13) && (*(int *)((long)param_1 + lVar9 + 0xc) <= (int)fVar7)) {
                pfVar10 = (float *)((long)param_1 + lVar9 + 0x10);
                break;
              }
              lVar8 = lVar9 + -8;
              *(undefined8 *)((long)param_1 + lVar9 + 0x10) =
                   *(undefined8 *)((long)param_1 + lVar9 + 8);
              lVar9 = lVar8;
              pfVar10 = param_1;
              pfVar11 = pfVar11 + -2;
            } while (lVar8 != -0x10);
          }
          iVar6 = iVar6 + 1;
          *pfVar10 = fVar12;
          pfVar10[1] = fVar7;
          if (iVar6 == 8) {
            return pfVar3 + 2 == param_2;
          }
        }
LAB_71005cbde0:
        lVar5 = lVar5 + 8;
        pfVar10 = pfVar3 + 2;
        pfVar11 = pfVar3;
      } while (pfVar3 + 2 != param_2);
    }
  }
  return true;
}



void FUN_71005cc000(float *param_1,float *param_2,float *param_3,float *param_4,float *param_5)

{
  undefined8 uVar1;
  
  FUN_71005cb980(param_1,param_2,param_3);
  if ((*param_3 <= *param_4) && ((*param_4 != *param_3 || ((int)param_4[1] < (int)param_3[1])))) {
    uVar1 = *(undefined8 *)param_3;
    *(undefined8 *)param_3 = *(undefined8 *)param_4;
    *(undefined8 *)param_4 = uVar1;
    if ((*param_2 <= *param_3) && ((*param_3 != *param_2 || ((int)param_3[1] < (int)param_2[1])))) {
      uVar1 = *(undefined8 *)param_2;
      *(undefined8 *)param_2 = *(undefined8 *)param_3;
      *(undefined8 *)param_3 = uVar1;
      if ((*param_1 <= *param_2) && ((*param_2 != *param_1 || ((int)param_2[1] < (int)param_1[1]))))
      {
        uVar1 = *(undefined8 *)param_1;
        *(undefined8 *)param_1 = *(undefined8 *)param_2;
        *(undefined8 *)param_2 = uVar1;
      }
    }
  }
  if ((*param_4 <= *param_5) && ((*param_5 != *param_4 || ((int)param_5[1] < (int)param_4[1])))) {
    uVar1 = *(undefined8 *)param_4;
    *(undefined8 *)param_4 = *(undefined8 *)param_5;
    *(undefined8 *)param_5 = uVar1;
    if ((*param_3 <= *param_4) && ((*param_4 != *param_3 || ((int)param_4[1] < (int)param_3[1])))) {
      uVar1 = *(undefined8 *)param_3;
      *(undefined8 *)param_3 = *(undefined8 *)param_4;
      *(undefined8 *)param_4 = uVar1;
      if ((*param_2 <= *param_3) && ((*param_3 != *param_2 || ((int)param_3[1] < (int)param_2[1]))))
      {
        uVar1 = *(undefined8 *)param_2;
        *(undefined8 *)param_2 = *(undefined8 *)param_3;
        *(undefined8 *)param_3 = uVar1;
        if ((*param_1 <= *param_2) &&
           ((*param_2 != *param_1 || ((int)param_2[1] < (int)param_1[1])))) {
          uVar1 = *(undefined8 *)param_1;
          *(undefined8 *)param_1 = *(undefined8 *)param_2;
          *(undefined8 *)param_2 = uVar1;
        }
      }
    }
  }
  return;
}



void FUN_71005cc1b0(long param_1,undefined8 param_2,long param_3,float *param_4)

{
  ulong uVar1;
  ulong uVar2;
  ulong uVar3;
  float *pfVar4;
  ulong uVar5;
  float fVar6;
  long lVar7;
  float *pfVar8;
  float fVar9;
  float fVar10;
  
  if (1 < param_3) {
    uVar3 = param_3 - 2U >> 1;
    if ((long)param_4 - param_1 >> 3 <= (long)uVar3) {
      lVar7 = (long)param_4 - param_1 >> 2;
      uVar5 = lVar7 + 1;
      uVar1 = lVar7 + 2;
      pfVar4 = (float *)(param_1 + uVar5 * 8);
      if ((long)uVar1 < param_3) {
        fVar9 = pfVar4[2];
        if ((fVar9 <= *pfVar4) && ((*pfVar4 != fVar9 || ((int)pfVar4[1] < (int)pfVar4[3])))) {
          pfVar4 = pfVar4 + 2;
          uVar5 = uVar1;
        }
      }
      fVar9 = *param_4;
      if (fVar9 <= *pfVar4) {
        if (fVar9 < *pfVar4) {
          return;
        }
        fVar6 = param_4[1];
        if ((int)pfVar4[1] < (int)fVar6) {
          return;
        }
      }
      else {
        fVar6 = param_4[1];
      }
      *(undefined8 *)param_4 = *(undefined8 *)pfVar4;
      if ((long)uVar3 < (long)uVar5) {
        *pfVar4 = fVar9;
        pfVar4[1] = fVar6;
        return;
      }
      do {
        uVar2 = uVar5 << 1 | 1;
        uVar1 = uVar5 * 2 + 2;
        pfVar8 = (float *)(param_1 + uVar2 * 8);
        uVar5 = uVar2;
        if ((long)uVar1 < param_3) {
          fVar10 = pfVar8[2];
          if ((fVar10 <= *pfVar8) && ((*pfVar8 != fVar10 || ((int)pfVar8[1] < (int)pfVar8[3])))) {
            uVar5 = uVar1;
            pfVar8 = pfVar8 + 2;
          }
        }
        if (fVar9 <= *pfVar8) {
          if (*pfVar8 != fVar9) break;
          if ((int)pfVar8[1] < (int)fVar6) {
            *pfVar4 = fVar9;
            pfVar4[1] = fVar6;
            return;
          }
        }
        *(undefined8 *)pfVar4 = *(undefined8 *)pfVar8;
        pfVar4 = pfVar8;
      } while ((long)uVar5 <= (long)uVar3);
      *pfVar4 = fVar9;
      pfVar4[1] = fVar6;
      return;
    }
  }
  return;
}



void FUN_71005cc300(float *param_1,float *param_2)

{
  bool bVar1;
  float *pfVar2;
  ulong uVar3;
  ulong uVar4;
  float *pfVar5;
  float *pfVar6;
  undefined8 uVar7;
  float fVar8;
  ulong uVar9;
  ulong uVar10;
  float *pfVar11;
  float fVar12;
  
  if (8 < (long)param_2 - (long)param_1) {
    uVar4 = (ulong)((long)param_2 - (long)param_1) >> 3;
    do {
      uVar7 = *(undefined8 *)param_1;
      uVar9 = 0;
      pfVar6 = param_1;
      do {
        uVar3 = uVar9 << 1 | 1;
        pfVar2 = pfVar6 + (uVar9 + 1) * 2;
        uVar10 = uVar9 * 2 + 2;
        pfVar5 = pfVar2;
        uVar9 = uVar3;
        if ((long)uVar10 < (long)uVar4) {
          pfVar11 = pfVar2 + 2;
          if (((*pfVar11 <= *pfVar2) && (pfVar5 = pfVar11, uVar9 = uVar10, *pfVar2 == *pfVar11)) &&
             ((int)pfVar2[3] <= (int)pfVar2[1])) {
            pfVar5 = pfVar2;
            uVar9 = uVar3;
          }
        }
        *(undefined8 *)pfVar6 = *(undefined8 *)pfVar5;
        pfVar6 = pfVar5;
      } while ((long)uVar9 <= (long)(uVar4 - 2 >> 1));
      param_2 = param_2 + -2;
      if (pfVar5 == param_2) {
        *(undefined8 *)pfVar5 = uVar7;
      }
      else {
        *(undefined8 *)pfVar5 = *(undefined8 *)param_2;
        *(undefined8 *)param_2 = uVar7;
        uVar9 = (long)pfVar5 + (8 - (long)param_1);
        if (8 < (long)uVar9) {
          fVar12 = *pfVar5;
          uVar10 = (uVar9 >> 3) - 2;
          uVar9 = uVar10 >> 1;
          pfVar6 = param_1 + uVar9 * 2;
          if (fVar12 <= *pfVar6) {
            if (*pfVar6 <= fVar12) {
              fVar8 = pfVar5[1];
              if ((int)fVar8 <= (int)pfVar6[1]) goto LAB_71005cc318;
            }
            else {
              fVar8 = pfVar5[1];
            }
            *(undefined8 *)pfVar5 = *(undefined8 *)pfVar6;
            while (1 < uVar10) {
              uVar10 = uVar9 - 1;
              uVar9 = uVar10 >> 1;
              pfVar2 = param_1 + uVar9 * 2;
              if ((*pfVar2 < fVar12) || ((*pfVar2 == fVar12 && ((int)fVar8 <= (int)pfVar2[1]))))
              break;
              *(undefined8 *)pfVar6 = *(undefined8 *)pfVar2;
              pfVar6 = pfVar2;
            }
            *pfVar6 = fVar12;
            pfVar6[1] = fVar8;
          }
        }
      }
LAB_71005cc318:
      bVar1 = 2 < (long)uVar4;
      uVar4 = uVar4 - 1;
    } while (bVar1);
  }
  return;
}



void FUN_71005cc480(float *param_1,float *param_2,undefined8 param_3,long param_4,uint param_5)

{
  float *pfVar1;
  undefined8 uVar2;
  bool bVar3;
  bool bVar4;
  float *pfVar5;
  ulong extraout_x1;
  long lVar6;
  undefined8 uVar7;
  ulong uVar8;
  float *pfVar9;
  float *pfVar10;
  long lVar11;
  ulong uVar12;
  ulong uVar13;
  float fVar14;
  float fVar15;
  float fVar16;
  
LAB_71005cc4b0:
  pfVar10 = param_2 + -2;
  do {
    lVar6 = -param_4;
    pfVar9 = param_1;
    do {
      param_1 = pfVar9;
      lVar6 = lVar6 + 1;
      uVar13 = (long)param_2 - (long)param_1;
      uVar12 = (long)uVar13 >> 3;
      switch(uVar12) {
      case 0:
      case 1:
        goto switchD_71005cc694_caseD_0;
      case 2:
        fVar14 = param_2[-2];
        fVar15 = *param_1;
        if ((0.0 <= fVar14) || (0.0 <= fVar15)) {
          if (fVar15 <= fVar14) {
            return;
          }
        }
        else if (fVar14 <= fVar15) {
          return;
        }
        uVar7 = *(undefined8 *)param_1;
        *(undefined8 *)param_1 = *(undefined8 *)(param_2 + -2);
        *(undefined8 *)(param_2 + -2) = uVar7;
        return;
      case 3:
        FUN_71005cca40(param_1,param_1 + 2,pfVar10);
        return;
      case 4:
        pfVar10 = param_1 + 4;
        FUN_71005cca40(param_1,param_1 + 2,pfVar10);
        fVar14 = param_2[-2];
        fVar15 = param_1[4];
        if ((0.0 <= fVar14) || (0.0 <= fVar15)) {
          if (fVar15 <= fVar14) {
            return;
          }
        }
        else if (fVar14 <= fVar15) {
          return;
        }
        uVar7 = *(undefined8 *)pfVar10;
        *(undefined8 *)pfVar10 = *(undefined8 *)(param_2 + -2);
        *(undefined8 *)(param_2 + -2) = uVar7;
        fVar14 = *pfVar10;
        fVar15 = param_1[2];
        if ((0.0 <= fVar14) || (0.0 <= fVar15)) {
          if (fVar15 <= fVar14) {
            return;
          }
        }
        else if (fVar14 <= fVar15) {
          return;
        }
        uVar7 = *(undefined8 *)(param_1 + 2);
        uVar2 = *(undefined8 *)(param_1 + 4);
        fVar15 = *param_1;
        *(undefined8 *)(param_1 + 2) = uVar2;
        *(undefined8 *)(param_1 + 4) = uVar7;
        fVar14 = (float)uVar2;
        if ((0.0 <= fVar14) || (0.0 <= fVar15)) {
          if (fVar15 <= fVar14) {
            return;
          }
        }
        else if (fVar14 <= fVar15) {
          return;
        }
        uVar7 = *(undefined8 *)param_1;
        *(undefined8 *)param_1 = uVar2;
        *(undefined8 *)(param_1 + 2) = uVar7;
        return;
      case 5:
        FUN_71005cd250(param_1,param_1 + 2,param_1 + 4,param_1 + 6,pfVar10);
        return;
      }
      if ((long)uVar13 < 0xc0) {
        pfVar10 = param_1 + 2;
        if ((param_5 & 1) == 0) {
          if (param_1 == param_2 || pfVar10 == param_2) {
            return;
          }
          goto LAB_71005cc944;
        }
        if (param_1 == param_2 || pfVar10 == param_2) {
          return;
        }
        lVar6 = 0;
        pfVar9 = param_1;
        goto LAB_71005cc7a4;
      }
      if (lVar6 == 1) {
        if (param_1 == param_2) {
          return;
        }
        uVar8 = uVar12 - 2 >> 1;
        pfVar10 = param_1 + uVar8 * 2;
        lVar6 = uVar8 + 1;
        do {
          FUN_71005cd450((long)param_1,param_3,uVar12,pfVar10);
          lVar6 = lVar6 + -1;
          pfVar10 = pfVar10 + -2;
        } while (lVar6 != 0);
        uVar12 = uVar13 >> 3;
        do {
          FUN_71005cd630(param_1,(long)param_2,param_3,uVar12);
          param_2 = param_2 + -2;
          bVar3 = 2 < uVar12;
          uVar12 = uVar12 - 1;
        } while (bVar3);
        return;
      }
      uVar12 = uVar12 >> 1;
      pfVar9 = param_1 + uVar12 * 2;
      if (uVar13 < 0x401) {
        FUN_71005cca40(pfVar9,param_1,pfVar10);
      }
      else {
        FUN_71005cca40(param_1,pfVar9,pfVar10);
        pfVar1 = param_1 + uVar12 * 2;
        pfVar5 = param_1 + 2;
        FUN_71005cca40(pfVar5,pfVar1 + -2,param_2 + -4);
        FUN_71005cca40(param_1 + 4,pfVar5 + uVar12 * 2,param_2 + -6);
        FUN_71005cca40(pfVar1 + -2,pfVar9,pfVar5 + uVar12 * 2);
        uVar7 = *(undefined8 *)param_1;
        *(undefined8 *)param_1 = *(undefined8 *)pfVar1;
        *(undefined8 *)pfVar1 = uVar7;
      }
      if ((param_5 & 1) == 0) {
        fVar14 = param_1[-2];
        fVar15 = *param_1;
        if ((0.0 <= fVar14) || (0.0 <= fVar15)) {
          if (fVar15 <= fVar14) goto LAB_71005cc650;
        }
        else if (fVar14 <= fVar15) {
LAB_71005cc650:
          param_1 = FUN_71005ccb80(param_1,param_2);
          goto LAB_71005cc664;
        }
      }
      pfVar5 = FUN_71005ccd50(param_1,param_2);
      if ((extraout_x1 & 1) == 0) break;
      bVar3 = FUN_71005ccf20(param_1,pfVar5);
      bVar4 = FUN_71005ccf20(pfVar5 + 2,param_2);
      if (bVar4) {
        param_4 = -lVar6;
        param_2 = pfVar5;
        if (bVar3) {
          return;
        }
        goto LAB_71005cc4b0;
      }
      pfVar9 = pfVar5 + 2;
    } while (bVar3);
    FUN_71005cc480(param_1,pfVar5,param_3,-lVar6,param_5 & 1);
    param_1 = pfVar5 + 2;
LAB_71005cc664:
    param_5 = 0;
    param_4 = -lVar6;
  } while( true );
LAB_71005cc944:
  pfVar9 = pfVar10;
  fVar14 = param_1[2];
  fVar15 = *param_1;
  if ((0.0 <= fVar14) || (0.0 <= fVar15)) {
    if (fVar14 < fVar15) goto LAB_71005cc978;
  }
  else if (fVar15 < fVar14) {
LAB_71005cc978:
    fVar15 = param_1[3];
    pfVar10 = pfVar9;
    if (fVar14 < 0.0) {
      do {
        while( true ) {
          pfVar5 = param_1;
          *(undefined8 *)(pfVar5 + 2) = *(undefined8 *)pfVar5;
          param_1 = pfVar5 + -2;
          fVar16 = *param_1;
          if (0.0 <= fVar16) break;
          if (fVar14 <= fVar16) goto LAB_71005cc930;
        }
      } while (fVar14 < fVar16);
    }
    else {
      do {
        pfVar1 = pfVar10 + -4;
        pfVar5 = pfVar10 + -2;
        *(undefined8 *)pfVar10 = *(undefined8 *)pfVar5;
        pfVar10 = pfVar5;
      } while (fVar14 < *pfVar1);
    }
LAB_71005cc930:
    *pfVar5 = fVar14;
    pfVar5[1] = fVar15;
  }
  pfVar10 = pfVar9 + 2;
  param_1 = pfVar9;
  if (pfVar9 + 2 == param_2) {
    return;
  }
  goto LAB_71005cc944;
LAB_71005cc7a4:
  fVar14 = pfVar9[2];
  fVar15 = *pfVar9;
  if ((0.0 <= fVar14) || (0.0 <= fVar15)) {
    if (fVar14 < fVar15) goto LAB_71005cc7d8;
  }
  else if (fVar15 < fVar14) {
LAB_71005cc7d8:
    fVar15 = pfVar9[3];
    *(undefined8 *)(pfVar9 + 2) = *(undefined8 *)pfVar9;
    pfVar5 = param_1;
    if (pfVar9 != param_1) {
      lVar11 = lVar6;
      if (fVar14 < 0.0) {
        do {
          pfVar1 = (float *)((long)param_1 + lVar11);
          fVar16 = pfVar1[-2];
          if (fVar16 < 0.0) {
            pfVar5 = pfVar1;
            if (fVar14 <= fVar16) break;
          }
          else {
            pfVar5 = pfVar9;
            if (fVar16 <= fVar14) break;
          }
          pfVar9 = pfVar9 + -2;
          lVar11 = lVar11 + -8;
          *(undefined8 *)pfVar1 = *(undefined8 *)(pfVar1 + -2);
          pfVar5 = param_1;
        } while (lVar11 != 0);
      }
      else {
        do {
          pfVar5 = (float *)((long)param_1 + lVar11);
          if (pfVar5[-2] <= fVar14) break;
          lVar11 = lVar11 + -8;
          *(undefined8 *)pfVar5 = *(undefined8 *)(pfVar5 + -2);
          pfVar5 = param_1;
        } while (lVar11 != 0);
      }
    }
    *pfVar5 = fVar14;
    pfVar5[1] = fVar15;
  }
  pfVar5 = pfVar10 + 2;
  lVar6 = lVar6 + 8;
  pfVar9 = pfVar10;
  pfVar10 = pfVar5;
  if (pfVar5 == param_2) {
switchD_71005cc694_caseD_0:
    return;
  }
  goto LAB_71005cc7a4;
}



undefined8 FUN_71005cca40(float *param_1,float *param_2,float *param_3)

{
  undefined8 uVar1;
  float fVar2;
  float fVar3;
  
  fVar2 = *param_2;
  fVar3 = *param_1;
  if ((0.0 <= fVar2) || (0.0 <= fVar3)) {
    if (fVar3 <= fVar2) goto LAB_71005cca60;
  }
  else if (fVar2 <= fVar3) {
LAB_71005cca60:
    fVar3 = *param_3;
    if ((0.0 <= fVar2) || (0.0 <= fVar3)) {
      if (fVar2 <= fVar3) {
        return 0;
      }
    }
    else if (fVar3 <= fVar2) {
      return 0;
    }
    uVar1 = *(undefined8 *)param_2;
    *(undefined8 *)param_2 = *(undefined8 *)param_3;
    *(undefined8 *)param_3 = uVar1;
    fVar2 = *param_2;
    fVar3 = *param_1;
    if ((0.0 <= fVar2) || (0.0 <= fVar3)) {
      if (fVar3 <= fVar2) {
        return 1;
      }
    }
    else if (fVar2 <= fVar3) {
      return 1;
    }
    uVar1 = *(undefined8 *)param_1;
    *(undefined8 *)param_1 = *(undefined8 *)param_2;
    *(undefined8 *)param_2 = uVar1;
    return 2;
  }
  fVar3 = *param_3;
  if ((0.0 <= fVar2) || (0.0 <= fVar3)) {
    if (fVar3 < fVar2) goto LAB_71005ccb20;
  }
  else if (fVar2 < fVar3) {
LAB_71005ccb20:
    uVar1 = *(undefined8 *)param_1;
    *(undefined8 *)param_1 = *(undefined8 *)param_3;
    *(undefined8 *)param_3 = uVar1;
    return 1;
  }
  uVar1 = *(undefined8 *)param_1;
  *(undefined8 *)param_1 = *(undefined8 *)param_2;
  *(undefined8 *)param_2 = uVar1;
  fVar2 = (float)uVar1;
  fVar3 = *param_3;
  if ((0.0 <= fVar3) || (0.0 <= fVar2)) {
    if (fVar2 <= fVar3) {
      return 1;
    }
  }
  else if (fVar3 <= fVar2) {
    return 1;
  }
  *(undefined8 *)param_2 = *(undefined8 *)param_3;
  *(undefined8 *)param_3 = uVar1;
  return 2;
}



float * FUN_71005ccb80(float *param_1,float *param_2)

{
  float fVar1;
  float fVar2;
  float *pfVar3;
  undefined8 uVar4;
  float fVar5;
  float fVar6;
  
  fVar1 = *param_1;
  fVar2 = param_1[1];
  fVar5 = param_2[-2];
  if ((0.0 <= fVar1) || (0.0 <= fVar5)) {
    if (fVar1 < fVar5) goto LAB_71005ccc14;
  }
  else if (fVar5 < fVar1) {
LAB_71005ccc14:
    pfVar3 = param_1;
    if (fVar1 < 0.0) {
      do {
        while( true ) {
          pfVar3 = pfVar3 + 2;
          fVar6 = *pfVar3;
          if (0.0 <= fVar6) break;
          if (fVar6 < fVar1) goto LAB_71005ccc5c;
        }
      } while (fVar6 <= fVar1);
    }
    else {
      do {
        pfVar3 = pfVar3 + 2;
      } while (*pfVar3 <= fVar1);
    }
    goto LAB_71005ccc5c;
  }
  pfVar3 = param_1 + 2;
  if (pfVar3 < param_2) {
    if (fVar1 < 0.0) {
      do {
        fVar6 = *pfVar3;
        if (0.0 <= fVar6) {
          if (fVar1 < fVar6) break;
        }
        else if (fVar6 < fVar1) break;
        pfVar3 = pfVar3 + 2;
      } while (pfVar3 < param_2);
    }
    else {
      do {
        if (fVar1 < *pfVar3) break;
        pfVar3 = pfVar3 + 2;
      } while (pfVar3 < param_2);
    }
  }
LAB_71005ccc5c:
  if (pfVar3 < param_2) {
    if (fVar1 < 0.0) {
      param_2 = param_2 + -2;
      do {
        if (0.0 <= fVar5) {
          if (fVar5 <= fVar1) goto LAB_71005ccd20;
        }
        else if (fVar1 <= fVar5) goto LAB_71005ccd20;
        param_2 = param_2 + -2;
        fVar5 = *param_2;
      } while( true );
    }
    do {
      param_2 = param_2 + -2;
    } while (fVar1 < *param_2);
  }
LAB_71005ccd20:
  do {
    if (param_2 <= pfVar3) {
      if (pfVar3 + -2 != param_1) {
        *(undefined8 *)param_1 = *(undefined8 *)(pfVar3 + -2);
      }
      pfVar3[-2] = fVar1;
      pfVar3[-1] = fVar2;
      return pfVar3;
    }
    uVar4 = *(undefined8 *)pfVar3;
    *(undefined8 *)pfVar3 = *(undefined8 *)param_2;
    *(undefined8 *)param_2 = uVar4;
    if (fVar1 < 0.0) {
      do {
        while( true ) {
          pfVar3 = pfVar3 + 2;
          fVar5 = *pfVar3;
          if (0.0 <= fVar5) break;
          if (fVar5 < fVar1) goto LAB_71005cccec;
        }
      } while (fVar5 <= fVar1);
    }
    else {
      do {
        pfVar3 = pfVar3 + 2;
      } while (*pfVar3 <= fVar1);
    }
LAB_71005cccec:
    if (0.0 <= fVar1) {
      do {
        param_2 = param_2 + -2;
      } while (fVar1 < *param_2);
      goto LAB_71005ccd20;
    }
    do {
      while( true ) {
        param_2 = param_2 + -2;
        fVar5 = *param_2;
        if (0.0 <= fVar5) break;
        if (fVar1 <= fVar5) goto LAB_71005ccd20;
      }
    } while (fVar1 < fVar5);
  } while( true );
}



float * FUN_71005ccd50(float *param_1,float *param_2)

{
  float fVar1;
  float *pfVar2;
  float *pfVar3;
  undefined8 uVar4;
  float fVar5;
  float fVar6;
  
  fVar1 = *param_1;
  pfVar3 = param_1;
  if (fVar1 < 0.0) {
    do {
      while( true ) {
        pfVar3 = pfVar3 + 2;
        fVar5 = *pfVar3;
        if (0.0 <= fVar5) break;
        if (fVar5 <= fVar1) goto LAB_71005ccdac;
      }
    } while (fVar5 < fVar1);
  }
  else {
    do {
      pfVar3 = pfVar3 + 2;
    } while (*pfVar3 < fVar1);
  }
LAB_71005ccdac:
  if (pfVar3 + -2 == param_1) {
    if (pfVar3 < param_2) {
      if (fVar1 < 0.0) {
        do {
          while( true ) {
            param_2 = param_2 + -2;
            fVar5 = *param_2;
            if (0.0 <= fVar5) break;
            if (fVar1 < fVar5 || param_2 <= pfVar3) goto LAB_71005cce54;
          }
        } while (fVar1 <= fVar5 && pfVar3 < param_2);
      }
      else {
        do {
          param_2 = param_2 + -2;
        } while (fVar1 <= *param_2 && pfVar3 < param_2);
      }
    }
  }
  else if (fVar1 < 0.0) {
    do {
      while( true ) {
        param_2 = param_2 + -2;
        fVar5 = *param_2;
        if (0.0 <= fVar5) break;
        if (fVar1 < fVar5) goto LAB_71005cce54;
      }
    } while (fVar1 <= fVar5);
  }
  else {
    do {
      param_2 = param_2 + -2;
    } while (fVar1 <= *param_2);
  }
LAB_71005cce54:
  fVar5 = param_1[1];
  if (pfVar3 < param_2) {
    do {
      uVar4 = *(undefined8 *)pfVar3;
      *(undefined8 *)pfVar3 = *(undefined8 *)param_2;
      *(undefined8 *)param_2 = uVar4;
      if (fVar1 < 0.0) {
        do {
          while( true ) {
            pfVar3 = pfVar3 + 2;
            fVar6 = *pfVar3;
            if (0.0 <= fVar6) break;
            if (fVar6 <= fVar1) goto LAB_71005ccebc;
          }
        } while (fVar6 < fVar1);
      }
      else {
        do {
          pfVar3 = pfVar3 + 2;
        } while (*pfVar3 < fVar1);
      }
LAB_71005ccebc:
      if (fVar1 < 0.0) {
        do {
          while( true ) {
            param_2 = param_2 + -2;
            fVar6 = *param_2;
            if (0.0 <= fVar6) break;
            if (fVar1 < fVar6) goto LAB_71005cce70;
          }
        } while (fVar1 <= fVar6);
      }
      else {
        do {
          param_2 = param_2 + -2;
        } while (fVar1 <= *param_2);
      }
LAB_71005cce70:
    } while (pfVar3 < param_2);
  }
  pfVar2 = pfVar3 + -2;
  if (pfVar2 != param_1) {
    *(undefined8 *)param_1 = *(undefined8 *)pfVar2;
  }
  pfVar3[-2] = fVar1;
  pfVar3[-1] = fVar5;
  return pfVar2;
}



bool FUN_71005ccf20(float *param_1,float *param_2)

{
  undefined8 uVar1;
  bool bVar2;
  float *pfVar3;
  undefined8 uVar4;
  long lVar5;
  int iVar6;
  float *pfVar7;
  long lVar8;
  long lVar9;
  float *pfVar10;
  float fVar11;
  float fVar12;
  float fVar13;
  
  bVar2 = true;
  switch((long)param_2 - (long)param_1 >> 3) {
  case 0:
  case 1:
    return bVar2;
  case 2:
    fVar11 = param_2[-2];
    fVar12 = *param_1;
    if ((0.0 <= fVar11) || (0.0 <= fVar12)) {
      if (fVar12 <= fVar11) {
        return bVar2;
      }
    }
    else if (fVar11 <= fVar12) {
      return bVar2;
    }
    uVar4 = *(undefined8 *)param_1;
    *(undefined8 *)param_1 = *(undefined8 *)(param_2 + -2);
    *(undefined8 *)(param_2 + -2) = uVar4;
    return bVar2;
  case 3:
    FUN_71005cca40(param_1,param_1 + 2,param_2 + -2);
    return true;
  case 4:
    pfVar7 = param_1 + 4;
    FUN_71005cca40(param_1,param_1 + 2,pfVar7);
    fVar11 = param_2[-2];
    fVar12 = param_1[4];
    if ((0.0 <= fVar11) || (0.0 <= fVar12)) {
      if (fVar12 <= fVar11) {
        return true;
      }
    }
    else if (fVar11 <= fVar12) {
      return true;
    }
    uVar4 = *(undefined8 *)pfVar7;
    *(undefined8 *)pfVar7 = *(undefined8 *)(param_2 + -2);
    *(undefined8 *)(param_2 + -2) = uVar4;
    fVar11 = *pfVar7;
    fVar12 = param_1[2];
    if ((0.0 <= fVar11) || (0.0 <= fVar12)) {
      if (fVar12 <= fVar11) {
        return true;
      }
    }
    else if (fVar11 <= fVar12) {
      return true;
    }
    uVar4 = *(undefined8 *)(param_1 + 2);
    uVar1 = *(undefined8 *)(param_1 + 4);
    fVar12 = *param_1;
    *(undefined8 *)(param_1 + 2) = uVar1;
    *(undefined8 *)(param_1 + 4) = uVar4;
    fVar11 = (float)uVar1;
    if ((0.0 <= fVar11) || (0.0 <= fVar12)) {
      if (fVar11 < fVar12) goto LAB_71005cd22c;
    }
    else if (fVar12 < fVar11) {
LAB_71005cd22c:
      uVar4 = *(undefined8 *)param_1;
      *(undefined8 *)param_1 = uVar1;
      *(undefined8 *)(param_1 + 2) = uVar4;
      return true;
    }
    break;
  case 5:
    FUN_71005cd250(param_1,param_1 + 2,param_1 + 4,param_1 + 6,param_2 + -2);
    return true;
  default:
    FUN_71005cca40(param_1,param_1 + 2,param_1 + 4);
    if (param_1 + 6 != param_2) {
      lVar5 = 0;
      iVar6 = 0;
      pfVar7 = param_1 + 6;
      pfVar10 = param_1 + 4;
      do {
        pfVar3 = pfVar7;
        fVar11 = *pfVar3;
        fVar12 = *pfVar10;
        if ((0.0 <= fVar11) || (0.0 <= fVar12)) {
          if (fVar11 < fVar12) goto LAB_71005cd008;
        }
        else if (fVar12 < fVar11) {
LAB_71005cd008:
          fVar12 = pfVar3[1];
          *(undefined8 *)pfVar3 = *(undefined8 *)pfVar10;
          pfVar7 = param_1;
          if (pfVar10 != param_1) {
            lVar8 = lVar5;
            if (fVar11 < 0.0) {
              do {
                fVar13 = *(float *)((long)param_1 + lVar8 + 8);
                if (0.0 <= fVar13) {
                  if (fVar13 <= fVar11) {
                    pfVar7 = (float *)((long)param_1 + lVar8 + 0x10);
                    break;
                  }
                }
                else {
                  pfVar7 = pfVar10;
                  if (fVar11 <= fVar13) break;
                }
                lVar9 = lVar8 + -8;
                pfVar10 = pfVar10 + -2;
                *(undefined8 *)((long)param_1 + lVar8 + 0x10) =
                     *(undefined8 *)((long)param_1 + lVar8 + 8);
                pfVar7 = param_1;
                lVar8 = lVar9;
              } while (lVar9 != -0x10);
            }
            else {
              do {
                if (*(float *)((long)param_1 + lVar8 + 8) <= fVar11) {
                  pfVar7 = (float *)((long)param_1 + lVar8 + 0x10);
                  break;
                }
                lVar9 = lVar8 + -8;
                *(undefined8 *)((long)param_1 + lVar8 + 0x10) =
                     *(undefined8 *)((long)param_1 + lVar8 + 8);
                lVar8 = lVar9;
              } while (lVar9 != -0x10);
            }
          }
          iVar6 = iVar6 + 1;
          *pfVar7 = fVar11;
          pfVar7[1] = fVar12;
          if (iVar6 == 8) {
            return pfVar3 + 2 == param_2;
          }
        }
        lVar5 = lVar5 + 8;
        pfVar7 = pfVar3 + 2;
        pfVar10 = pfVar3;
      } while (pfVar3 + 2 != param_2);
    }
  }
  return true;
}



void FUN_71005cd250(float *param_1,float *param_2,float *param_3,float *param_4,float *param_5)

{
  undefined8 uVar1;
  float fVar2;
  float fVar3;
  
  FUN_71005cca40(param_1,param_2,param_3);
  fVar2 = *param_4;
  fVar3 = *param_3;
  if ((0.0 <= fVar2) || (0.0 <= fVar3)) {
    if (fVar2 < fVar3) goto LAB_71005cd2ac;
  }
  else if (fVar3 < fVar2) {
LAB_71005cd2ac:
    uVar1 = *(undefined8 *)param_3;
    *(undefined8 *)param_3 = *(undefined8 *)param_4;
    *(undefined8 *)param_4 = uVar1;
    fVar2 = *param_3;
    fVar3 = *param_2;
    if ((0.0 <= fVar2) || (0.0 <= fVar3)) {
      if (fVar2 < fVar3) goto LAB_71005cd2e8;
    }
    else if (fVar3 < fVar2) {
LAB_71005cd2e8:
      uVar1 = *(undefined8 *)param_2;
      *(undefined8 *)param_2 = *(undefined8 *)param_3;
      *(undefined8 *)param_3 = uVar1;
      fVar2 = *param_2;
      fVar3 = *param_1;
      if ((0.0 <= fVar2) || (0.0 <= fVar3)) {
        if (fVar2 < fVar3) goto LAB_71005cd324;
      }
      else if (fVar3 < fVar2) {
LAB_71005cd324:
        uVar1 = *(undefined8 *)param_1;
        *(undefined8 *)param_1 = *(undefined8 *)param_2;
        *(undefined8 *)param_2 = uVar1;
      }
    }
  }
  fVar2 = *param_5;
  fVar3 = *param_4;
  if ((0.0 <= fVar2) || (0.0 <= fVar3)) {
    if (fVar3 <= fVar2) {
      return;
    }
  }
  else if (fVar2 <= fVar3) {
    return;
  }
  uVar1 = *(undefined8 *)param_4;
  *(undefined8 *)param_4 = *(undefined8 *)param_5;
  *(undefined8 *)param_5 = uVar1;
  fVar2 = *param_4;
  fVar3 = *param_3;
  if ((0.0 <= fVar2) || (0.0 <= fVar3)) {
    if (fVar3 <= fVar2) {
      return;
    }
  }
  else if (fVar2 <= fVar3) {
    return;
  }
  uVar1 = *(undefined8 *)param_3;
  *(undefined8 *)param_3 = *(undefined8 *)param_4;
  *(undefined8 *)param_4 = uVar1;
  fVar2 = *param_3;
  fVar3 = *param_2;
  if ((0.0 <= fVar2) || (0.0 <= fVar3)) {
    if (fVar3 <= fVar2) {
      return;
    }
  }
  else if (fVar2 <= fVar3) {
    return;
  }
  uVar1 = *(undefined8 *)param_2;
  *(undefined8 *)param_2 = *(undefined8 *)param_3;
  *(undefined8 *)param_3 = uVar1;
  fVar2 = *param_2;
  fVar3 = *param_1;
  if ((0.0 <= fVar2) || (0.0 <= fVar3)) {
    if (fVar2 < fVar3) goto LAB_71005cd424;
  }
  else if (fVar3 < fVar2) {
LAB_71005cd424:
    uVar1 = *(undefined8 *)param_1;
    *(undefined8 *)param_1 = *(undefined8 *)param_2;
    *(undefined8 *)param_2 = uVar1;
    return;
  }
  return;
}



void FUN_71005cd450(long param_1,undefined8 param_2,long param_3,float *param_4)

{
  ulong uVar1;
  ulong uVar2;
  float *pfVar3;
  float *pfVar4;
  ulong uVar5;
  long lVar6;
  float fVar7;
  float fVar8;
  float fVar9;
  float fVar10;
  
  if (param_3 < 2) {
    return;
  }
  uVar2 = param_3 - 2U >> 1;
  if ((long)uVar2 < (long)param_4 - param_1 >> 3) {
    return;
  }
  lVar6 = (long)param_4 - param_1 >> 2;
  uVar5 = lVar6 + 1;
  uVar1 = lVar6 + 2;
  pfVar3 = (float *)(param_1 + uVar5 * 8);
  if ((long)uVar1 < param_3) {
    fVar8 = *pfVar3;
    fVar7 = pfVar3[2];
    if ((0.0 <= fVar8) || (0.0 <= fVar7)) {
      if (fVar8 < fVar7) goto LAB_71005cd4b0;
    }
    else if (fVar7 < fVar8) {
LAB_71005cd4b0:
      pfVar3 = pfVar3 + 2;
      uVar5 = uVar1;
    }
  }
  fVar8 = *pfVar3;
  fVar7 = *param_4;
  if ((0.0 <= fVar8) || (0.0 <= fVar7)) {
    if (fVar7 <= fVar8) goto LAB_71005cd4e4;
  }
  else if (fVar8 <= fVar7) {
LAB_71005cd4e4:
    fVar8 = param_4[1];
    *(undefined8 *)param_4 = *(undefined8 *)pfVar3;
    if ((long)uVar5 <= (long)uVar2) {
      pfVar4 = pfVar3;
      if (fVar7 < 0.0) {
        do {
          lVar6 = uVar5 * 2;
          uVar5 = uVar5 << 1 | 1;
          uVar1 = lVar6 + 2;
          pfVar3 = (float *)(param_1 + uVar5 * 8);
          if ((long)uVar1 < param_3) {
            fVar10 = *pfVar3;
            fVar9 = pfVar3[2];
            if ((0.0 <= fVar10) || (0.0 <= fVar9)) {
              if (fVar10 < fVar9) goto LAB_71005cd5fc;
            }
            else if (fVar9 < fVar10) {
LAB_71005cd5fc:
              uVar5 = uVar1;
              pfVar3 = pfVar3 + 2;
            }
          }
          fVar9 = *pfVar3;
          if (0.0 <= fVar9) {
            if (fVar9 < fVar7) goto LAB_71005cd618;
          }
          else if (fVar7 < fVar9) goto LAB_71005cd618;
          *(undefined8 *)pfVar4 = *(undefined8 *)pfVar3;
          pfVar4 = pfVar3;
        } while ((long)uVar5 <= (long)uVar2);
      }
      else {
        do {
          lVar6 = uVar5 * 2;
          uVar5 = uVar5 << 1 | 1;
          uVar1 = lVar6 + 2;
          pfVar3 = (float *)(param_1 + uVar5 * 8);
          if ((long)uVar1 < param_3) {
            fVar10 = *pfVar3;
            fVar9 = pfVar3[2];
            if ((0.0 <= fVar10) || (0.0 <= fVar9)) {
              if (fVar10 < fVar9) goto LAB_71005cd560;
            }
            else if (fVar9 < fVar10) {
LAB_71005cd560:
              uVar5 = uVar1;
              pfVar3 = pfVar3 + 2;
            }
          }
          if (*pfVar3 < fVar7) {
LAB_71005cd618:
            *pfVar4 = fVar7;
            pfVar4[1] = fVar8;
            return;
          }
          *(undefined8 *)pfVar4 = *(undefined8 *)pfVar3;
          pfVar4 = pfVar3;
        } while ((long)uVar5 <= (long)uVar2);
      }
    }
    *pfVar3 = fVar7;
    pfVar3[1] = fVar8;
    return;
  }
  return;
}



void FUN_71005cd630(float *param_1,long param_2,undefined8 param_3,long param_4)

{
  float *pfVar1;
  undefined8 uVar2;
  ulong uVar3;
  float *pfVar4;
  ulong uVar5;
  ulong uVar6;
  float fVar7;
  float fVar8;
  float fVar9;
  
  if (1 < param_4) {
    uVar2 = *(undefined8 *)param_1;
    pfVar4 = param_1;
    uVar3 = 0;
    do {
      uVar5 = uVar3 << 1 | 1;
      uVar6 = uVar3 * 2 + 2;
      pfVar1 = pfVar4 + uVar3 * 2 + 2;
      if ((long)uVar6 < param_4) {
        fVar8 = *pfVar1;
        fVar7 = pfVar4[uVar3 * 2 + 4];
        if ((0.0 <= fVar8) || (0.0 <= fVar7)) {
          if (fVar8 < fVar7) goto LAB_71005cd650;
        }
        else if (fVar7 < fVar8) {
LAB_71005cd650:
          pfVar1 = pfVar4 + uVar3 * 2 + 4;
          uVar5 = uVar6;
        }
      }
      *(undefined8 *)pfVar4 = *(undefined8 *)pfVar1;
      pfVar4 = pfVar1;
      uVar3 = uVar5;
    } while ((long)uVar5 <= (long)(param_4 - 2U >> 1));
    pfVar4 = (float *)(param_2 + -8);
    if (pfVar1 == pfVar4) {
      *(undefined8 *)pfVar1 = uVar2;
      return;
    }
    *(undefined8 *)pfVar1 = *(undefined8 *)pfVar4;
    *(undefined8 *)pfVar4 = uVar2;
    uVar3 = (long)pfVar1 + (8 - (long)param_1);
    if (8 < (long)uVar3) {
      fVar7 = *pfVar1;
      uVar6 = (uVar3 >> 3) - 2;
      uVar3 = uVar6 >> 1;
      pfVar4 = param_1 + uVar3 * 2;
      fVar8 = *pfVar4;
      if ((0.0 <= fVar8) || (0.0 <= fVar7)) {
        if (fVar8 < fVar7) {
LAB_71005cd738:
          fVar8 = pfVar1[1];
          *(undefined8 *)pfVar1 = *(undefined8 *)pfVar4;
          if (1 < uVar6) {
            pfVar1 = pfVar4;
            if (fVar7 < 0.0) {
              do {
                uVar6 = uVar3 - 1;
                uVar3 = uVar6 >> 1;
                pfVar4 = param_1 + uVar3 * 2;
                fVar9 = *pfVar4;
                if (0.0 <= fVar9) {
                  if (fVar7 <= fVar9) goto LAB_71005cd7d0;
                }
                else if (fVar9 <= fVar7) goto LAB_71005cd7d0;
                *(undefined8 *)pfVar1 = *(undefined8 *)pfVar4;
                pfVar1 = pfVar4;
              } while (1 < uVar6);
            }
            else {
              do {
                uVar6 = uVar3 - 1;
                uVar3 = uVar6 >> 1;
                pfVar4 = param_1 + uVar3 * 2;
                if (fVar7 <= *pfVar4) {
LAB_71005cd7d0:
                  *pfVar1 = fVar7;
                  pfVar1[1] = fVar8;
                  return;
                }
                *(undefined8 *)pfVar1 = *(undefined8 *)pfVar4;
                pfVar1 = pfVar4;
              } while (1 < uVar6);
            }
          }
          *pfVar4 = fVar7;
          pfVar4[1] = fVar8;
          return;
        }
      }
      else if (fVar7 < fVar8) goto LAB_71005cd738;
    }
  }
  return;
}



void FUN_71005cd7e0(float *param_1,float *param_2,undefined8 param_3,long param_4,uint param_5)

{
  float *pfVar1;
  undefined8 uVar2;
  bool bVar3;
  bool bVar4;
  float *pfVar5;
  ulong extraout_x1;
  long lVar6;
  undefined8 uVar7;
  ulong uVar8;
  float *pfVar9;
  float *pfVar10;
  long lVar11;
  ulong uVar12;
  ulong uVar13;
  float fVar14;
  float fVar15;
  float fVar16;
  
LAB_71005cd810:
  pfVar10 = param_2 + -2;
  do {
    lVar6 = -param_4;
    pfVar9 = param_1;
    do {
      param_1 = pfVar9;
      lVar6 = lVar6 + 1;
      uVar13 = (long)param_2 - (long)param_1;
      uVar12 = (long)uVar13 >> 3;
      switch(uVar12) {
      case 0:
      case 1:
        goto switchD_71005cd9f4_caseD_0;
      case 2:
        fVar14 = param_2[-2];
        fVar15 = *param_1;
        if ((0.0 <= fVar14) || (0.0 <= fVar15)) {
          if (fVar14 <= fVar15) {
            return;
          }
        }
        else if (fVar15 <= fVar14) {
          return;
        }
        uVar7 = *(undefined8 *)param_1;
        *(undefined8 *)param_1 = *(undefined8 *)(param_2 + -2);
        *(undefined8 *)(param_2 + -2) = uVar7;
        return;
      case 3:
        FUN_71005cdda0(param_1,param_1 + 2,pfVar10);
        return;
      case 4:
        pfVar10 = param_1 + 4;
        FUN_71005cdda0(param_1,param_1 + 2,pfVar10);
        fVar14 = param_2[-2];
        fVar15 = param_1[4];
        if ((0.0 <= fVar14) || (0.0 <= fVar15)) {
          if (fVar14 <= fVar15) {
            return;
          }
        }
        else if (fVar15 <= fVar14) {
          return;
        }
        uVar7 = *(undefined8 *)pfVar10;
        *(undefined8 *)pfVar10 = *(undefined8 *)(param_2 + -2);
        *(undefined8 *)(param_2 + -2) = uVar7;
        fVar14 = *pfVar10;
        fVar15 = param_1[2];
        if ((0.0 <= fVar14) || (0.0 <= fVar15)) {
          if (fVar14 <= fVar15) {
            return;
          }
        }
        else if (fVar15 <= fVar14) {
          return;
        }
        uVar7 = *(undefined8 *)(param_1 + 2);
        uVar2 = *(undefined8 *)(param_1 + 4);
        fVar15 = *param_1;
        *(undefined8 *)(param_1 + 2) = uVar2;
        *(undefined8 *)(param_1 + 4) = uVar7;
        fVar14 = (float)uVar2;
        if ((0.0 <= fVar14) || (0.0 <= fVar15)) {
          if (fVar14 <= fVar15) {
            return;
          }
        }
        else if (fVar15 <= fVar14) {
          return;
        }
        uVar7 = *(undefined8 *)param_1;
        *(undefined8 *)param_1 = uVar2;
        *(undefined8 *)(param_1 + 2) = uVar7;
        return;
      case 5:
        FUN_71005ce5b0(param_1,param_1 + 2,param_1 + 4,param_1 + 6,pfVar10);
        return;
      }
      if ((long)uVar13 < 0xc0) {
        pfVar10 = param_1 + 2;
        if ((param_5 & 1) == 0) {
          if (param_1 == param_2 || pfVar10 == param_2) {
            return;
          }
          goto LAB_71005cdca4;
        }
        if (param_1 == param_2 || pfVar10 == param_2) {
          return;
        }
        lVar6 = 0;
        pfVar9 = param_1;
        goto LAB_71005cdb04;
      }
      if (lVar6 == 1) {
        if (param_1 == param_2) {
          return;
        }
        uVar8 = uVar12 - 2 >> 1;
        pfVar10 = param_1 + uVar8 * 2;
        lVar6 = uVar8 + 1;
        do {
          FUN_71005ce7b0((long)param_1,param_3,uVar12,pfVar10);
          lVar6 = lVar6 + -1;
          pfVar10 = pfVar10 + -2;
        } while (lVar6 != 0);
        uVar12 = uVar13 >> 3;
        do {
          FUN_71005ce990(param_1,(long)param_2,param_3,uVar12);
          param_2 = param_2 + -2;
          bVar3 = 2 < uVar12;
          uVar12 = uVar12 - 1;
        } while (bVar3);
        return;
      }
      uVar12 = uVar12 >> 1;
      pfVar9 = param_1 + uVar12 * 2;
      if (uVar13 < 0x401) {
        FUN_71005cdda0(pfVar9,param_1,pfVar10);
      }
      else {
        FUN_71005cdda0(param_1,pfVar9,pfVar10);
        pfVar1 = param_1 + uVar12 * 2;
        pfVar5 = param_1 + 2;
        FUN_71005cdda0(pfVar5,pfVar1 + -2,param_2 + -4);
        FUN_71005cdda0(param_1 + 4,pfVar5 + uVar12 * 2,param_2 + -6);
        FUN_71005cdda0(pfVar1 + -2,pfVar9,pfVar5 + uVar12 * 2);
        uVar7 = *(undefined8 *)param_1;
        *(undefined8 *)param_1 = *(undefined8 *)pfVar1;
        *(undefined8 *)pfVar1 = uVar7;
      }
      if ((param_5 & 1) == 0) {
        fVar14 = param_1[-2];
        fVar15 = *param_1;
        if ((0.0 <= fVar14) || (0.0 <= fVar15)) {
          if (fVar14 <= fVar15) goto LAB_71005cd9b0;
        }
        else if (fVar15 <= fVar14) {
LAB_71005cd9b0:
          param_1 = FUN_71005cdee0(param_1,param_2);
          goto LAB_71005cd9c4;
        }
      }
      pfVar5 = FUN_71005ce0b0(param_1,param_2);
      if ((extraout_x1 & 1) == 0) break;
      bVar3 = FUN_71005ce280(param_1,pfVar5);
      bVar4 = FUN_71005ce280(pfVar5 + 2,param_2);
      if (bVar4) {
        param_4 = -lVar6;
        param_2 = pfVar5;
        if (bVar3) {
          return;
        }
        goto LAB_71005cd810;
      }
      pfVar9 = pfVar5 + 2;
    } while (bVar3);
    FUN_71005cd7e0(param_1,pfVar5,param_3,-lVar6,param_5 & 1);
    param_1 = pfVar5 + 2;
LAB_71005cd9c4:
    param_5 = 0;
    param_4 = -lVar6;
  } while( true );
LAB_71005cdca4:
  pfVar9 = pfVar10;
  fVar14 = param_1[2];
  fVar15 = *param_1;
  if ((0.0 <= fVar14) || (0.0 <= fVar15)) {
    if (fVar15 < fVar14) goto LAB_71005cdcd8;
  }
  else if (fVar14 < fVar15) {
LAB_71005cdcd8:
    fVar15 = param_1[3];
    pfVar10 = pfVar9;
    if (fVar14 < 0.0) {
      do {
        while( true ) {
          pfVar5 = param_1;
          *(undefined8 *)(pfVar5 + 2) = *(undefined8 *)pfVar5;
          param_1 = pfVar5 + -2;
          fVar16 = *param_1;
          if (0.0 <= fVar16) break;
          if (fVar16 <= fVar14) goto LAB_71005cdc90;
        }
      } while (fVar16 < fVar14);
    }
    else {
      do {
        pfVar1 = pfVar10 + -4;
        pfVar5 = pfVar10 + -2;
        *(undefined8 *)pfVar10 = *(undefined8 *)pfVar5;
        pfVar10 = pfVar5;
      } while (*pfVar1 < fVar14);
    }
LAB_71005cdc90:
    *pfVar5 = fVar14;
    pfVar5[1] = fVar15;
  }
  pfVar10 = pfVar9 + 2;
  param_1 = pfVar9;
  if (pfVar9 + 2 == param_2) {
    return;
  }
  goto LAB_71005cdca4;
LAB_71005cdb04:
  fVar14 = pfVar9[2];
  fVar15 = *pfVar9;
  if ((0.0 <= fVar14) || (0.0 <= fVar15)) {
    if (fVar15 < fVar14) goto LAB_71005cdb38;
  }
  else if (fVar14 < fVar15) {
LAB_71005cdb38:
    fVar15 = pfVar9[3];
    *(undefined8 *)(pfVar9 + 2) = *(undefined8 *)pfVar9;
    pfVar5 = param_1;
    if (pfVar9 != param_1) {
      lVar11 = lVar6;
      if (fVar14 < 0.0) {
        do {
          pfVar1 = (float *)((long)param_1 + lVar11);
          fVar16 = pfVar1[-2];
          if (fVar16 < 0.0) {
            pfVar5 = pfVar1;
            if (fVar16 <= fVar14) break;
          }
          else {
            pfVar5 = pfVar9;
            if (fVar14 <= fVar16) break;
          }
          pfVar9 = pfVar9 + -2;
          lVar11 = lVar11 + -8;
          *(undefined8 *)pfVar1 = *(undefined8 *)(pfVar1 + -2);
          pfVar5 = param_1;
        } while (lVar11 != 0);
      }
      else {
        do {
          pfVar5 = (float *)((long)param_1 + lVar11);
          if (fVar14 <= pfVar5[-2]) break;
          lVar11 = lVar11 + -8;
          *(undefined8 *)pfVar5 = *(undefined8 *)(pfVar5 + -2);
          pfVar5 = param_1;
        } while (lVar11 != 0);
      }
    }
    *pfVar5 = fVar14;
    pfVar5[1] = fVar15;
  }
  pfVar5 = pfVar10 + 2;
  lVar6 = lVar6 + 8;
  pfVar9 = pfVar10;
  pfVar10 = pfVar5;
  if (pfVar5 == param_2) {
switchD_71005cd9f4_caseD_0:
    return;
  }
  goto LAB_71005cdb04;
}



undefined8 FUN_71005cdda0(float *param_1,float *param_2,float *param_3)

{
  undefined8 uVar1;
  float fVar2;
  float fVar3;
  
  fVar2 = *param_2;
  fVar3 = *param_1;
  if ((0.0 <= fVar2) || (0.0 <= fVar3)) {
    if (fVar2 <= fVar3) goto LAB_71005cddc0;
  }
  else if (fVar3 <= fVar2) {
LAB_71005cddc0:
    fVar3 = *param_3;
    if ((0.0 <= fVar2) || (0.0 <= fVar3)) {
      if (fVar3 <= fVar2) {
        return 0;
      }
    }
    else if (fVar2 <= fVar3) {
      return 0;
    }
    uVar1 = *(undefined8 *)param_2;
    *(undefined8 *)param_2 = *(undefined8 *)param_3;
    *(undefined8 *)param_3 = uVar1;
    fVar2 = *param_2;
    fVar3 = *param_1;
    if ((0.0 <= fVar2) || (0.0 <= fVar3)) {
      if (fVar2 <= fVar3) {
        return 1;
      }
    }
    else if (fVar3 <= fVar2) {
      return 1;
    }
    uVar1 = *(undefined8 *)param_1;
    *(undefined8 *)param_1 = *(undefined8 *)param_2;
    *(undefined8 *)param_2 = uVar1;
    return 2;
  }
  fVar3 = *param_3;
  if ((0.0 <= fVar2) || (0.0 <= fVar3)) {
    if (fVar2 < fVar3) goto LAB_71005cde80;
  }
  else if (fVar3 < fVar2) {
LAB_71005cde80:
    uVar1 = *(undefined8 *)param_1;
    *(undefined8 *)param_1 = *(undefined8 *)param_3;
    *(undefined8 *)param_3 = uVar1;
    return 1;
  }
  uVar1 = *(undefined8 *)param_1;
  *(undefined8 *)param_1 = *(undefined8 *)param_2;
  *(undefined8 *)param_2 = uVar1;
  fVar2 = (float)uVar1;
  fVar3 = *param_3;
  if ((0.0 <= fVar3) || (0.0 <= fVar2)) {
    if (fVar3 <= fVar2) {
      return 1;
    }
  }
  else if (fVar2 <= fVar3) {
    return 1;
  }
  *(undefined8 *)param_2 = *(undefined8 *)param_3;
  *(undefined8 *)param_3 = uVar1;
  return 2;
}



float * FUN_71005cdee0(float *param_1,float *param_2)

{
  float fVar1;
  float fVar2;
  float *pfVar3;
  undefined8 uVar4;
  float fVar5;
  float fVar6;
  
  fVar1 = *param_1;
  fVar2 = param_1[1];
  fVar5 = param_2[-2];
  if ((0.0 <= fVar1) || (0.0 <= fVar5)) {
    if (fVar5 < fVar1) goto LAB_71005cdf74;
  }
  else if (fVar1 < fVar5) {
LAB_71005cdf74:
    pfVar3 = param_1;
    if (fVar1 < 0.0) {
      do {
        while( true ) {
          pfVar3 = pfVar3 + 2;
          fVar6 = *pfVar3;
          if (0.0 <= fVar6) break;
          if (fVar1 < fVar6) goto LAB_71005cdfbc;
        }
      } while (fVar1 <= fVar6);
    }
    else {
      do {
        pfVar3 = pfVar3 + 2;
      } while (fVar1 <= *pfVar3);
    }
    goto LAB_71005cdfbc;
  }
  pfVar3 = param_1 + 2;
  if (pfVar3 < param_2) {
    if (fVar1 < 0.0) {
      do {
        fVar6 = *pfVar3;
        if (0.0 <= fVar6) {
          if (fVar6 < fVar1) break;
        }
        else if (fVar1 < fVar6) break;
        pfVar3 = pfVar3 + 2;
      } while (pfVar3 < param_2);
    }
    else {
      do {
        if (*pfVar3 < fVar1) break;
        pfVar3 = pfVar3 + 2;
      } while (pfVar3 < param_2);
    }
  }
LAB_71005cdfbc:
  if (pfVar3 < param_2) {
    if (fVar1 < 0.0) {
      param_2 = param_2 + -2;
      do {
        if (0.0 <= fVar5) {
          if (fVar1 <= fVar5) goto LAB_71005ce080;
        }
        else if (fVar5 <= fVar1) goto LAB_71005ce080;
        param_2 = param_2 + -2;
        fVar5 = *param_2;
      } while( true );
    }
    do {
      param_2 = param_2 + -2;
    } while (*param_2 < fVar1);
  }
LAB_71005ce080:
  do {
    if (param_2 <= pfVar3) {
      if (pfVar3 + -2 != param_1) {
        *(undefined8 *)param_1 = *(undefined8 *)(pfVar3 + -2);
      }
      pfVar3[-2] = fVar1;
      pfVar3[-1] = fVar2;
      return pfVar3;
    }
    uVar4 = *(undefined8 *)pfVar3;
    *(undefined8 *)pfVar3 = *(undefined8 *)param_2;
    *(undefined8 *)param_2 = uVar4;
    if (fVar1 < 0.0) {
      do {
        while( true ) {
          pfVar3 = pfVar3 + 2;
          fVar5 = *pfVar3;
          if (0.0 <= fVar5) break;
          if (fVar1 < fVar5) goto LAB_71005ce04c;
        }
      } while (fVar1 <= fVar5);
    }
    else {
      do {
        pfVar3 = pfVar3 + 2;
      } while (fVar1 <= *pfVar3);
    }
LAB_71005ce04c:
    if (0.0 <= fVar1) {
      do {
        param_2 = param_2 + -2;
      } while (*param_2 < fVar1);
      goto LAB_71005ce080;
    }
    do {
      while( true ) {
        param_2 = param_2 + -2;
        fVar5 = *param_2;
        if (0.0 <= fVar5) break;
        if (fVar5 <= fVar1) goto LAB_71005ce080;
      }
    } while (fVar5 < fVar1);
  } while( true );
}



float * FUN_71005ce0b0(float *param_1,float *param_2)

{
  float fVar1;
  float *pfVar2;
  float *pfVar3;
  undefined8 uVar4;
  float fVar5;
  float fVar6;
  
  fVar1 = *param_1;
  pfVar3 = param_1;
  if (fVar1 < 0.0) {
    do {
      while( true ) {
        pfVar3 = pfVar3 + 2;
        fVar5 = *pfVar3;
        if (0.0 <= fVar5) break;
        if (fVar1 <= fVar5) goto LAB_71005ce10c;
      }
    } while (fVar1 < fVar5);
  }
  else {
    do {
      pfVar3 = pfVar3 + 2;
    } while (fVar1 < *pfVar3);
  }
LAB_71005ce10c:
  if (pfVar3 + -2 == param_1) {
    if (pfVar3 < param_2) {
      if (fVar1 < 0.0) {
        do {
          while( true ) {
            param_2 = param_2 + -2;
            fVar5 = *param_2;
            if (0.0 <= fVar5) break;
            if (fVar5 < fVar1 || param_2 <= pfVar3) goto LAB_71005ce1b4;
          }
        } while (fVar5 <= fVar1 && pfVar3 < param_2);
      }
      else {
        do {
          param_2 = param_2 + -2;
        } while (*param_2 <= fVar1 && pfVar3 < param_2);
      }
    }
  }
  else if (fVar1 < 0.0) {
    do {
      while( true ) {
        param_2 = param_2 + -2;
        fVar5 = *param_2;
        if (0.0 <= fVar5) break;
        if (fVar5 < fVar1) goto LAB_71005ce1b4;
      }
    } while (fVar5 <= fVar1);
  }
  else {
    do {
      param_2 = param_2 + -2;
    } while (*param_2 <= fVar1);
  }
LAB_71005ce1b4:
  fVar5 = param_1[1];
  if (pfVar3 < param_2) {
    do {
      uVar4 = *(undefined8 *)pfVar3;
      *(undefined8 *)pfVar3 = *(undefined8 *)param_2;
      *(undefined8 *)param_2 = uVar4;
      if (fVar1 < 0.0) {
        do {
          while( true ) {
            pfVar3 = pfVar3 + 2;
            fVar6 = *pfVar3;
            if (0.0 <= fVar6) break;
            if (fVar1 <= fVar6) goto LAB_71005ce21c;
          }
        } while (fVar1 < fVar6);
      }
      else {
        do {
          pfVar3 = pfVar3 + 2;
        } while (fVar1 < *pfVar3);
      }
LAB_71005ce21c:
      if (fVar1 < 0.0) {
        do {
          while( true ) {
            param_2 = param_2 + -2;
            fVar6 = *param_2;
            if (0.0 <= fVar6) break;
            if (fVar6 < fVar1) goto LAB_71005ce1d0;
          }
        } while (fVar6 <= fVar1);
      }
      else {
        do {
          param_2 = param_2 + -2;
        } while (*param_2 <= fVar1);
      }
LAB_71005ce1d0:
    } while (pfVar3 < param_2);
  }
  pfVar2 = pfVar3 + -2;
  if (pfVar2 != param_1) {
    *(undefined8 *)param_1 = *(undefined8 *)pfVar2;
  }
  pfVar3[-2] = fVar1;
  pfVar3[-1] = fVar5;
  return pfVar2;
}



bool FUN_71005ce280(float *param_1,float *param_2)

{
  undefined8 uVar1;
  bool bVar2;
  float *pfVar3;
  undefined8 uVar4;
  long lVar5;
  int iVar6;
  float *pfVar7;
  long lVar8;
  long lVar9;
  float *pfVar10;
  float fVar11;
  float fVar12;
  float fVar13;
  
  bVar2 = true;
  switch((long)param_2 - (long)param_1 >> 3) {
  case 0:
  case 1:
    return bVar2;
  case 2:
    fVar11 = param_2[-2];
    fVar12 = *param_1;
    if ((0.0 <= fVar11) || (0.0 <= fVar12)) {
      if (fVar11 <= fVar12) {
        return bVar2;
      }
    }
    else if (fVar12 <= fVar11) {
      return bVar2;
    }
    uVar4 = *(undefined8 *)param_1;
    *(undefined8 *)param_1 = *(undefined8 *)(param_2 + -2);
    *(undefined8 *)(param_2 + -2) = uVar4;
    return bVar2;
  case 3:
    FUN_71005cdda0(param_1,param_1 + 2,param_2 + -2);
    return true;
  case 4:
    pfVar7 = param_1 + 4;
    FUN_71005cdda0(param_1,param_1 + 2,pfVar7);
    fVar11 = param_2[-2];
    fVar12 = param_1[4];
    if ((0.0 <= fVar11) || (0.0 <= fVar12)) {
      if (fVar11 <= fVar12) {
        return true;
      }
    }
    else if (fVar12 <= fVar11) {
      return true;
    }
    uVar4 = *(undefined8 *)pfVar7;
    *(undefined8 *)pfVar7 = *(undefined8 *)(param_2 + -2);
    *(undefined8 *)(param_2 + -2) = uVar4;
    fVar11 = *pfVar7;
    fVar12 = param_1[2];
    if ((0.0 <= fVar11) || (0.0 <= fVar12)) {
      if (fVar11 <= fVar12) {
        return true;
      }
    }
    else if (fVar12 <= fVar11) {
      return true;
    }
    uVar4 = *(undefined8 *)(param_1 + 2);
    uVar1 = *(undefined8 *)(param_1 + 4);
    fVar12 = *param_1;
    *(undefined8 *)(param_1 + 2) = uVar1;
    *(undefined8 *)(param_1 + 4) = uVar4;
    fVar11 = (float)uVar1;
    if ((0.0 <= fVar11) || (0.0 <= fVar12)) {
      if (fVar12 < fVar11) goto LAB_71005ce58c;
    }
    else if (fVar11 < fVar12) {
LAB_71005ce58c:
      uVar4 = *(undefined8 *)param_1;
      *(undefined8 *)param_1 = uVar1;
      *(undefined8 *)(param_1 + 2) = uVar4;
      return true;
    }
    break;
  case 5:
    FUN_71005ce5b0(param_1,param_1 + 2,param_1 + 4,param_1 + 6,param_2 + -2);
    return true;
  default:
    FUN_71005cdda0(param_1,param_1 + 2,param_1 + 4);
    if (param_1 + 6 != param_2) {
      lVar5 = 0;
      iVar6 = 0;
      pfVar7 = param_1 + 6;
      pfVar10 = param_1 + 4;
      do {
        pfVar3 = pfVar7;
        fVar11 = *pfVar3;
        fVar12 = *pfVar10;
        if ((0.0 <= fVar11) || (0.0 <= fVar12)) {
          if (fVar12 < fVar11) goto LAB_71005ce368;
        }
        else if (fVar11 < fVar12) {
LAB_71005ce368:
          fVar12 = pfVar3[1];
          *(undefined8 *)pfVar3 = *(undefined8 *)pfVar10;
          pfVar7 = param_1;
          if (pfVar10 != param_1) {
            lVar8 = lVar5;
            if (fVar11 < 0.0) {
              do {
                fVar13 = *(float *)((long)param_1 + lVar8 + 8);
                if (0.0 <= fVar13) {
                  if (fVar11 <= fVar13) {
                    pfVar7 = (float *)((long)param_1 + lVar8 + 0x10);
                    break;
                  }
                }
                else {
                  pfVar7 = pfVar10;
                  if (fVar13 <= fVar11) break;
                }
                lVar9 = lVar8 + -8;
                pfVar10 = pfVar10 + -2;
                *(undefined8 *)((long)param_1 + lVar8 + 0x10) =
                     *(undefined8 *)((long)param_1 + lVar8 + 8);
                pfVar7 = param_1;
                lVar8 = lVar9;
              } while (lVar9 != -0x10);
            }
            else {
              do {
                if (fVar11 <= *(float *)((long)param_1 + lVar8 + 8)) {
                  pfVar7 = (float *)((long)param_1 + lVar8 + 0x10);
                  break;
                }
                lVar9 = lVar8 + -8;
                *(undefined8 *)((long)param_1 + lVar8 + 0x10) =
                     *(undefined8 *)((long)param_1 + lVar8 + 8);
                lVar8 = lVar9;
              } while (lVar9 != -0x10);
            }
          }
          iVar6 = iVar6 + 1;
          *pfVar7 = fVar11;
          pfVar7[1] = fVar12;
          if (iVar6 == 8) {
            return pfVar3 + 2 == param_2;
          }
        }
        lVar5 = lVar5 + 8;
        pfVar7 = pfVar3 + 2;
        pfVar10 = pfVar3;
      } while (pfVar3 + 2 != param_2);
    }
  }
  return true;
}



void FUN_71005ce5b0(float *param_1,float *param_2,float *param_3,float *param_4,float *param_5)

{
  undefined8 uVar1;
  float fVar2;
  float fVar3;
  
  FUN_71005cdda0(param_1,param_2,param_3);
  fVar2 = *param_4;
  fVar3 = *param_3;
  if ((0.0 <= fVar2) || (0.0 <= fVar3)) {
    if (fVar3 < fVar2) goto LAB_71005ce60c;
  }
  else if (fVar2 < fVar3) {
LAB_71005ce60c:
    uVar1 = *(undefined8 *)param_3;
    *(undefined8 *)param_3 = *(undefined8 *)param_4;
    *(undefined8 *)param_4 = uVar1;
    fVar2 = *param_3;
    fVar3 = *param_2;
    if ((0.0 <= fVar2) || (0.0 <= fVar3)) {
      if (fVar3 < fVar2) goto LAB_71005ce648;
    }
    else if (fVar2 < fVar3) {
LAB_71005ce648:
      uVar1 = *(undefined8 *)param_2;
      *(undefined8 *)param_2 = *(undefined8 *)param_3;
      *(undefined8 *)param_3 = uVar1;
      fVar2 = *param_2;
      fVar3 = *param_1;
      if ((0.0 <= fVar2) || (0.0 <= fVar3)) {
        if (fVar3 < fVar2) goto LAB_71005ce684;
      }
      else if (fVar2 < fVar3) {
LAB_71005ce684:
        uVar1 = *(undefined8 *)param_1;
        *(undefined8 *)param_1 = *(undefined8 *)param_2;
        *(undefined8 *)param_2 = uVar1;
      }
    }
  }
  fVar2 = *param_5;
  fVar3 = *param_4;
  if ((0.0 <= fVar2) || (0.0 <= fVar3)) {
    if (fVar2 <= fVar3) {
      return;
    }
  }
  else if (fVar3 <= fVar2) {
    return;
  }
  uVar1 = *(undefined8 *)param_4;
  *(undefined8 *)param_4 = *(undefined8 *)param_5;
  *(undefined8 *)param_5 = uVar1;
  fVar2 = *param_4;
  fVar3 = *param_3;
  if ((0.0 <= fVar2) || (0.0 <= fVar3)) {
    if (fVar2 <= fVar3) {
      return;
    }
  }
  else if (fVar3 <= fVar2) {
    return;
  }
  uVar1 = *(undefined8 *)param_3;
  *(undefined8 *)param_3 = *(undefined8 *)param_4;
  *(undefined8 *)param_4 = uVar1;
  fVar2 = *param_3;
  fVar3 = *param_2;
  if ((0.0 <= fVar2) || (0.0 <= fVar3)) {
    if (fVar2 <= fVar3) {
      return;
    }
  }
  else if (fVar3 <= fVar2) {
    return;
  }
  uVar1 = *(undefined8 *)param_2;
  *(undefined8 *)param_2 = *(undefined8 *)param_3;
  *(undefined8 *)param_3 = uVar1;
  fVar2 = *param_2;
  fVar3 = *param_1;
  if ((0.0 <= fVar2) || (0.0 <= fVar3)) {
    if (fVar3 < fVar2) goto LAB_71005ce784;
  }
  else if (fVar2 < fVar3) {
LAB_71005ce784:
    uVar1 = *(undefined8 *)param_1;
    *(undefined8 *)param_1 = *(undefined8 *)param_2;
    *(undefined8 *)param_2 = uVar1;
    return;
  }
  return;
}



void FUN_71005ce7b0(long param_1,undefined8 param_2,long param_3,float *param_4)

{
  ulong uVar1;
  ulong uVar2;
  float *pfVar3;
  float *pfVar4;
  ulong uVar5;
  long lVar6;
  float fVar7;
  float fVar8;
  float fVar9;
  float fVar10;
  
  if (param_3 < 2) {
    return;
  }
  uVar2 = param_3 - 2U >> 1;
  if ((long)uVar2 < (long)param_4 - param_1 >> 3) {
    return;
  }
  lVar6 = (long)param_4 - param_1 >> 2;
  uVar5 = lVar6 + 1;
  uVar1 = lVar6 + 2;
  pfVar3 = (float *)(param_1 + uVar5 * 8);
  if ((long)uVar1 < param_3) {
    fVar8 = *pfVar3;
    fVar7 = pfVar3[2];
    if ((0.0 <= fVar8) || (0.0 <= fVar7)) {
      if (fVar7 < fVar8) goto LAB_71005ce810;
    }
    else if (fVar8 < fVar7) {
LAB_71005ce810:
      pfVar3 = pfVar3 + 2;
      uVar5 = uVar1;
    }
  }
  fVar8 = *pfVar3;
  fVar7 = *param_4;
  if ((0.0 <= fVar8) || (0.0 <= fVar7)) {
    if (fVar8 <= fVar7) goto LAB_71005ce844;
  }
  else if (fVar7 <= fVar8) {
LAB_71005ce844:
    fVar8 = param_4[1];
    *(undefined8 *)param_4 = *(undefined8 *)pfVar3;
    if ((long)uVar5 <= (long)uVar2) {
      pfVar4 = pfVar3;
      if (fVar7 < 0.0) {
        do {
          lVar6 = uVar5 * 2;
          uVar5 = uVar5 << 1 | 1;
          uVar1 = lVar6 + 2;
          pfVar3 = (float *)(param_1 + uVar5 * 8);
          if ((long)uVar1 < param_3) {
            fVar10 = *pfVar3;
            fVar9 = pfVar3[2];
            if ((0.0 <= fVar10) || (0.0 <= fVar9)) {
              if (fVar9 < fVar10) goto LAB_71005ce95c;
            }
            else if (fVar10 < fVar9) {
LAB_71005ce95c:
              uVar5 = uVar1;
              pfVar3 = pfVar3 + 2;
            }
          }
          fVar9 = *pfVar3;
          if (0.0 <= fVar9) {
            if (fVar7 < fVar9) goto LAB_71005ce978;
          }
          else if (fVar9 < fVar7) goto LAB_71005ce978;
          *(undefined8 *)pfVar4 = *(undefined8 *)pfVar3;
          pfVar4 = pfVar3;
        } while ((long)uVar5 <= (long)uVar2);
      }
      else {
        do {
          lVar6 = uVar5 * 2;
          uVar5 = uVar5 << 1 | 1;
          uVar1 = lVar6 + 2;
          pfVar3 = (float *)(param_1 + uVar5 * 8);
          if ((long)uVar1 < param_3) {
            fVar10 = *pfVar3;
            fVar9 = pfVar3[2];
            if ((0.0 <= fVar10) || (0.0 <= fVar9)) {
              if (fVar9 < fVar10) goto LAB_71005ce8c0;
            }
            else if (fVar10 < fVar9) {
LAB_71005ce8c0:
              uVar5 = uVar1;
              pfVar3 = pfVar3 + 2;
            }
          }
          if (fVar7 < *pfVar3) {
LAB_71005ce978:
            *pfVar4 = fVar7;
            pfVar4[1] = fVar8;
            return;
          }
          *(undefined8 *)pfVar4 = *(undefined8 *)pfVar3;
          pfVar4 = pfVar3;
        } while ((long)uVar5 <= (long)uVar2);
      }
    }
    *pfVar3 = fVar7;
    pfVar3[1] = fVar8;
    return;
  }
  return;
}



void FUN_71005ce990(float *param_1,long param_2,undefined8 param_3,long param_4)

{
  float *pfVar1;
  undefined8 uVar2;
  ulong uVar3;
  float *pfVar4;
  ulong uVar5;
  ulong uVar6;
  float fVar7;
  float fVar8;
  float fVar9;
  
  if (1 < param_4) {
    uVar2 = *(undefined8 *)param_1;
    pfVar4 = param_1;
    uVar3 = 0;
    do {
      uVar5 = uVar3 << 1 | 1;
      uVar6 = uVar3 * 2 + 2;
      pfVar1 = pfVar4 + uVar3 * 2 + 2;
      if ((long)uVar6 < param_4) {
        fVar8 = *pfVar1;
        fVar7 = pfVar4[uVar3 * 2 + 4];
        if ((0.0 <= fVar8) || (0.0 <= fVar7)) {
          if (fVar7 < fVar8) goto LAB_71005ce9b0;
        }
        else if (fVar8 < fVar7) {
LAB_71005ce9b0:
          pfVar1 = pfVar4 + uVar3 * 2 + 4;
          uVar5 = uVar6;
        }
      }
      *(undefined8 *)pfVar4 = *(undefined8 *)pfVar1;
      pfVar4 = pfVar1;
      uVar3 = uVar5;
    } while ((long)uVar5 <= (long)(param_4 - 2U >> 1));
    pfVar4 = (float *)(param_2 + -8);
    if (pfVar1 == pfVar4) {
      *(undefined8 *)pfVar1 = uVar2;
      return;
    }
    *(undefined8 *)pfVar1 = *(undefined8 *)pfVar4;
    *(undefined8 *)pfVar4 = uVar2;
    uVar3 = (long)pfVar1 + (8 - (long)param_1);
    if (8 < (long)uVar3) {
      fVar7 = *pfVar1;
      uVar6 = (uVar3 >> 3) - 2;
      uVar3 = uVar6 >> 1;
      pfVar4 = param_1 + uVar3 * 2;
      fVar8 = *pfVar4;
      if ((0.0 <= fVar8) || (0.0 <= fVar7)) {
        if (fVar7 < fVar8) {
LAB_71005cea98:
          fVar8 = pfVar1[1];
          *(undefined8 *)pfVar1 = *(undefined8 *)pfVar4;
          if (1 < uVar6) {
            pfVar1 = pfVar4;
            if (fVar7 < 0.0) {
              do {
                uVar6 = uVar3 - 1;
                uVar3 = uVar6 >> 1;
                pfVar4 = param_1 + uVar3 * 2;
                fVar9 = *pfVar4;
                if (0.0 <= fVar9) {
                  if (fVar9 <= fVar7) goto LAB_71005ceb30;
                }
                else if (fVar7 <= fVar9) goto LAB_71005ceb30;
                *(undefined8 *)pfVar1 = *(undefined8 *)pfVar4;
                pfVar1 = pfVar4;
              } while (1 < uVar6);
            }
            else {
              do {
                uVar6 = uVar3 - 1;
                uVar3 = uVar6 >> 1;
                pfVar4 = param_1 + uVar3 * 2;
                if (*pfVar4 <= fVar7) {
LAB_71005ceb30:
                  *pfVar1 = fVar7;
                  pfVar1[1] = fVar8;
                  return;
                }
                *(undefined8 *)pfVar1 = *(undefined8 *)pfVar4;
                pfVar1 = pfVar4;
              } while (1 < uVar6);
            }
          }
          *pfVar4 = fVar7;
          pfVar4[1] = fVar8;
          return;
        }
      }
      else if (fVar8 < fVar7) goto LAB_71005cea98;
    }
  }
  return;
}



void FUN_71005ced60(long param_1)

{
  long *plVar1;
  long *plVar2;
  long lVar3;
  
  plVar2 = *(long **)(param_1 + 0x198);
  while (plVar2 != (long *)(param_1 + 400)) {
    plVar1 = (long *)plVar2[1];
    lVar3 = *plVar1;
    *(long **)(*plVar2 + 8) = plVar1;
    *plVar1 = *plVar2;
    *(long **)(lVar3 + 8) = plVar2;
    *plVar2 = lVar3;
    plVar2 = *(long **)(param_1 + 0x198);
  }
  FUN_71005fc21c((undefined1 *)(param_1 + 0x18));
  FUN_71005fd94c((undefined8 *)(param_1 + 0x60));
  return;
}



ulong FUN_71005cedd0(long param_1,ulong param_2,long param_3)

{
  long lVar1;
  int iVar2;
  uint uVar3;
  ulong *puVar4;
  ulong *puVar5;
  ulong *puVar6;
  ulong uVar7;
  
  (**(code **)**(undefined8 **)(param_1 + 0x1c0))();
  uVar3 = *(uint *)(param_1 + 0x1e4);
  if (*(int *)(param_1 + 0x1e0) < (int)uVar3) {
    puVar5 = *(ulong **)(param_1 + 0x1b0);
    if (*(ulong **)(param_1 + 0x1b0) == (ulong *)0x0) {
      iVar2 = 0;
      if (*(int *)(param_1 + 0x1e8) + 1U != uVar3) {
        iVar2 = *(int *)(param_1 + 0x1e8) + 1;
      }
      puVar4 = *(ulong **)(param_1 + 0x1a8);
      *(int *)(param_1 + 0x1e8) = iVar2;
      puVar5 = puVar4 + (long)iVar2 * 7;
      if (*puVar5 == 0) {
        *(ulong **)(param_1 + 0x1b0) = puVar5;
      }
      else {
        if (0 < (int)uVar3) {
          uVar7 = 0;
          do {
            if (*puVar4 == 0) {
              *(ulong **)(param_1 + 0x1b0) = puVar4;
              *(int *)(param_1 + 0x1e8) = (int)uVar7;
              puVar5 = puVar4;
              goto LAB_71005cee94;
            }
            uVar7 = uVar7 + 1;
            puVar4 = puVar4 + 7;
          } while (uVar3 != uVar7);
        }
        puVar5 = (ulong *)0x0;
      }
    }
LAB_71005cee94:
    lVar1 = *(long *)(param_1 + 0x1a0);
    for (puVar4 = *(ulong **)(param_1 + 0x188); puVar4 != (ulong *)(param_1 + 0x180);
        puVar4 = (ulong *)puVar4[1]) {
      uVar7 = param_3 + -1 + lVar1 & -param_3;
      if ((long)param_2 <= (long)(puVar4[-2] - uVar7)) {
        *puVar5 = uVar7;
        puVar5[1] = param_2;
        puVar6 = puVar5 + 2;
        uVar7 = *puVar6;
        *puVar6 = *puVar4;
        *(ulong **)(uVar7 + 8) = puVar4;
        *(ulong **)(*puVar4 + 8) = puVar6;
        *puVar4 = uVar7;
        goto LAB_71005cef70;
      }
      lVar1 = puVar4[-2] + puVar4[-1];
    }
    uVar7 = param_3 + -1 + lVar1 & -param_3;
    if ((long)param_2 <= (long)((*(long *)(param_1 + 0x1a0) + *(long *)(param_1 + 0x1c8)) - uVar7))
    {
      *puVar5 = uVar7;
      puVar5[1] = param_2;
      puVar4 = puVar5 + 2;
      uVar7 = *puVar4;
      *puVar4 = *(ulong *)(param_1 + 0x180);
      *(ulong **)(uVar7 + 8) = (ulong *)(param_1 + 0x180);
      *(ulong **)(*(long *)(param_1 + 0x180) + 8) = puVar4;
      *(ulong *)(param_1 + 0x180) = uVar7;
LAB_71005cef70:
      *(undefined8 *)(param_1 + 0x1b0) = 0;
      *(int *)(param_1 + 0x1e0) = *(int *)(param_1 + 0x1e0) + 1;
      *(ulong *)(param_1 + 0x1d0) = *(long *)(param_1 + 0x1d0) + puVar5[1];
      uVar7 = *puVar5;
      goto LAB_71005cef94;
    }
    FUN_71005dee10();
    FUN_71005dee10();
  }
  else {
    FUN_71005dee10();
  }
  uVar7 = 0;
LAB_71005cef94:
  (**(code **)(**(long **)(param_1 + 0x1c0) + 8))();
  return uVar7;
}



void FUN_71005cefc0(long param_1,long param_2,uint param_3)

{
  long *plVar1;
  long *plVar2;
  long lVar3;
  
  (**(code **)**(undefined8 **)(param_1 + 0x1c0))();
  if (param_2 != 0) {
    plVar2 = (long *)(param_1 + 0x188);
    if ((param_3 & 1) == 0) {
      for (plVar2 = (long *)*plVar2; plVar2 != (long *)(param_1 + 0x180); plVar2 = (long *)plVar2[1]
          ) {
        if (plVar2[-2] == param_2) {
          plVar1 = plVar2 + 2;
          lVar3 = *plVar1;
          *(undefined1 *)(plVar2 + 4) = *(undefined1 *)(param_1 + 0x1ec);
          *plVar1 = *(long *)(param_1 + 400);
          *(long *)(lVar3 + 8) = param_1 + 400;
          *(long **)(*(long *)(param_1 + 400) + 8) = plVar1;
          *(long *)(param_1 + 400) = lVar3;
          break;
        }
      }
    }
    else {
      do {
        plVar1 = (long *)*plVar2;
        if (plVar1 == (long *)(param_1 + 0x180)) goto LAB_71005cf0b4;
        plVar2 = plVar1 + 1;
      } while (plVar1[-2] != param_2);
      plVar1[-2] = 0;
      *(long *)(param_1 + 0x1d0) = *(long *)(param_1 + 0x1d0) - plVar1[-1];
      plVar2 = (long *)plVar1[1];
      lVar3 = *plVar2;
      *(long **)(*plVar1 + 8) = plVar2;
      *plVar2 = *plVar1;
      *(long **)(lVar3 + 8) = plVar1;
      *plVar1 = lVar3;
      *(long **)(param_1 + 0x1b0) = plVar1 + -2;
      *(int *)(param_1 + 0x1e0) = *(int *)(param_1 + 0x1e0) + -1;
    }
  }
LAB_71005cf0b4:
                    // WARNING: Could not recover jumptable at 0x0071005cf0cc. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(**(long **)(param_1 + 0x1c0) + 8))();
  return;
}



void FUN_71005cf0d0(long param_1)

{
  long *plVar1;
  long *plVar2;
  long *plVar3;
  long lVar4;
  long *plVar5;
  
  (**(code **)**(undefined8 **)(param_1 + 0x1c0))();
  if (*(long **)(param_1 + 0x198) != (long *)(param_1 + 400)) {
    plVar1 = *(long **)(param_1 + 0x198);
    do {
      plVar2 = (long *)plVar1[1];
      if ((char)plVar1[2] == '\0') {
        lVar4 = *plVar2;
        *(long **)(*plVar1 + 8) = plVar2;
        *plVar2 = *plVar1;
        *(long **)(lVar4 + 8) = plVar1;
        *plVar1 = lVar4;
        plVar5 = (long *)(param_1 + 0x188);
        do {
          plVar3 = (long *)*plVar5;
          if (plVar3 == (long *)(param_1 + 0x180)) goto LAB_71005cf118;
          plVar5 = plVar3 + 1;
        } while (plVar3[-2] != plVar1[-4]);
        plVar3[-2] = 0;
        *(long *)(param_1 + 0x1d0) = *(long *)(param_1 + 0x1d0) - plVar3[-1];
        plVar1 = (long *)plVar3[1];
        lVar4 = *plVar1;
        *(long **)(*plVar3 + 8) = plVar1;
        *plVar1 = *plVar3;
        *(long **)(lVar4 + 8) = plVar3;
        *plVar3 = lVar4;
        *(long **)(param_1 + 0x1b0) = plVar3 + -2;
        *(int *)(param_1 + 0x1e0) = *(int *)(param_1 + 0x1e0) + -1;
      }
      else {
        *(char *)(plVar1 + 2) = (char)plVar1[2] + -1;
      }
LAB_71005cf118:
      plVar1 = plVar2;
    } while (plVar2 != (long *)(param_1 + 400));
  }
                    // WARNING: Could not recover jumptable at 0x0071005cf1cc. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(**(long **)(param_1 + 0x1c0) + 8))();
  return;
}



void FUN_71005cf1d0(long *param_1)

{
  *param_1 = DAT_7103a6f9e0 + 0x10;
  ret_71005FD8B0();
  ret_71005FC128();
  return;
}



void FUN_71005cf208(long *param_1)

{
  *param_1 = DAT_7103a6f9e0 + 0x10;
  ret_71005FD8B0();
  ret_71005FC128();
  FUN_71024d49c0((long)param_1);
  return;
}



void FUN_71005cf24c(undefined2 *param_1)

{
  *param_1 = 0;
  FUN_71005cf550((undefined8 *)(param_1 + 4));
  *(undefined8 *)(param_1 + 0x18) = 0;
  *(undefined8 *)(param_1 + 0x1c) = 0;
  *(undefined8 *)(param_1 + 0xc) = 0;
  *(undefined8 *)(param_1 + 0x10) = 0;
  *(undefined8 *)(param_1 + 0x14) = 0;
  return;
}



long FUN_71005cf27c(long param_1)

{
  return param_1 + 8;
}



undefined8 FUN_71005cf290(char *param_1,long param_2,char param_3,uint param_4,long param_5)

{
  ulong uVar1;
  ulong uVar2;
  long lVar3;
  long lVar4;
  ulong uVar5;
  char cVar6;
  bool bVar7;
  long lVar8;
  ulong uVar9;
  ulong uVar10;
  ulong uVar11;
  ulong uVar12;
  
  if (*param_1 != '\0') {
    return 0;
  }
  *(long *)(param_1 + 0x38) = param_5;
  lVar8 = *(long *)(param_2 + 0x1d8);
  param_1[1] = param_3;
  uVar12 = (param_5 + lVar8) - 1U & -lVar8;
  uVar9 = uVar12;
  if (param_3 != '\x02') {
    uVar9 = 0;
  }
  bVar7 = FUN_71005cf55c((ulong *)(param_1 + 8),param_2,uVar9 + uVar12 * (long)(int)param_4);
  if (!bVar7) {
    return 0;
  }
  if ((int)param_4 < 1) {
    uVar9 = 0;
    cVar6 = param_1[1];
  }
  else {
    lVar8 = *(long *)(param_1 + 8);
    uVar5 = *(ulong *)(param_1 + 0x10);
    uVar10 = 0;
    uVar9 = 0;
    if (param_4 != 1) {
      uVar11 = uVar10;
      do {
        uVar10 = uVar9 + uVar12;
        uVar2 = uVar9;
        if (uVar10 <= uVar5) {
          uVar2 = uVar10;
        }
        lVar3 = 0;
        if (uVar10 <= uVar5) {
          lVar3 = lVar8 + uVar9;
        }
        uVar10 = uVar11 + 2;
        uVar1 = uVar2 + uVar12;
        uVar9 = uVar2;
        if (uVar1 <= uVar5) {
          uVar9 = uVar1;
        }
        lVar4 = 0;
        if (uVar1 <= uVar5) {
          lVar4 = lVar8 + uVar2;
        }
        *(long *)(param_1 + uVar11 * 8 + 0x18) = lVar3;
        *(long *)(param_1 + uVar11 * 8 + 0x20) = lVar4;
        uVar11 = uVar10;
      } while (((ulong)param_4 & 0xfffffffe) != uVar10);
    }
    if ((param_4 & 1) != 0) {
      uVar11 = uVar9 + uVar12;
      lVar3 = 0;
      if (uVar11 <= uVar5) {
        lVar3 = lVar8 + uVar9;
      }
      if (uVar11 <= uVar5) {
        uVar9 = uVar11;
      }
      *(long *)(param_1 + uVar10 * 8 + 0x18) = lVar3;
    }
    cVar6 = param_1[1];
  }
  if (cVar6 == '\x02') {
    lVar8 = 0;
    if (uVar9 + uVar12 <= *(ulong *)(param_1 + 0x10)) {
      lVar8 = *(long *)(param_1 + 8) + uVar9;
    }
  }
  else {
    lVar8 = 0;
  }
  *(long *)(param_1 + 0x30) = lVar8;
  *param_1 = '\x01';
  return 1;
}



undefined1 FUN_71005cf3e4(undefined1 *param_1)

{
  return *param_1;
}



void FUN_71005cf3ec(undefined1 *param_1,long param_2)

{
  FUN_71005cf5ac((long *)(param_1 + 8),param_2);
  *param_1 = 0;
  *(undefined8 *)(param_1 + 0x38) = 0;
  *(undefined8 *)(param_1 + 0x18) = 0;
  *(undefined8 *)(param_1 + 0x20) = 0;
  *(undefined8 *)(param_1 + 0x28) = 0;
  *(undefined8 *)(param_1 + 0x30) = 0;
  return;
}



undefined8 FUN_71005cf420(char *param_1,byte param_2)

{
  char cVar1;
  undefined8 uVar2;
  
  if (*param_1 == '\0') {
    return 0;
  }
  cVar1 = param_1[1];
  if (cVar1 == '\x02') {
    return *(undefined8 *)(param_1 + 0x30);
  }
  if (cVar1 == '\x01') {
    return *(undefined8 *)(param_1 + (ulong)param_2 * 8 + 0x18);
  }
  if (cVar1 == '\0') {
    return *(undefined8 *)(param_1 + 0x18);
  }
  uVar2 = thunk_EXT_FUN_02e95df0();
  return uVar2;
}



undefined8 FUN_71005cf470(long param_1,byte param_2)

{
  char cVar1;
  undefined8 uVar2;
  
  cVar1 = *(char *)(param_1 + 1);
  if ((cVar1 != '\x02') && (cVar1 != '\x01')) {
    if (cVar1 == '\0') {
      return *(undefined8 *)(param_1 + 0x18);
    }
    uVar2 = thunk_EXT_FUN_02e95df0();
    return uVar2;
  }
  return *(undefined8 *)(param_1 + (ulong)param_2 * 8 + 0x18);
}



void FUN_71005cf4ac(char *param_1,long *param_2,byte param_3,long param_4)

{
  long lVar1;
  long lVar2;
  char cVar3;
  long lVar4;
  
  if (*param_1 != '\0') {
    cVar3 = param_1[1];
    if ((cVar3 == '\x02') || (cVar3 == '\x01')) {
      param_1 = param_1 + (ulong)param_3 * 8;
    }
    else if (cVar3 != '\0') {
      thunk_EXT_FUN_02e95df0();
      return;
    }
    lVar1 = *(long *)(param_4 + 8);
    lVar2 = *(long *)(param_4 + 0x10);
    lVar4 = *(long *)(param_1 + 0x18);
    *param_2 = lVar1;
    param_2[1] = lVar2;
    *param_2 = (lVar4 - *(long *)(param_4 + 0x1a0)) + lVar1;
  }
  return;
}



void FUN_71005cf508(char *param_1,byte param_2)

{
  if (*param_1 == '\0' || param_1[1] != '\x02') {
    return;
  }
  thunk_EXT_FUN_02e95df0
            (*(undefined8 *)(param_1 + (ulong)param_2 * 8 + 0x18),*(undefined8 *)(param_1 + 0x30),
             *(undefined8 *)(param_1 + 0x38));
  return;
}



void FUN_71005cf534(char *param_1)

{
  if (*param_1 != '\0') {
    thunk_EXT_FUN_02e95df0(*(undefined8 *)(param_1 + 8),0,*(undefined8 *)(param_1 + 0x10));
    return;
  }
  return;
}



void FUN_71005cf550(undefined8 *param_1)

{
  *param_1 = 0;
  param_1[1] = 0;
  return;
}



bool FUN_71005cf55c(ulong *param_1,long param_2,long param_3)

{
  ulong uVar1;
  long lVar2;
  
  lVar2 = *(long *)(param_2 + 0x1d8);
  uVar1 = (param_3 + lVar2) - 1U & -lVar2;
  param_1[1] = uVar1;
  uVar1 = FUN_71005cedd0(param_2,uVar1,lVar2);
  *param_1 = uVar1;
  return uVar1 != 0;
}



void FUN_71005cf5ac(long *param_1,long param_2)

{
  if (*param_1 != 0) {
    FUN_71005cefc0(param_2,*param_1,0);
    *param_1 = 0;
  }
  return;
}



bool FUN_71005cf5e4(long *param_1)

{
  return *param_1 != 0;
}



undefined8
FUN_71005cf5f4(long *param_1,long param_2,long param_3,long param_4,long *param_5,int *param_6)

{
  char cVar1;
  char cVar2;
  undefined *puVar3;
  long lVar4;
  long lVar5;
  long lVar6;
  long lVar7;
  long *plVar8;
  int iVar9;
  long local_58;
  
  lVar4 = *(long *)(param_3 + 0x40);
  lVar6 = *(long *)(lVar4 + 0x78);
  if (lVar6 != 0) {
    Hint_Prefetch(lVar6,0,0,0);
    Hint_Prefetch(lVar6 + 0x40,0,0,0);
    Hint_Prefetch(lVar6 + 0x80,0,0,0);
    Hint_Prefetch(lVar6 + 0xc0,0,0,0);
  }
  lVar5 = *(long *)(lVar4 + 0x80);
  if (lVar5 != 0) {
    Hint_Prefetch(lVar5,0,0,0);
    Hint_Prefetch(lVar5 + 0x40,0,0,0);
    Hint_Prefetch(lVar5 + 0x80,0,0,0);
    Hint_Prefetch(lVar5 + 0xc0,0,0,0);
  }
  lVar7 = *(long *)(lVar4 + 0x88);
  if (lVar7 != 0) {
    Hint_Prefetch(lVar7,0,0,0);
    Hint_Prefetch(lVar7 + 0x40,0,0,0);
    Hint_Prefetch(lVar7 + 0x80,0,0,0);
    Hint_Prefetch(lVar7 + 0xc0,0,0,0);
  }
  lVar7 = *(long *)(lVar4 + 0x90);
  if (lVar7 != 0) {
    Hint_Prefetch(lVar7,0,0,0);
    Hint_Prefetch(lVar7 + 0x40,0,0,0);
    Hint_Prefetch(lVar7 + 0x80,0,0,0);
    Hint_Prefetch(lVar7 + 0xc0,0,0,0);
  }
  lVar7 = *(long *)(lVar4 + 0x98);
  if (lVar7 != 0) {
    Hint_Prefetch(lVar7,0,0,0);
    Hint_Prefetch(lVar7 + 0x40,0,0,0);
    Hint_Prefetch(lVar7 + 0x80,0,0,0);
    Hint_Prefetch(lVar7 + 0xc0,0,0,0);
  }
  lVar7 = *(long *)(lVar4 + 0xa0);
  if (lVar7 != 0) {
    Hint_Prefetch(lVar7,0,0,0);
    Hint_Prefetch(lVar7 + 0x40,0,0,0);
    Hint_Prefetch(lVar7 + 0x80,0,0,0);
    Hint_Prefetch(lVar7 + 0xc0,0,0,0);
  }
  if (lVar6 != 0) {
    local_58 = *(long *)(lVar6 + 0x90);
    if (local_58 != -1) {
      cVar1 = *(char *)(param_4 + 0x4a);
      lVar4 = *(long *)(lVar4 + 0xa8);
      if (*(char *)(param_4 + 8) != -1) {
        FUN_71005fd45c(param_2,(int)*(char *)(param_4 + 8),0,(undefined4 *)&local_58,
                       (undefined4 *)(lVar4 + 0x18));
      }
      if (cVar1 != -1) {
        FUN_71005fd45c(param_2,(int)cVar1,4,(undefined4 *)&local_58,(undefined4 *)(lVar4 + 0x18));
      }
    }
    lVar4 = *(long *)(param_3 + 0x40);
    lVar5 = *(long *)(lVar4 + 0x80);
  }
  if (lVar5 != 0) {
    local_58 = *(long *)(lVar5 + 0x90);
    if (local_58 != -1) {
      cVar1 = *(char *)(param_4 + 0x4b);
      lVar4 = *(long *)(lVar4 + 0xb0);
      if (*(char *)(param_4 + 9) != -1) {
        FUN_71005fd45c(param_2,(int)*(char *)(param_4 + 9),0,(undefined4 *)&local_58,
                       (undefined4 *)(lVar4 + 0x18));
      }
      if (cVar1 != -1) {
        FUN_71005fd45c(param_2,(int)cVar1,4,(undefined4 *)&local_58,(undefined4 *)(lVar4 + 0x18));
      }
    }
    lVar4 = *(long *)(param_3 + 0x40);
  }
  if (*(long *)(lVar4 + 0x88) != 0) {
    local_58 = *(long *)(*(long *)(lVar4 + 0x88) + 0x90);
    if (local_58 != -1) {
      cVar1 = *(char *)(param_4 + 0x4c);
      lVar4 = *(long *)(lVar4 + 0xb8);
      if (*(char *)(param_4 + 10) != -1) {
        FUN_71005fd45c(param_2,(int)*(char *)(param_4 + 10),0,(undefined4 *)&local_58,
                       (undefined4 *)(lVar4 + 0x18));
      }
      if (cVar1 != -1) {
        FUN_71005fd45c(param_2,(int)cVar1,4,(undefined4 *)&local_58,(undefined4 *)(lVar4 + 0x18));
      }
    }
    lVar4 = *(long *)(param_3 + 0x40);
  }
  if (*(long *)(lVar4 + 0x90) != 0) {
    local_58 = *(long *)(*(long *)(lVar4 + 0x90) + 0x90);
    if (local_58 != -1) {
      cVar1 = *(char *)(param_4 + 0x4d);
      lVar4 = *(long *)(lVar4 + 0xc0);
      if (*(char *)(param_4 + 0xb) != -1) {
        FUN_71005fd45c(param_2,(int)*(char *)(param_4 + 0xb),0,(undefined4 *)&local_58,
                       (undefined4 *)(lVar4 + 0x18));
      }
      if (cVar1 != -1) {
        FUN_71005fd45c(param_2,(int)cVar1,4,(undefined4 *)&local_58,(undefined4 *)(lVar4 + 0x18));
      }
    }
    lVar4 = *(long *)(param_3 + 0x40);
  }
  if (*(long *)(lVar4 + 0x98) != 0) {
    local_58 = *(long *)(*(long *)(lVar4 + 0x98) + 0x90);
    if (local_58 != -1) {
      cVar1 = *(char *)(param_4 + 0x4e);
      lVar4 = *(long *)(lVar4 + 200);
      if (*(char *)(param_4 + 0xc) != -1) {
        FUN_71005fd45c(param_2,(int)*(char *)(param_4 + 0xc),0,(undefined4 *)&local_58,
                       (undefined4 *)(lVar4 + 0x18));
      }
      if (cVar1 != -1) {
        FUN_71005fd45c(param_2,(int)cVar1,4,(undefined4 *)&local_58,(undefined4 *)(lVar4 + 0x18));
      }
    }
    lVar4 = *(long *)(param_3 + 0x40);
  }
  if ((*(long *)(lVar4 + 0xa0) != 0) &&
     (local_58 = *(long *)(*(long *)(lVar4 + 0xa0) + 0x90), local_58 != -1)) {
    cVar1 = *(char *)(param_4 + 0x4f);
    lVar4 = *(long *)(lVar4 + 0xd0);
    if (*(char *)(param_4 + 0xd) != -1) {
      FUN_71005fd45c(param_2,(int)*(char *)(param_4 + 0xd),0,(undefined4 *)&local_58,
                     (undefined4 *)(lVar4 + 0x18));
    }
    if (cVar1 != -1) {
      FUN_71005fd45c(param_2,(int)cVar1,4,(undefined4 *)&local_58,(undefined4 *)(lVar4 + 0x18));
    }
  }
  cVar1 = (char)param_6[6];
  if (*param_5 != -1) {
    cVar2 = *(char *)(param_4 + 0xe);
    iVar9 = (int)*(char *)(param_4 + 0x50);
    if (cVar2 == -1) {
LAB_71005cf968:
      if (iVar9 != -1) {
        if (cVar1 != '\0') goto LAB_71005cf974;
        goto LAB_71005cf980;
      }
    }
    else {
      if ((cVar1 == '\0') || (*param_6 != (int)cVar2)) {
        FUN_71005fd45c(param_2,(int)cVar2,0,(undefined4 *)param_5,(undefined4 *)(param_1[1] + 0x18))
        ;
        *param_6 = (int)cVar2;
        goto LAB_71005cf968;
      }
      if (iVar9 == -1) goto LAB_71005cf9a0;
LAB_71005cf974:
      if (param_6[1] != iVar9) {
LAB_71005cf980:
        FUN_71005fd45c(param_2,iVar9,4,(undefined4 *)param_5,(undefined4 *)(param_1[1] + 0x18));
        param_6[1] = iVar9;
      }
    }
  }
LAB_71005cf9a0:
  plVar8 = param_5 + 1;
  if (*plVar8 != -1) {
    cVar2 = *(char *)(param_4 + 0xf);
    iVar9 = (int)*(char *)(param_4 + 0x51);
    if (cVar2 == -1) {
LAB_71005cf9f8:
      if (iVar9 != -1) {
        if (cVar1 != '\0') goto LAB_71005cfa04;
        goto LAB_71005cfa10;
      }
    }
    else {
      if ((cVar1 == '\0') || (param_6[2] != (int)cVar2)) {
        FUN_71005fd45c(param_2,(int)cVar2,0,(undefined4 *)plVar8,(undefined4 *)(param_1[1] + 0x18));
        param_6[2] = (int)cVar2;
        goto LAB_71005cf9f8;
      }
      if (iVar9 == -1) goto LAB_71005cfa30;
LAB_71005cfa04:
      if (param_6[3] != iVar9) {
LAB_71005cfa10:
        FUN_71005fd45c(param_2,iVar9,4,(undefined4 *)plVar8,(undefined4 *)(param_1[1] + 0x18));
        param_6[3] = iVar9;
      }
    }
  }
LAB_71005cfa30:
  puVar3 = FUN_71005d1b70();
  cVar2 = *(char *)(param_4 + 0x10);
  iVar9 = (int)*(char *)(param_4 + 0x52);
  if (cVar2 == -1) {
LAB_71005cfa84:
    if (iVar9 == -1) {
      return 1;
    }
    if (cVar1 == '\0') goto LAB_71005cfa9c;
  }
  else {
    if ((cVar1 == '\0') || (param_6[4] != (int)cVar2)) {
      FUN_71005fd45c(param_2,(int)cVar2,0,(undefined4 *)(puVar3 + 0x260),
                     (undefined4 *)(*param_1 + 0x18));
      param_6[4] = (int)cVar2;
      goto LAB_71005cfa84;
    }
    if (iVar9 == -1) {
      return 1;
    }
  }
  if (param_6[5] == iVar9) {
    return 1;
  }
LAB_71005cfa9c:
  FUN_71005fd45c(param_2,iVar9,4,(undefined4 *)(puVar3 + 0x260),(undefined4 *)(*param_1 + 0x18));
  param_6[5] = iVar9;
  return 1;
}



undefined8 FUN_71005cfadc(long param_1,long param_2,long param_3)

{
  char cVar1;
  long lVar2;
  long local_40;
  undefined8 uStack_38;
  
  lVar2 = *(long *)(param_2 + 0x650);
  cVar1 = *(char *)(param_3 + 0x7d);
  uStack_38 = *(undefined8 *)(lVar2 + 400);
  local_40 = (*(long *)(param_2 + (ulong)*(byte *)(param_2 + 0x80) * 8 + 0x638) -
             *(long *)(lVar2 + 0x1a0)) + *(long *)(lVar2 + 0x188);
  if (*(char *)(param_3 + 0x3b) != -1) {
    FUN_71005fd4d4(param_1,(int)*(char *)(param_3 + 0x3b),0,&local_40,0x160);
  }
  if (cVar1 != -1) {
    FUN_71005fd4d4(param_1,(int)cVar1,4,&local_40,0x160);
  }
  lVar2 = *(long *)(*(long *)(param_2 + 0x40) + 0x70);
  cVar1 = *(char *)(param_3 + 0x7c);
  uStack_38 = *(undefined8 *)(lVar2 + 400);
  local_40 = *(long *)(lVar2 + 0x188) + (ulong)*(uint *)(*(long *)(param_2 + 0x40) + 0x4f0);
  if (*(char *)(param_3 + 0x3a) != -1) {
    FUN_71005fd4d4(param_1,(int)*(char *)(param_3 + 0x3a),0,&local_40,0xcc0);
  }
  if (cVar1 != -1) {
    FUN_71005fd4d4(param_1,(int)cVar1,4,&local_40,0xcc0);
  }
  lVar2 = *(long *)(*(long *)(param_2 + 0x40) + 0x70);
  cVar1 = *(char *)(param_3 + 0x7e);
  uStack_38 = *(undefined8 *)(lVar2 + 400);
  local_40 = *(long *)(lVar2 + 0x188) + (ulong)*(uint *)(*(long *)(param_2 + 0x40) + 0x4fc);
  if (*(char *)(param_3 + 0x3c) != -1) {
    FUN_71005fd4d4(param_1,(int)*(char *)(param_3 + 0x3c),0,&local_40,0x160);
  }
  if (cVar1 != -1) {
    FUN_71005fd4d4(param_1,(int)cVar1,4,&local_40,0x160);
  }
  return 1;
}



undefined8
FUN_71005cfc34(long *param_1,long param_2,long *param_3,long *param_4,byte param_5,int param_6,
              uint param_7,undefined8 param_8,byte param_9,long *param_10,int *param_11,
              undefined *param_12)

{
  uint uVar1;
  byte bVar2;
  char cVar3;
  char cVar4;
  byte bVar5;
  undefined *puVar6;
  ulong uVar7;
  undefined8 uVar8;
  long lVar9;
  long lVar10;
  long lVar11;
  int *piVar12;
  int iVar13;
  long local_b0;
  undefined8 uStack_a8;
  long local_a0;
  long lStack_98;
  long local_90;
  long *plStack_88;
  undefined8 local_80;
  long *plStack_78;
  int *local_70;
  byte local_68;
  int local_64;
  
  if ((param_7 & 1) == 0) {
    return 0;
  }
  piVar12 = (int *)((long)param_3 + (ulong)param_5 * 4 + 0x84);
  if (*piVar12 == param_6) {
    return 0;
  }
  FUN_71005fc9f0(param_2,*param_4,0x1ff);
  lVar9 = param_3[0xca];
  uStack_a8 = *(undefined8 *)(lVar9 + 400);
  local_b0 = (param_3[(ulong)*(byte *)(param_3 + 0x10) + 199] - *(long *)(lVar9 + 0x1a0)) +
             *(long *)(lVar9 + 0x188);
  if (*(char *)((long)param_4 + 0x44) != -1) {
    FUN_71005fd4d4(param_2,(int)*(char *)((long)param_4 + 0x44),5,&local_b0,0x160);
  }
  lVar9 = param_3[8];
  lVar10 = *(long *)(lVar9 + 0x70);
  uStack_a8 = *(undefined8 *)(lVar10 + 400);
  local_b0 = *(long *)(lVar10 + 0x188) + (ulong)*(uint *)(lVar9 + 0x4f0);
  if (*(char *)((long)param_4 + 0x43) != -1) {
    FUN_71005fd4d4(param_2,(int)*(char *)((long)param_4 + 0x43),5,&local_b0,0xcc0);
    lVar9 = param_3[8];
    lVar10 = *(long *)(lVar9 + 0x70);
  }
  uStack_a8 = *(undefined8 *)(lVar10 + 400);
  local_b0 = *(long *)(lVar10 + 0x188) + (ulong)*(uint *)(lVar9 + 0x4fc);
  if (*(char *)((long)param_4 + 0x45) != -1) {
    FUN_71005fd4d4(param_2,(int)*(char *)((long)param_4 + 0x45),5,&local_b0,0x160);
  }
  cVar4 = (char)param_11[3];
  if (param_10 == (long *)0x0) {
LAB_71005cfe1c:
    cVar3 = *(char *)((long)param_4 + 0x19);
    iVar13 = (int)cVar3;
    puVar6 = FUN_71005d1b70();
    if (cVar3 != -1) {
      if (cVar4 != '\0') {
LAB_71005cfe30:
        if (iVar13 == param_11[2]) goto LAB_71005cfe64;
      }
      FUN_71005fd45c(param_2,iVar13,5,(undefined4 *)(puVar6 + 0x260),(undefined4 *)(*param_1 + 0x18)
                    );
      param_11[2] = iVar13;
    }
LAB_71005cfe64:
    if (param_10 != (long *)0x0) goto LAB_71005cfe68;
  }
  else {
    if (*param_10 != -1) {
      cVar3 = *(char *)((long)param_4 + 0x17);
      if ((cVar3 != -1) && ((cVar4 == '\0' || (*param_11 != (int)cVar3)))) {
        FUN_71005fd45c(param_2,(int)cVar3,5,(undefined4 *)param_10,(undefined4 *)(param_1[1] + 0x18)
                      );
        *param_11 = (int)cVar3;
      }
    }
    if (param_10[1] == -1) goto LAB_71005cfe1c;
    cVar3 = (char)param_4[3];
    if (cVar3 == -1) goto LAB_71005cfe1c;
    if ((cVar4 == '\0') || (param_11[1] != (int)cVar3)) {
      FUN_71005fd45c(param_2,(int)cVar3,5,(undefined4 *)(param_10 + 1),
                     (undefined4 *)(param_1[1] + 0x18));
      param_11[1] = (int)cVar3;
      goto LAB_71005cfe1c;
    }
    cVar4 = *(char *)((long)param_4 + 0x19);
    iVar13 = (int)cVar4;
    puVar6 = FUN_71005d1b70();
    if (cVar4 != -1) goto LAB_71005cfe30;
LAB_71005cfe68:
    local_a0 = *param_10;
    lStack_98 = param_10[1];
    local_80 = CONCAT44(CONCAT31(local_80._5_3_,param_5),(int)param_10[4]);
    local_90 = param_10[2];
    plStack_88 = (long *)param_10[3];
    uVar7 = FUN_71005ca308((long)param_3,param_2,param_3,param_8,&local_a0);
    if ((uVar7 & 1) == 0) {
      return 0;
    }
  }
  cVar4 = *(char *)((long)param_4 + 0x4f);
  bVar2 = *(byte *)(param_3 + 0xc6);
  if (cVar4 == -1) {
LAB_71005cff00:
    lVar9 = param_4[10];
    if ((char)lVar9 != -1) {
      bVar5 = FUN_71005cf3e4((undefined1 *)(param_3 + 0xa2));
      if ((bVar5 & 1) == 0) goto LAB_71005d030c;
      local_a0 = 0;
      lStack_98 = 0;
      lVar10 = param_3[0xa9];
      FUN_71005cf4ac((char *)(param_3 + 0xa2),&local_a0,bVar2,param_3[0xcb]);
      FUN_71005fd540(param_2,(int)(char)lVar9,5,&local_a0,lVar10);
    }
    cVar4 = *(char *)((long)param_4 + 0x51);
    if (cVar4 != -1) {
      bVar5 = FUN_71005cf3e4((undefined1 *)(param_3 + 0xaa));
      if ((bVar5 & 1) == 0) goto LAB_71005d030c;
      local_a0 = 0;
      lStack_98 = 0;
      lVar9 = param_3[0xb1];
      FUN_71005cf4ac((char *)(param_3 + 0xaa),&local_a0,bVar2,param_3[0xcb]);
      FUN_71005fd540(param_2,(int)cVar4,5,&local_a0,lVar9);
    }
    cVar4 = *(char *)((long)param_4 + 0x52);
    if (cVar4 != -1) {
      bVar5 = FUN_71005cf3e4((undefined1 *)(param_3 + 0xb2));
      if ((bVar5 & 1) == 0) goto LAB_71005d030c;
      local_a0 = 0;
      lStack_98 = 0;
      lVar9 = param_3[0xb9];
      FUN_71005cf4ac((char *)(param_3 + 0xb2),&local_a0,bVar2,param_3[0xcb]);
      FUN_71005fd540(param_2,(int)cVar4,5,&local_a0,lVar9);
    }
    lVar9 = (long)(int)param_3[0x12] << 4;
    if ((char)param_4[1] != -1) {
      lVar10 = param_3[0xcb];
      uStack_a8 = *(undefined8 *)(lVar10 + 0x10);
      local_b0 = (*(long *)param_3[0xd] - *(long *)(lVar10 + 0x1a0)) + *(long *)(lVar10 + 8);
      FUN_71005fd540(param_2,(int)(char)param_4[1],5,&local_b0,lVar9);
    }
    if (*(char *)((long)param_4 + 9) != -1) {
      lVar10 = param_3[0xcb];
      uStack_a8 = *(undefined8 *)(lVar10 + 0x10);
      local_b0 = (*(long *)(param_3[0xd] + 8) - *(long *)(lVar10 + 0x1a0)) + *(long *)(lVar10 + 8);
      FUN_71005fd540(param_2,(int)*(char *)((long)param_4 + 9),5,&local_b0,lVar9);
    }
    if (*(char *)((long)param_4 + 10) != -1) {
      lVar10 = param_3[0xcb];
      uStack_a8 = *(undefined8 *)(lVar10 + 0x10);
      local_b0 = (*(long *)(param_3[0xd] + 0x10) - *(long *)(lVar10 + 0x1a0)) +
                 *(long *)(lVar10 + 8);
      FUN_71005fd540(param_2,(int)*(char *)((long)param_4 + 10),5,&local_b0,lVar9);
    }
    if (*(char *)((long)param_4 + 0xb) != -1) {
      lVar10 = param_3[0xcb];
      uStack_a8 = *(undefined8 *)(lVar10 + 0x10);
      local_b0 = (*(long *)(param_3[0xd] + 0x18) - *(long *)(lVar10 + 0x1a0)) +
                 *(long *)(lVar10 + 8);
      FUN_71005fd540(param_2,(int)*(char *)((long)param_4 + 0xb),5,&local_b0,lVar9);
    }
    if (*(char *)((long)param_4 + 0xc) != -1) {
      lVar10 = param_3[0xcb];
      uStack_a8 = *(undefined8 *)(lVar10 + 0x10);
      local_b0 = (*(long *)(param_3[0xd] + 0x20) - *(long *)(lVar10 + 0x1a0)) +
                 *(long *)(lVar10 + 8);
      FUN_71005fd540(param_2,(int)*(char *)((long)param_4 + 0xc),5,&local_b0,lVar9);
    }
    if (*(char *)((long)param_4 + 0xd) != -1) {
      lVar10 = *(long *)(param_3[0xd] + 0x40);
      if (lVar10 == 0) {
        lVar10 = *(long *)(param_3[0xd] + 0x20);
      }
      lVar11 = param_3[0xcb];
      uStack_a8 = *(undefined8 *)(lVar11 + 0x10);
      local_b0 = (lVar10 - *(long *)(lVar11 + 0x1a0)) + *(long *)(lVar11 + 8);
      FUN_71005fd540(param_2,(int)*(char *)((long)param_4 + 0xd),5,&local_b0,lVar9);
    }
    if (*(char *)((long)param_4 + 0xe) != -1) {
      lVar10 = *(long *)(param_3[0xd] + 0x48);
      if (lVar10 == 0) {
        lVar10 = *(long *)(param_3[0xd] + 0x20);
      }
      lVar11 = param_3[0xcb];
      uStack_a8 = *(undefined8 *)(lVar11 + 0x10);
      local_b0 = (lVar10 - *(long *)(lVar11 + 0x1a0)) + *(long *)(lVar11 + 8);
      FUN_71005fd540(param_2,(int)*(char *)((long)param_4 + 0xe),5,&local_b0,lVar9);
    }
    if (*(char *)((long)param_4 + 0xf) != -1) {
      lVar10 = *(long *)(param_3[0xd] + 0x50);
      if (lVar10 == 0) {
        lVar10 = *(long *)(param_3[0xd] + 0x20);
      }
      lVar11 = param_3[0xcb];
      uStack_a8 = *(undefined8 *)(lVar11 + 0x10);
      local_b0 = (lVar10 - *(long *)(lVar11 + 0x1a0)) + *(long *)(lVar11 + 8);
      FUN_71005fd540(param_2,(int)*(char *)((long)param_4 + 0xf),5,&local_b0,lVar9);
    }
    if ((char)param_4[2] != -1) {
      lVar10 = *(long *)(param_3[0xd] + 0x58);
      if (lVar10 == 0) {
        lVar10 = *(long *)(param_3[0xd] + 0x20);
      }
      lVar11 = param_3[0xcb];
      uStack_a8 = *(undefined8 *)(lVar11 + 0x10);
      local_b0 = (lVar10 - *(long *)(lVar11 + 0x1a0)) + *(long *)(lVar11 + 8);
      FUN_71005fd540(param_2,(int)(char)param_4[2],5,&local_b0,lVar9);
    }
    if (*(char *)((long)param_11 + 0xd) == '\0') {
      FUN_71005fd1c4(param_2,0x40);
    }
    if (param_12 == (undefined *)0x0) {
      FUN_71005fc338(param_2);
    }
    else {
      local_90 = *param_3;
      plStack_78 = param_10;
      lStack_98 = *(long *)(local_90 + 0x68);
      local_70 = param_11;
      local_a0 = param_2;
      plStack_88 = param_3;
      local_80 = param_8;
      local_68 = param_5;
      local_64 = (int)((float)(int)param_3[0x12] * 0.03125);
      (*(code *)param_12)(&local_a0);
    }
    if ((param_9 & 1) != 0) {
      FUN_71005fd19c(param_2,0x40);
    }
    uVar1 = *(uint *)(param_3 + 6);
    uVar8 = 1;
    *piVar12 = param_6;
    *(uint *)(param_3 + 6) = uVar1 | 0x100;
  }
  else {
    bVar5 = FUN_71005cf3e4((undefined1 *)(param_3 + 0x9a));
    if ((bVar5 & 1) != 0) {
      local_a0 = 0;
      lStack_98 = 0;
      lVar9 = param_3[0xa1];
      FUN_71005cf4ac((char *)(param_3 + 0x9a),&local_a0,bVar2,param_3[0xcb]);
      FUN_71005fd540(param_2,(int)cVar4,5,&local_a0,lVar9);
      goto LAB_71005cff00;
    }
LAB_71005d030c:
    FUN_71005dee10();
    uVar8 = 0;
  }
  return uVar8;
}



undefined8
FUN_71005d0378(long *param_1,long param_2,long *param_3,undefined8 param_4,long *param_5,
              int *param_6)

{
  ulong uVar1;
  long *plVar2;
  long local_88;
  long *plStack_80;
  undefined8 local_78;
  long *plStack_70;
  int *local_60;
  undefined4 local_58;
  undefined1 local_54;
  
  if ((*(char *)(param_3[8] + 0xe9) != '\0') || (*(char *)((long)param_3 + 0x82) != '?')) {
    local_54 = *(undefined1 *)((long)param_5 + 0x2c);
    local_58 = *(undefined4 *)((long)param_5 + 0x24);
    local_88 = param_2;
    plStack_80 = param_3;
    local_78 = param_4;
    plStack_70 = param_5;
    local_60 = param_6;
    uVar1 = FUN_71005c6aa0(param_3 + 0x6e,(long)&local_88);
    if ((uVar1 & 1) != 0) {
LAB_71005d03f0:
      *(uint *)(param_3 + 6) = *(uint *)(param_3 + 6) | 0x80;
      return 1;
    }
    if ((((ulong)*(byte *)((long)param_5 + 0x2c) != 8) &&
        (plVar2 = *(long **)(param_3[8] + (ulong)*(byte *)((long)param_5 + 0x2c) * 8 + 0x10),
        plVar2 != (long *)0x0)) && (*(int *)((long)param_5 + 0x24) == -1)) {
      FUN_71005fc9f0(param_2,*plVar2,0x1ff);
      uVar1 = FUN_71005d0480(param_1,param_2,param_3,(long)plVar2,param_4,param_5,param_6);
      if ((uVar1 & 1) != 0) goto LAB_71005d03f0;
    }
  }
  return 0;
}



undefined8
FUN_71005d0480(long *param_1,long param_2,long *param_3,long param_4,undefined8 param_5,
              long *param_6,int *param_7)

{
  byte bVar1;
  char cVar2;
  int iVar3;
  int iVar4;
  byte bVar5;
  int iVar6;
  int iVar7;
  ulong uVar8;
  undefined8 uVar9;
  undefined8 uVar10;
  long *plVar11;
  long lVar12;
  long lVar13;
  long *plVar14;
  long local_80 [4];
  
  lVar12 = param_3[0xd];
  if (lVar12 != 0) {
    Hint_Prefetch(lVar12,0,0,0);
    Hint_Prefetch(lVar12 + 0x40,0,0,0);
  }
  lVar12 = *(long *)(param_3[8] + 8);
  if (lVar12 != 0) {
    Hint_Prefetch(lVar12,0,0,0);
    Hint_Prefetch(lVar12 + 0x40,0,0,0);
    Hint_Prefetch(lVar12 + 0x80,0,0,0);
    Hint_Prefetch(lVar12 + 0xc0,0,0,0);
  }
  if (*(int *)((long)param_6 + 0x24) == -1) {
    FUN_71005fc820(param_2,(long *)(param_3[8] + 0x2c8));
    FUN_71005fc8c4(param_2,param_3[8] + 0x2f0);
    FUN_71005fc71c(param_2,param_3[8] + 0x30c);
  }
  FUN_71005cf5f4(param_1,param_2,(long)param_3,param_4,param_6,param_7);
  FUN_71005cfadc(param_2,(long)param_3,param_4);
  uVar8 = FUN_71005c9d10(param_3,param_2,*(byte *)((long)param_6 + 0x2c),param_5,(long)param_6);
  if ((uVar8 & 1) == 0) {
    return 0;
  }
  local_80[0] = 0;
  local_80[1] = 0;
  lVar12 = param_3[0xcb];
  local_80[3] = *(undefined8 *)(lVar12 + 0x10);
  local_80[2] = (*(long *)param_3[0xd] - *(long *)(lVar12 + 0x1a0)) + *(long *)(lVar12 + 8);
  FUN_71005fcafc(param_2,(int)*(char *)(param_3[8] + 0xd8),local_80 + 2,0x10,
                 (long)(int)param_3[0x12] << 4);
  plVar11 = local_80 + 2;
  lVar12 = param_3[0xcb];
  local_80[3] = *(undefined8 *)(lVar12 + 0x10);
  local_80[2] = (*(long *)(param_3[0xd] + 8) - *(long *)(lVar12 + 0x1a0)) + *(long *)(lVar12 + 8);
  FUN_71005fcafc(param_2,(int)*(char *)(param_3[8] + 0xd9),plVar11,0x10,
                 (long)(int)param_3[0x12] << 4);
  lVar12 = param_3[8];
  if (*(char *)(lVar12 + 0xda) != -1) {
    plVar11 = local_80 + 2;
    lVar13 = param_3[0xcb];
    local_80[3] = *(undefined8 *)(lVar13 + 0x10);
    local_80[2] = (*(long *)(param_3[0xd] + 0x10) - *(long *)(lVar13 + 0x1a0)) +
                  *(long *)(lVar13 + 8);
    FUN_71005fcafc(param_2,(int)*(char *)(lVar12 + 0xda),plVar11,0x10,(long)(int)param_3[0x12] << 4)
    ;
    lVar12 = param_3[8];
  }
  if (*(char *)(lVar12 + 0xdc) != -1) {
    plVar11 = local_80 + 2;
    lVar13 = param_3[0xcb];
    local_80[3] = *(undefined8 *)(lVar13 + 0x10);
    local_80[2] = (*(long *)(param_3[0xd] + 0x20) - *(long *)(lVar13 + 0x1a0)) +
                  *(long *)(lVar13 + 8);
    FUN_71005fcafc(param_2,(int)*(char *)(lVar12 + 0xdc),plVar11,0x10,(long)(int)param_3[0x12] << 4)
    ;
    lVar12 = param_3[8];
  }
  if (*(char *)(lVar12 + 0xdb) != -1) {
    plVar11 = local_80 + 2;
    lVar13 = param_3[0xcb];
    local_80[3] = *(undefined8 *)(lVar13 + 0x10);
    local_80[2] = (*(long *)(param_3[0xd] + 0x18) - *(long *)(lVar13 + 0x1a0)) +
                  *(long *)(lVar13 + 8);
    FUN_71005fcafc(param_2,(int)*(char *)(lVar12 + 0xdb),plVar11,0x10,(long)(int)param_3[0x12] << 4)
    ;
    lVar12 = param_3[8];
  }
  if (*(char *)(lVar12 + 0xdd) != -1) {
    plVar11 = local_80 + 2;
    lVar13 = param_3[0xcb];
    local_80[3] = *(undefined8 *)(lVar13 + 0x10);
    local_80[2] = (*(long *)(param_3[0xd] + 0x28) - *(long *)(lVar13 + 0x1a0)) +
                  *(long *)(lVar13 + 8);
    FUN_71005fcafc(param_2,(int)*(char *)(lVar12 + 0xdd),plVar11,0x10,(long)(int)param_3[0x12] << 4)
    ;
    lVar12 = param_3[8];
  }
  if (*(char *)(lVar12 + 0xde) != -1) {
    plVar11 = local_80 + 2;
    lVar13 = param_3[0xcb];
    local_80[3] = *(undefined8 *)(lVar13 + 0x10);
    local_80[2] = (*(long *)(param_3[0xd] + 0x30) - *(long *)(lVar13 + 0x1a0)) +
                  *(long *)(lVar13 + 8);
    FUN_71005fcafc(param_2,(int)*(char *)(lVar12 + 0xde),plVar11,0x10,(long)(int)param_3[0x12] << 4)
    ;
    lVar12 = param_3[8];
  }
  if (*(char *)(lVar12 + 0xdf) != -1) {
    plVar11 = local_80 + 2;
    lVar13 = param_3[0xcb];
    local_80[3] = *(undefined8 *)(lVar13 + 0x10);
    local_80[2] = (*(long *)(param_3[0xd] + 0x38) - *(long *)(lVar13 + 0x1a0)) +
                  *(long *)(lVar13 + 8);
    FUN_71005fcafc(param_2,(int)*(char *)(lVar12 + 0xdf),plVar11,0x10,(long)(int)param_3[0x12] << 4)
    ;
    lVar12 = param_3[8];
  }
  if (*(char *)(lVar12 + 0xe0) != -1) {
    plVar11 = local_80 + 2;
    lVar13 = param_3[0xcb];
    local_80[3] = *(undefined8 *)(lVar13 + 0x10);
    local_80[2] = (*(long *)(param_3[0xd] + 0x40) - *(long *)(lVar13 + 0x1a0)) +
                  *(long *)(lVar13 + 8);
    FUN_71005fcafc(param_2,(int)*(char *)(lVar12 + 0xe0),plVar11,0x10,(long)(int)param_3[0x12] << 4)
    ;
    lVar12 = param_3[8];
  }
  if (*(char *)(lVar12 + 0xe1) != -1) {
    plVar11 = local_80 + 2;
    lVar13 = param_3[0xcb];
    local_80[3] = *(undefined8 *)(lVar13 + 0x10);
    local_80[2] = (*(long *)(param_3[0xd] + 0x48) - *(long *)(lVar13 + 0x1a0)) +
                  *(long *)(lVar13 + 8);
    FUN_71005fcafc(param_2,(int)*(char *)(lVar12 + 0xe1),plVar11,0x10,(long)(int)param_3[0x12] << 4)
    ;
    lVar12 = param_3[8];
  }
  if (*(char *)(lVar12 + 0xe2) != -1) {
    plVar11 = local_80 + 2;
    lVar13 = param_3[0xcb];
    local_80[3] = *(undefined8 *)(lVar13 + 0x10);
    local_80[2] = (*(long *)(param_3[0xd] + 0x50) - *(long *)(lVar13 + 0x1a0)) +
                  *(long *)(lVar13 + 8);
    FUN_71005fcafc(param_2,(int)*(char *)(lVar12 + 0xe2),plVar11,0x10,(long)(int)param_3[0x12] << 4)
    ;
    lVar12 = param_3[8];
  }
  if (*(char *)(lVar12 + 0xe4) != -1) {
    plVar11 = local_80 + 2;
    lVar13 = param_3[0xcb];
    local_80[3] = *(undefined8 *)(lVar13 + 0x10);
    local_80[2] = (*(long *)(param_3[0xd] + 0x58) - *(long *)(lVar13 + 0x1a0)) +
                  *(long *)(lVar13 + 8);
    FUN_71005fcafc(param_2,(int)*(char *)(lVar12 + 0xe4),plVar11,0x10,(long)(int)param_3[0x12] << 4)
    ;
  }
  cVar2 = *(char *)(param_4 + 0x46);
  bVar1 = *(byte *)(param_3 + 0xc6);
  if (cVar2 != -1) {
    bVar5 = FUN_71005cf3e4((undefined1 *)(param_3 + 0x9a));
    if ((bVar5 & 1) == 0) goto LAB_71005d0c6c;
    lVar12 = param_3[0xa1];
    local_80[2] = 0;
    local_80[3] = 0;
    FUN_71005cf4ac((char *)(param_3 + 0x9a),local_80 + 2,bVar1,param_3[0xcb]);
    plVar11 = (long *)0x0;
    FUN_71005fd540(param_2,(int)cVar2,0,local_80 + 2,lVar12);
  }
  cVar2 = *(char *)(param_4 + 0x47);
  if (cVar2 != -1) {
    bVar5 = FUN_71005cf3e4((undefined1 *)(param_3 + 0xa2));
    if ((bVar5 & 1) == 0) goto LAB_71005d0c6c;
    lVar12 = param_3[0xa9];
    local_80[2] = 0;
    local_80[3] = 0;
    FUN_71005cf4ac((char *)(param_3 + 0xa2),local_80 + 2,bVar1,param_3[0xcb]);
    plVar11 = (long *)0x0;
    FUN_71005fd540(param_2,(int)cVar2,0,local_80 + 2,lVar12);
  }
  cVar2 = *(char *)(param_4 + 0x48);
  if (cVar2 != -1) {
    bVar5 = FUN_71005cf3e4((undefined1 *)(param_3 + 0xaa));
    if ((bVar5 & 1) == 0) goto LAB_71005d0c6c;
    lVar12 = param_3[0xb1];
    local_80[2] = 0;
    local_80[3] = 0;
    FUN_71005cf4ac((char *)(param_3 + 0xaa),local_80 + 2,bVar1,param_3[0xcb]);
    plVar11 = (long *)0x0;
    FUN_71005fd540(param_2,(int)cVar2,0,local_80 + 2,lVar12);
  }
  cVar2 = *(char *)(param_4 + 0x49);
  if (cVar2 != -1) {
    bVar5 = FUN_71005cf3e4((undefined1 *)(param_3 + 0xb2));
    if ((bVar5 & 1) == 0) goto LAB_71005d0c6c;
    lVar12 = param_3[0xb9];
    local_80[2] = 0;
    local_80[3] = 0;
    FUN_71005cf4ac((char *)(param_3 + 0xb2),local_80 + 2,bVar1,param_3[0xcb]);
    plVar11 = (long *)0x0;
    FUN_71005fd540(param_2,(int)cVar2,0,local_80 + 2,lVar12);
  }
  cVar2 = *(char *)(param_4 + 0x88);
  bVar1 = *(byte *)(param_3 + 0xc6);
  if (cVar2 != -1) {
    bVar5 = FUN_71005cf3e4((undefined1 *)(param_3 + 0x9a));
    if ((bVar5 & 1) == 0) goto LAB_71005d0c6c;
    lVar12 = param_3[0xa1];
    local_80[2] = 0;
    local_80[3] = 0;
    FUN_71005cf4ac((char *)(param_3 + 0x9a),local_80 + 2,bVar1,param_3[0xcb]);
    plVar11 = (long *)&DAT_00000004;
    FUN_71005fd540(param_2,(int)cVar2,4,local_80 + 2,lVar12);
  }
  cVar2 = *(char *)(param_4 + 0x89);
  if (cVar2 != -1) {
    bVar5 = FUN_71005cf3e4((undefined1 *)(param_3 + 0xa2));
    if ((bVar5 & 1) == 0) goto LAB_71005d0c6c;
    lVar12 = param_3[0xa9];
    local_80[2] = 0;
    local_80[3] = 0;
    FUN_71005cf4ac((char *)(param_3 + 0xa2),local_80 + 2,bVar1,param_3[0xcb]);
    plVar11 = (long *)&DAT_00000004;
    FUN_71005fd540(param_2,(int)cVar2,4,local_80 + 2,lVar12);
  }
  cVar2 = *(char *)(param_4 + 0x8a);
  if (cVar2 != -1) {
    bVar5 = FUN_71005cf3e4((undefined1 *)(param_3 + 0xaa));
    if ((bVar5 & 1) == 0) goto LAB_71005d0c6c;
    lVar12 = param_3[0xb1];
    local_80[2] = 0;
    local_80[3] = 0;
    FUN_71005cf4ac((char *)(param_3 + 0xaa),local_80 + 2,bVar1,param_3[0xcb]);
    plVar11 = (long *)&DAT_00000004;
    FUN_71005fd540(param_2,(int)cVar2,4,local_80 + 2,lVar12);
  }
  cVar2 = *(char *)(param_4 + 0x8b);
  if (cVar2 != -1) {
    bVar5 = FUN_71005cf3e4((undefined1 *)(param_3 + 0xb2));
    if ((bVar5 & 1) == 0) {
LAB_71005d0c6c:
      FUN_71005dee10();
      return 0;
    }
    lVar12 = param_3[0xb9];
    local_80[2] = 0;
    local_80[3] = 0;
    FUN_71005cf4ac((char *)(param_3 + 0xb2),local_80 + 2,bVar1,param_3[0xcb]);
    plVar11 = (long *)&DAT_00000004;
    FUN_71005fd540(param_2,(int)cVar2,4,local_80 + 2,lVar12);
  }
  plVar14 = *(long **)(param_3[8] + 8);
  if ((plVar14 != (long *)0x0) && (iVar6 = (**(code **)(*plVar14 + 0x30))(plVar14), 0 < iVar6)) {
    iVar6 = 0;
    do {
      (**(code **)(*plVar14 + 0x20))(plVar14,local_80,iVar6);
      uVar9 = (**(code **)(*plVar14 + 0x10))(plVar14,iVar6);
      uVar10 = (**(code **)(*plVar14 + 0x18))(plVar14,iVar6);
      plVar11 = local_80;
      FUN_71005fcafc(param_2,iVar6,local_80,uVar9,uVar10);
      iVar6 = iVar6 + 1;
      iVar7 = (**(code **)(*plVar14 + 0x30))(plVar14);
    } while (iVar6 < iVar7);
  }
  if (*(int *)((long)param_6 + 0x24) == -1) {
    FUN_71005fc99c(param_2,param_3[8] + (ulong)*(byte *)((long)param_6 + 0x2c) * 0x20 + 0xf8);
  }
  if (*(char *)(param_3[9] + 0xcc1) == '\0') {
    if ((*(byte *)((long)param_3 + 0x31) >> 4 & 1) == 0) {
      if (plVar14 == (long *)0x0) {
        FUN_71005fc39c(param_2,4,4,0,(int)param_3[0x12],0);
      }
      else {
        (**(code **)(*plVar14 + 0x58))
                  (plVar14,param_2,(int)param_3[0x12],*(undefined1 *)((long)param_3 + 0xac));
      }
    }
    else {
      iVar6 = (int)param_3[0x13];
      iVar7 = *(int *)((long)param_3 + 0x94);
      iVar4 = *(int *)((long)param_3 + 0x9c) + iVar6 + -1;
      iVar3 = 0;
      if (iVar6 != 0) {
        iVar3 = iVar4 / iVar6;
      }
      iVar4 = iVar4 - iVar3 * iVar6;
      if (iVar4 < iVar7) {
        iVar6 = iVar6 - iVar7;
        if (plVar14 != (long *)0x0) {
          (**(code **)(*plVar14 + 0x60))
                    (plVar14,param_2,iVar4 + 1,0,*(undefined1 *)((long)param_3 + 0xac));
          (**(code **)(*plVar14 + 0x60))
                    (plVar14,param_2,iVar6,iVar7,*(undefined1 *)((long)param_3 + 0xac));
          goto LAB_71005d0c2c;
        }
        FUN_71005fc39c(param_2,4,4,0,iVar4 + 1,0);
      }
      else {
        iVar6 = (iVar4 - iVar7) + 1;
        if (plVar14 != (long *)0x0) {
          (**(code **)(*plVar14 + 0x60))
                    (plVar14,param_2,iVar6,iVar7,*(undefined1 *)((long)param_3 + 0xac));
          goto LAB_71005d0c2c;
        }
      }
      FUN_71005fc39c(param_2,4,4,0,iVar6,iVar7);
    }
  }
  else {
    FUN_71005d0e10(param_2,(long)param_3,plVar11,plVar14,(long)param_6);
  }
LAB_71005d0c2c:
  FUN_71005c9f28((long)param_3,param_2,param_5,param_6);
  return 1;
}



bool FUN_71005d0e10(long param_1,long param_2,undefined8 param_3,long *param_4,long param_5)

{
  long lVar1;
  int iVar2;
  uint uVar3;
  long lVar4;
  uint uVar5;
  long lVar6;
  long lVar7;
  float fVar8;
  long local_50;
  uint local_44;
  
  local_44 = 0;
  local_50 = 0;
  FUN_71005c97d0(*(float *)(param_2 + 0x28) - *(float *)(param_2 + 0x2c),param_2,&local_50,&local_44
                 ,*(undefined1 *)(*(long *)(param_2 + 0x48) + 0xcc1),*(int *)(param_5 + 0x20),
                 *(long *)(param_5 + 0x10));
  uVar3 = local_44;
  if (0 < (int)local_44) {
    if (param_4 == (long *)0x0) {
      lVar7 = 4;
      lVar6 = 0;
      uVar5 = local_44;
      do {
        iVar2 = *(int *)(local_50 + lVar7);
        lVar1 = *(long *)(param_2 + 0x60) + (long)iVar2 * 0x20;
        fVar8 = *(float *)(lVar1 + 0xc);
        if (((*(float *)(param_2 + 0x28) - *(float *)(lVar1 + 8) <= fVar8) &&
            (*(int *)(*(long *)(param_2 + 0x60) + (long)iVar2 * 0x20) != 0)) && (0.0 < fVar8)) {
          FUN_71005fc39c(param_1,4,4,0,1,iVar2);
          uVar5 = local_44;
        }
        lVar6 = lVar6 + 1;
        lVar7 = lVar7 + 8;
      } while (lVar6 < (int)uVar5);
    }
    else {
      lVar6 = 0;
      lVar7 = 4;
      uVar5 = local_44;
      do {
        lVar4 = (long)*(int *)(local_50 + lVar7);
        lVar1 = *(long *)(param_2 + 0x60) + lVar4 * 0x20;
        fVar8 = *(float *)(lVar1 + 0xc);
        if (((*(float *)(param_2 + 0x28) - *(float *)(lVar1 + 8) <= fVar8) &&
            (*(int *)(*(long *)(param_2 + 0x60) + lVar4 * 0x20) != 0)) && (0.0 < fVar8)) {
          (**(code **)(*param_4 + 0x60))(param_4,param_1,1,lVar4,*(undefined1 *)(param_2 + 0xac));
          uVar5 = local_44;
        }
        lVar6 = lVar6 + 1;
        lVar7 = lVar7 + 8;
      } while (lVar6 < (int)uVar5);
    }
  }
  return uVar3 != 0;
}



void FUN_71005d0f98(void)

{
  ret_7100604248();
  ret_71006043A4();
  ret_71005FD8B0();
  return;
}



void FUN_71005d12c0(undefined8 param_1,long *param_2)

{
  if (DAT_7103ff35a0 != 0) {
    FUN_710060433c(&DAT_7103ff34b8);
    FUN_71006044e0(&DAT_7103ff3470);
    FUN_71005fd94c((undefined8 *)&DAT_7103ff3350);
    (**(code **)(*param_2 + 0x18))(param_2,DAT_7103ff35a0);
    DAT_7103ff35a0 = 0;
  }
  return;
}



void FUN_71005d1340(undefined8 *param_1,undefined8 *param_2,long param_3,long param_4,uint param_5)

{
  undefined1 (*pauVar1) [12];
  char *pcVar2;
  int iVar3;
  float *pfVar4;
  float *pfVar5;
  float *pfVar6;
  undefined4 *puVar7;
  undefined4 *puVar8;
  undefined4 *puVar9;
  float fVar10;
  int iVar11;
  char cVar12;
  int iVar13;
  undefined3 uVar14;
  undefined1 auVar15 [16];
  undefined1 auVar16 [16];
  undefined1 auVar17 [16];
  undefined1 auVar18 [16];
  undefined1 auVar19 [16];
  undefined1 auVar20 [16];
  undefined1 auVar21 [16];
  undefined1 auVar22 [16];
  undefined4 uVar23;
  undefined1 auVar24 [16];
  undefined1 auVar25 [16];
  undefined1 auVar26 [16];
  undefined1 auVar27 [16];
  undefined8 uVar28;
  undefined1 auVar29 [16];
  undefined1 auVar30 [16];
  undefined1 auVar31 [16];
  undefined1 auVar32 [16];
  int iVar33;
  int iVar34;
  int iVar35;
  ulong uVar36;
  ulong uVar37;
  byte *pbVar38;
  undefined1 uVar39;
  undefined1 uVar40;
  undefined1 uVar41;
  undefined1 uVar42;
  undefined1 uVar43;
  undefined1 uVar44;
  undefined1 uVar45;
  undefined1 uVar46;
  undefined1 uVar47;
  undefined1 uVar48;
  undefined1 uVar49;
  undefined1 uVar50;
  undefined1 uVar51;
  undefined1 uVar52;
  undefined1 uVar53;
  undefined1 uVar54;
  undefined1 uVar55;
  undefined1 uVar56;
  undefined1 uVar57;
  undefined1 uVar58;
  float fVar59;
  float fVar60;
  float fVar61;
  float fVar62;
  float fVar63;
  float fVar64;
  float fVar65;
  float fVar66;
  float fVar67;
  undefined1 uVar68;
  byte bVar69;
  undefined1 uVar70;
  byte bVar71;
  undefined1 uVar72;
  byte bVar73;
  undefined1 uVar74;
  byte bVar75;
  undefined1 uVar76;
  byte bVar77;
  undefined1 uVar78;
  byte bVar79;
  undefined1 uVar80;
  byte bVar81;
  undefined1 uVar82;
  byte bVar83;
  undefined1 uVar84;
  byte bVar85;
  undefined1 uVar86;
  byte bVar87;
  undefined1 uVar88;
  byte bVar89;
  undefined1 uVar90;
  byte bVar91;
  byte bVar92;
  byte bVar93;
  byte bVar94;
  byte bVar95;
  float fVar96;
  float fVar97;
  undefined8 uVar98;
  undefined8 uVar99;
  undefined8 uVar100;
  float fVar101;
  float fVar102;
  float fVar103;
  undefined4 uVar104;
  float fVar105;
  undefined4 uVar106;
  float fVar107;
  undefined4 uVar108;
  undefined4 uVar109;
  float fVar110;
  float fVar111;
  undefined1 auVar112 [12];
  undefined1 auVar113 [16];
  undefined8 uVar114;
  undefined1 auVar116 [12];
  undefined8 uVar115;
  undefined1 auVar117 [16];
  float fVar118;
  undefined8 uVar119;
  undefined8 uVar122;
  float fVar126;
  float fVar127;
  undefined1 auVar123 [16];
  undefined8 uVar120;
  undefined8 uVar121;
  undefined1 auVar124 [16];
  undefined1 auVar125 [16];
  float fVar128;
  undefined8 uVar129;
  undefined8 uVar130;
  float fVar131;
  float fVar132;
  undefined8 uVar133;
  undefined8 local_50;
  ulong uStack_48;
  
  uVar37 = (ulong)param_5;
  pbVar38 = *(byte **)(*(long *)(param_3 + 0x40) + 0x410);
  fVar96 = *(float *)(pbVar38 + 0x20);
  if ((pbVar38[1] & 1) != 0) {
    fVar96 = fVar96 * *(float *)(*(long *)(param_4 + 0x20) +
                                (-(ulong)(param_5 >> 0x1f) & 0xfffffff000000000 | uVar37 << 4));
  }
  fVar59 = *(float *)(param_3 + 0x28);
  fVar132 = *(float *)(param_3 + 0x2c);
  uVar133 = *(undefined8 *)(pbVar38 + 0x10);
  fVar61 = *(float *)(pbVar38 + 0x1c);
  fVar101 = (float)param_1[1];
  uVar98 = *param_1;
  fVar10 = *(float *)(pbVar38 + 0x18);
  if (pbVar38[2] != 0) {
    cVar12 = *(char *)(*(long *)(param_3 + 0x48) + 0xcc3);
    if (cVar12 == '\0') {
LAB_71005d148c:
      fVar107 = (float)*(undefined8 *)(param_3 + 0x108);
      fVar103 = (float)*(undefined8 *)(param_3 + 0x100);
      fVar105 = (float)((ulong)*(undefined8 *)(param_3 + 0x100) >> 0x20);
      auVar112 = SUB1612(*(undefined1 (*) [16])(param_3 + 0x110),0);
      auVar116 = SUB1612(*(undefined1 (*) [16])(param_3 + 0x120),0);
      fVar60 = (float)*(undefined8 *)(param_3 + 0x138);
      fVar110 = (float)*(undefined8 *)(param_3 + 0x130);
      fVar111 = (float)((ulong)*(undefined8 *)(param_3 + 0x130) >> 0x20);
    }
    else {
      iVar11 = *(int *)(param_3 + 0x90);
      uVar36 = -(ulong)(param_5 >> 0x1f) & 0xfffffff000000000 | uVar37 << 4;
      pfVar4 = (float *)0x0;
      if ((int)param_5 <= iVar11 && *(long *)(param_3 + 0x350) != 0) {
        pfVar4 = (float *)(*(long *)(param_3 + 0x350) + uVar36);
      }
      pfVar5 = (float *)0x0;
      if ((int)param_5 <= iVar11 && *(long *)(param_3 + 0x358) != 0) {
        pfVar5 = (float *)(*(long *)(param_3 + 0x358) + uVar36);
      }
      pfVar6 = (float *)0x0;
      if ((int)param_5 <= iVar11 && *(long *)(param_3 + 0x360) != 0) {
        pfVar6 = (float *)(*(long *)(param_3 + 0x360) + uVar36);
      }
      if (((pfVar4 == (float *)0x0) || (pfVar5 == (float *)0x0)) || (pfVar6 == (float *)0x0))
      goto LAB_71005d148c;
      if (cVar12 == '\x02') {
        pauVar1 = (undefined1 (*) [12])(param_3 + 0x130);
        uVar104 = (undefined4)((ulong)*(undefined8 *)(param_3 + 0x138) >> 0x20);
        fVar110 = (float)*(undefined8 *)*pauVar1;
        fVar111 = (float)((ulong)*(undefined8 *)*pauVar1 >> 0x20);
        auVar123._12_4_ = uVar104;
        auVar123._0_12_ = *pauVar1;
        auVar124._12_4_ = uVar104;
        auVar124._0_12_ = *pauVar1;
        auVar123 = NEON_ext(auVar123,auVar124,8,1);
        fVar103 = *pfVar4;
        fVar105 = *pfVar5;
        fVar107 = *pfVar6;
        auVar116._0_4_ = pfVar4[2];
        fVar60 = auVar123._0_4_;
        auVar116._4_4_ = pfVar5[2];
        auVar112._0_4_ = pfVar4[1];
        auVar112._4_4_ = pfVar5[1];
        auVar116._8_4_ = pfVar6[2];
        auVar112._8_4_ = pfVar6[1];
      }
      else {
        fVar103 = *pfVar4;
        fVar105 = *pfVar5;
        fVar107 = *pfVar6;
        auVar116._0_4_ = pfVar4[2];
        fVar110 = pfVar4[3];
        auVar112._0_4_ = pfVar4[1];
        auVar116._4_4_ = pfVar5[2];
        fVar111 = pfVar5[3];
        auVar112._4_4_ = pfVar5[1];
        fVar60 = pfVar6[3];
        auVar116._8_4_ = pfVar6[2];
        auVar112._8_4_ = pfVar6[1];
      }
    }
    fVar62 = (float)uVar98;
    fVar65 = (float)((ulong)uVar98 >> 0x20);
    uVar98 = CONCAT44(fVar111 + fVar105 * fVar62 + auVar112._4_4_ * fVar65 +
                                auVar116._4_4_ * fVar101,
                      fVar110 + fVar103 * fVar62 + auVar112._0_4_ * fVar65 +
                                auVar116._0_4_ * fVar101);
    fVar101 = fVar60 + fVar107 * fVar62 + auVar112._8_4_ * fVar65 + auVar116._8_4_ * fVar101;
  }
  fVar103 = fVar96 + (float)*(undefined8 *)(pbVar38 + 4) * fVar59 + (float)uVar98 * fVar61;
  fVar105 = fVar96 + (float)((ulong)*(undefined8 *)(pbVar38 + 4) >> 0x20) * fVar59 +
                     (float)((ulong)uVar98 >> 0x20) * fVar61;
  fVar96 = fVar96 + *(float *)(pbVar38 + 0xc) * fVar59 + fVar101 * fVar61;
  if ((*pbVar38 & 1) == 0) {
    iVar33 = (int)fVar103;
    iVar11 = -iVar33;
    if (-1 < iVar33) {
      iVar11 = iVar33;
    }
    iVar34 = (int)fVar105;
    iVar33 = 0;
    if (DAT_7103ff3348 != 0) {
      iVar33 = iVar11 / DAT_7103ff3348;
    }
    iVar35 = (int)fVar96;
    iVar3 = -iVar34;
    if (-1 < iVar34) {
      iVar3 = iVar34;
    }
    iVar34 = -iVar35;
    if (-1 < iVar35) {
      iVar34 = iVar35;
    }
    iVar35 = 0;
    if (DAT_7103ff3348 != 0) {
      iVar35 = iVar3 / DAT_7103ff3348;
    }
    iVar13 = 0;
    if (DAT_7103ff3348 != 0) {
      iVar13 = iVar34 / DAT_7103ff3348;
    }
    iVar11 = (iVar34 - iVar13 * DAT_7103ff3348) +
             ((iVar3 - iVar35 * DAT_7103ff3348) +
             (iVar11 - iVar33 * DAT_7103ff3348) * DAT_7103ff3348) * DAT_7103ff3348;
    pcVar2 = (char *)(DAT_7103ff3340 + (long)iVar11 + (long)iVar11 * 2);
    local_50 = CONCAT44((float)(int)pcVar2[1] / 127.0,(float)(int)*pcVar2 / 127.0);
    uStack_48 = (ulong)(uint)((float)(int)pcVar2[2] / 127.0);
    bVar69 = pbVar38[2];
  }
  else {
    FUN_71005d1828(fVar103,fVar105,fVar96,DAT_7103a6fa00,&local_50);
    bVar69 = pbVar38[2];
  }
  if (bVar69 == 0) {
    uVar51 = (undefined1)uStack_48;
    uVar52 = (undefined1)(uStack_48 >> 8);
    uVar53 = (undefined1)(uStack_48 >> 0x10);
    uVar54 = (undefined1)(uStack_48 >> 0x18);
    uVar55 = (undefined1)(uStack_48 >> 0x20);
    uVar56 = (undefined1)(uStack_48 >> 0x28);
    uVar57 = (undefined1)(uStack_48 >> 0x30);
    uVar58 = (undefined1)(uStack_48 >> 0x38);
    uVar39 = (undefined1)local_50;
    uVar40 = (undefined1)((ulong)local_50 >> 8);
    uVar41 = (undefined1)((ulong)local_50 >> 0x10);
    uVar42 = (undefined1)((ulong)local_50 >> 0x18);
    uVar43 = (undefined1)((ulong)local_50 >> 0x20);
    uVar45 = (undefined1)((ulong)local_50 >> 0x28);
    uVar47 = (undefined1)((ulong)local_50 >> 0x30);
    uVar49 = (undefined1)((ulong)local_50 >> 0x38);
    goto LAB_71005d17ac;
  }
  if (*(char *)(*(long *)(param_3 + 0x48) + 0xcc3) == '\0') {
LAB_71005d1658:
    uVar98 = *(undefined8 *)(param_3 + 0x108);
    uVar51 = (undefined1)uVar98;
    uVar52 = (undefined1)((ulong)uVar98 >> 8);
    uVar53 = (undefined1)((ulong)uVar98 >> 0x10);
    uVar54 = (undefined1)((ulong)uVar98 >> 0x18);
    uVar55 = (undefined1)((ulong)uVar98 >> 0x20);
    uVar56 = (undefined1)((ulong)uVar98 >> 0x28);
    uVar57 = (undefined1)((ulong)uVar98 >> 0x30);
    uVar58 = (undefined1)((ulong)uVar98 >> 0x38);
    uVar98 = *(undefined8 *)(param_3 + 0x100);
    uVar39 = (undefined1)uVar98;
    uVar40 = (undefined1)((ulong)uVar98 >> 8);
    uVar41 = (undefined1)((ulong)uVar98 >> 0x10);
    uVar42 = (undefined1)((ulong)uVar98 >> 0x18);
    uVar43 = (undefined1)((ulong)uVar98 >> 0x20);
    uVar45 = (undefined1)((ulong)uVar98 >> 0x28);
    uVar47 = (undefined1)((ulong)uVar98 >> 0x30);
    uVar49 = (undefined1)((ulong)uVar98 >> 0x38);
    uVar98 = *(undefined8 *)(param_3 + 0x118);
    uVar84 = (undefined1)uVar98;
    uVar86 = (undefined1)((ulong)uVar98 >> 8);
    uVar88 = (undefined1)((ulong)uVar98 >> 0x10);
    uVar90 = (undefined1)((ulong)uVar98 >> 0x18);
    uVar44 = (undefined1)((ulong)uVar98 >> 0x20);
    uVar46 = (undefined1)((ulong)uVar98 >> 0x28);
    uVar48 = (undefined1)((ulong)uVar98 >> 0x30);
    uVar50 = (undefined1)((ulong)uVar98 >> 0x38);
    uVar98 = *(undefined8 *)(param_3 + 0x110);
    uVar68 = (undefined1)uVar98;
    uVar70 = (undefined1)((ulong)uVar98 >> 8);
    uVar72 = (undefined1)((ulong)uVar98 >> 0x10);
    uVar74 = (undefined1)((ulong)uVar98 >> 0x18);
    uVar76 = (undefined1)((ulong)uVar98 >> 0x20);
    uVar78 = (undefined1)((ulong)uVar98 >> 0x28);
    uVar80 = (undefined1)((ulong)uVar98 >> 0x30);
    uVar82 = (undefined1)((ulong)uVar98 >> 0x38);
    uVar108 = (undefined4)*(undefined8 *)(param_3 + 0x128);
    uVar109 = (undefined4)((ulong)*(undefined8 *)(param_3 + 0x128) >> 0x20);
    uVar104 = (undefined4)*(undefined8 *)(param_3 + 0x120);
    uVar106 = (undefined4)((ulong)*(undefined8 *)(param_3 + 0x120) >> 0x20);
  }
  else {
    iVar11 = *(int *)(param_3 + 0x90);
    uVar37 = -(ulong)(param_5 >> 0x1f) & 0xfffffff000000000 | uVar37 << 4;
    puVar7 = (undefined4 *)0x0;
    if ((int)param_5 <= iVar11 && *(long *)(param_3 + 0x350) != 0) {
      puVar7 = (undefined4 *)(*(long *)(param_3 + 0x350) + uVar37);
    }
    puVar8 = (undefined4 *)0x0;
    if ((int)param_5 <= iVar11 && *(long *)(param_3 + 0x358) != 0) {
      puVar8 = (undefined4 *)(*(long *)(param_3 + 0x358) + uVar37);
    }
    puVar9 = (undefined4 *)0x0;
    if ((int)param_5 <= iVar11 && *(long *)(param_3 + 0x360) != 0) {
      puVar9 = (undefined4 *)(*(long *)(param_3 + 0x360) + uVar37);
    }
    if (((puVar7 == (undefined4 *)0x0) || (puVar8 == (undefined4 *)0x0)) ||
       (puVar9 == (undefined4 *)0x0)) goto LAB_71005d1658;
    uVar55 = 0;
    uVar56 = 0;
    uVar57 = 0;
    uVar58 = 0;
    uVar104 = *puVar7;
    uVar39 = (undefined1)uVar104;
    uVar40 = (undefined1)((uint)uVar104 >> 8);
    uVar41 = (undefined1)((uint)uVar104 >> 0x10);
    uVar42 = (undefined1)((uint)uVar104 >> 0x18);
    uVar104 = *puVar8;
    uVar43 = (undefined1)uVar104;
    uVar45 = (undefined1)((uint)uVar104 >> 8);
    uVar47 = (undefined1)((uint)uVar104 >> 0x10);
    uVar49 = (undefined1)((uint)uVar104 >> 0x18);
    uVar104 = *puVar9;
    uVar51 = (undefined1)uVar104;
    uVar52 = (undefined1)((uint)uVar104 >> 8);
    uVar53 = (undefined1)((uint)uVar104 >> 0x10);
    uVar54 = (undefined1)((uint)uVar104 >> 0x18);
    uVar104 = puVar7[2];
    uVar109 = 0;
    uVar106 = puVar8[2];
    uVar108 = puVar7[1];
    uVar68 = (undefined1)uVar108;
    uVar70 = (undefined1)((uint)uVar108 >> 8);
    uVar72 = (undefined1)((uint)uVar108 >> 0x10);
    uVar74 = (undefined1)((uint)uVar108 >> 0x18);
    uVar44 = 0;
    uVar46 = 0;
    uVar48 = 0;
    uVar50 = 0;
    uVar108 = puVar8[1];
    uVar76 = (undefined1)uVar108;
    uVar78 = (undefined1)((uint)uVar108 >> 8);
    uVar80 = (undefined1)((uint)uVar108 >> 0x10);
    uVar82 = (undefined1)((uint)uVar108 >> 0x18);
    uVar108 = puVar9[2];
    uVar23 = puVar9[1];
    uVar84 = (undefined1)uVar23;
    uVar86 = (undefined1)((uint)uVar23 >> 8);
    uVar88 = (undefined1)((uint)uVar23 >> 0x10);
    uVar90 = (undefined1)((uint)uVar23 >> 0x18);
  }
  auVar19[1] = uVar70;
  auVar19[0] = uVar68;
  auVar19[2] = uVar72;
  auVar19[3] = uVar74;
  auVar19[4] = uVar76;
  auVar19[5] = uVar78;
  auVar19[6] = uVar80;
  auVar19[7] = uVar82;
  auVar19[8] = uVar84;
  auVar19[9] = uVar86;
  auVar19[10] = uVar88;
  auVar19[0xb] = uVar90;
  auVar19[0xc] = uVar44;
  auVar19[0xd] = uVar46;
  auVar19[0xe] = uVar48;
  auVar19[0xf] = uVar50;
  uVar99 = a64_TBL(ZEXT816(0),auVar19,0xb0a090807060504);
  auVar20[1] = uVar70;
  auVar20[0] = uVar68;
  auVar20[2] = uVar72;
  auVar20[3] = uVar74;
  auVar20[4] = uVar76;
  auVar20[5] = uVar78;
  auVar20[6] = uVar80;
  auVar20[7] = uVar82;
  auVar20[8] = uVar84;
  auVar20[9] = uVar86;
  auVar20[10] = uVar88;
  auVar20[0xb] = uVar90;
  auVar20[0xc] = uVar44;
  auVar20[0xd] = uVar46;
  auVar20[0xe] = uVar48;
  auVar20[0xf] = uVar50;
  uVar98 = a64_TBL(ZEXT816(0),auVar20,0xf0e0d0c03020100);
  auVar24._4_4_ = uVar106;
  auVar24._0_4_ = uVar104;
  auVar24._8_4_ = uVar108;
  auVar24._12_4_ = uVar109;
  uVar28 = a64_TBL(ZEXT816(0),auVar24,0xf0e0d0c03020100);
  auVar25._4_4_ = uVar106;
  auVar25._0_4_ = uVar104;
  auVar25._8_4_ = uVar108;
  auVar25._12_4_ = uVar109;
  uVar114 = a64_TBL(ZEXT816(0),auVar25,0x30201000b0a0908);
  auVar26._4_4_ = uVar106;
  auVar26._0_4_ = uVar104;
  auVar26._8_4_ = uVar108;
  auVar26._12_4_ = uVar109;
  uVar119 = a64_TBL(ZEXT816(0),auVar26,0xf0e0d0c07060504);
  auVar21[1] = uVar70;
  auVar21[0] = uVar68;
  auVar21[2] = uVar72;
  auVar21[3] = uVar74;
  auVar21[4] = uVar76;
  auVar21[5] = uVar78;
  auVar21[6] = uVar80;
  auVar21[7] = uVar82;
  auVar21[8] = uVar84;
  auVar21[9] = uVar86;
  auVar21[10] = uVar88;
  auVar21[0xb] = uVar90;
  auVar21[0xc] = uVar44;
  auVar21[0xd] = uVar46;
  auVar21[0xe] = uVar48;
  auVar21[0xf] = uVar50;
  uVar120 = a64_TBL(ZEXT816(0),auVar21,0xf0e0d0c07060504);
  auVar22[1] = uVar70;
  auVar22[0] = uVar68;
  auVar22[2] = uVar72;
  auVar22[3] = uVar74;
  auVar22[4] = uVar76;
  auVar22[5] = uVar78;
  auVar22[6] = uVar80;
  auVar22[7] = uVar82;
  auVar22[8] = uVar84;
  auVar22[9] = uVar86;
  auVar22[10] = uVar88;
  auVar22[0xb] = uVar90;
  auVar22[0xc] = uVar44;
  auVar22[0xd] = uVar46;
  auVar22[0xe] = uVar48;
  auVar22[0xf] = uVar50;
  uVar115 = a64_TBL(ZEXT816(0),auVar22,0x30201000b0a0908);
  auVar27._4_4_ = uVar106;
  auVar27._0_4_ = uVar104;
  auVar27._8_4_ = uVar108;
  auVar27._12_4_ = uVar109;
  uVar121 = a64_TBL(ZEXT816(0),auVar27,0xb0a090807060504);
  uVar109 = CONCAT13(uVar42,CONCAT12(uVar41,CONCAT11(uVar40,uVar39)));
  uVar44 = (undefined1)uVar108;
  uVar46 = (undefined1)((uint)uVar108 >> 8);
  uVar48 = (undefined1)((uint)uVar108 >> 0x10);
  uVar50 = (undefined1)((uint)uVar108 >> 0x18);
  auVar113._0_4_ =
       ((float)CONCAT13(uVar42,CONCAT12(uVar41,CONCAT11(uVar40,uVar39))) * (float)uVar99 *
        (float)uVar114 -
       (float)uVar115 * (float)CONCAT13(uVar42,CONCAT12(uVar41,CONCAT11(uVar40,uVar39))) *
       (float)uVar121) +
       ((float)CONCAT13(uVar49,CONCAT12(uVar47,CONCAT11(uVar45,uVar43))) *
        (float)((ulong)uVar99 >> 0x20) * (float)((ulong)uVar114 >> 0x20) -
       (float)((ulong)uVar115 >> 0x20) *
       (float)CONCAT13(uVar49,CONCAT12(uVar47,CONCAT11(uVar45,uVar43))) *
       (float)((ulong)uVar121 >> 0x20)) +
       ((float)CONCAT13(uVar54,CONCAT12(uVar53,CONCAT11(uVar52,uVar51))) * (float)uVar98 *
        (float)uVar119 -
       (float)uVar120 * (float)CONCAT13(uVar54,CONCAT12(uVar53,CONCAT11(uVar52,uVar51))) *
       (float)uVar28) +
       ((float)CONCAT13(uVar58,CONCAT12(uVar57,CONCAT11(uVar56,uVar55))) *
        (float)((ulong)uVar98 >> 0x20) * (float)((ulong)uVar119 >> 0x20) -
       (float)((ulong)uVar120 >> 0x20) *
       (float)CONCAT13(uVar58,CONCAT12(uVar57,CONCAT11(uVar56,uVar55))) *
       (float)((ulong)uVar28 >> 0x20));
  auVar113._4_4_ = auVar113._0_4_;
  auVar113._8_4_ = auVar113._0_4_;
  auVar113._12_4_ = auVar113._0_4_;
  auVar123 = NEON_frecpe(auVar113,4);
  auVar124 = NEON_frecps(auVar123,auVar113,4);
  auVar117._0_4_ = auVar123._0_4_ * auVar124._0_4_;
  auVar117._4_4_ = auVar123._4_4_ * auVar124._4_4_;
  auVar117._8_4_ = auVar123._8_4_ * auVar124._8_4_;
  auVar117._12_4_ = auVar123._12_4_ * auVar124._12_4_;
  auVar123 = NEON_frecps(auVar117,auVar113,4);
  fVar59 = auVar117._0_4_ * auVar123._0_4_;
  fVar101 = auVar117._4_4_ * auVar123._4_4_;
  fVar103 = auVar117._8_4_ * auVar123._8_4_;
  fVar105 = auVar117._12_4_ * auVar123._12_4_;
  uVar108 = CONCAT13(uVar74,CONCAT12(uVar72,CONCAT11(uVar70,uVar68)));
  auVar125._4_4_ =
       (int)(CONCAT17(uVar82,CONCAT16(uVar80,CONCAT15(uVar78,CONCAT14(uVar76,uVar108)))) >> 0x20);
  auVar125._0_4_ =
       (int)(CONCAT17(uVar49,CONCAT16(uVar47,CONCAT15(uVar45,CONCAT14(uVar43,uVar109)))) >> 0x20);
  auVar125._8_4_ = uVar106;
  auVar125._12_4_ = 0;
  uVar14 = (undefined3)(CONCAT13(uVar53,CONCAT12(uVar52,CONCAT11(uVar51,uVar49))) >> 8);
  uVar99 = a64_TBL(ZEXT816(0),auVar125,0xb0a090807060504);
  uVar115 = a64_TBL(ZEXT816(0),auVar125,0xf0e0d0c03020100);
  auVar15[3] = uVar54;
  auVar15._0_3_ = uVar14;
  auVar15[4] = uVar84;
  auVar15[5] = uVar86;
  auVar15[6] = uVar88;
  auVar15[7] = uVar90;
  auVar15[8] = uVar44;
  auVar15[9] = uVar46;
  auVar15[10] = uVar48;
  auVar15[0xb] = uVar50;
  auVar15._12_4_ = 0;
  uVar129 = a64_TBL(ZEXT816(0),auVar15,0xf0e0d0c07060504);
  auVar16[3] = uVar54;
  auVar16._0_3_ = uVar14;
  auVar16[4] = uVar84;
  auVar16[5] = uVar86;
  auVar16[6] = uVar88;
  auVar16[7] = uVar90;
  auVar16[8] = uVar44;
  auVar16[9] = uVar46;
  auVar16[10] = uVar48;
  auVar16[0xb] = uVar50;
  auVar16._12_4_ = 0;
  uVar130 = a64_TBL(ZEXT816(0),auVar16,0xb0a090807060504);
  auVar29._4_4_ = uVar108;
  auVar29._0_4_ = uVar109;
  auVar29._8_4_ = uVar104;
  auVar29._12_4_ = 0;
  uVar120 = a64_TBL(ZEXT816(0),auVar29,0xb0a090807060504);
  auVar17[3] = uVar54;
  auVar17._0_3_ = uVar14;
  auVar17[4] = uVar84;
  auVar17[5] = uVar86;
  auVar17[6] = uVar88;
  auVar17[7] = uVar90;
  auVar17[8] = uVar44;
  auVar17[9] = uVar46;
  auVar17[10] = uVar48;
  auVar17[0xb] = uVar50;
  auVar17._12_4_ = 0;
  uVar119 = a64_TBL(ZEXT816(0),auVar17,0x30201000b0a0908);
  fVar65 = (float)((ulong)uVar119 >> 0x20);
  auVar18[3] = uVar54;
  auVar18._0_3_ = uVar14;
  auVar18[4] = uVar84;
  auVar18[5] = uVar86;
  auVar18[6] = uVar88;
  auVar18[7] = uVar90;
  auVar18[8] = uVar44;
  auVar18[9] = uVar46;
  auVar18[10] = uVar48;
  auVar18[0xb] = uVar50;
  auVar18._12_4_ = 0;
  uVar98 = a64_TBL(ZEXT816(0),auVar18,0xf0e0d0c03020100);
  auVar30._4_4_ = uVar108;
  auVar30._0_4_ = uVar109;
  auVar30._8_4_ = uVar104;
  auVar30._12_4_ = 0;
  uVar121 = a64_TBL(ZEXT816(0),auVar30,0xf0e0d0c03020100);
  uVar28 = a64_TBL(ZEXT816(0),auVar125,0x30201000b0a0908);
  uVar122 = a64_TBL(ZEXT816(0),auVar125,0xf0e0d0c07060504);
  auVar31._4_4_ = uVar108;
  auVar31._0_4_ = uVar109;
  auVar31._8_4_ = uVar104;
  auVar31._12_4_ = 0;
  uVar100 = a64_TBL(ZEXT816(0),auVar31,0x30201000b0a0908);
  auVar32._4_4_ = uVar108;
  auVar32._0_4_ = uVar109;
  auVar32._8_4_ = uVar104;
  auVar32._12_4_ = 0;
  uVar114 = a64_TBL(ZEXT816(0),auVar32,0xf0e0d0c07060504);
  fVar67 = (float)((ulong)uVar129 >> 0x20);
  fVar107 = (float)((ulong)uVar99 >> 0x20);
  fVar110 = (float)((ulong)uVar115 >> 0x20);
  fVar96 = (float)((ulong)uVar28 >> 0x20);
  fVar64 = (float)((ulong)uVar130 >> 0x20);
  fVar61 = (float)((ulong)uVar122 >> 0x20);
  fVar131 = (float)((ulong)uVar98 >> 0x20);
  fVar63 = (float)((ulong)uVar100 >> 0x20);
  fVar66 = (float)((ulong)uVar114 >> 0x20);
  fVar111 = (float)((ulong)uVar120 >> 0x20);
  fVar60 = (float)((ulong)uVar121 >> 0x20);
  iVar11 = -(uint)(auVar113._0_4_ == 0.0);
  bVar69 = (byte)iVar11;
  bVar71 = (byte)((uint)iVar11 >> 8);
  bVar73 = (byte)((uint)iVar11 >> 0x10);
  bVar75 = (byte)((uint)iVar11 >> 0x18);
  iVar11 = -(uint)(auVar113._0_4_ == 0.0);
  bVar77 = (byte)iVar11;
  bVar79 = (byte)((uint)iVar11 >> 8);
  bVar81 = (byte)((uint)iVar11 >> 0x10);
  bVar83 = (byte)((uint)iVar11 >> 0x18);
  iVar11 = -(uint)(auVar113._0_4_ == 0.0);
  bVar85 = (byte)iVar11;
  bVar87 = (byte)((uint)iVar11 >> 8);
  bVar89 = (byte)((uint)iVar11 >> 0x10);
  bVar91 = (byte)((uint)iVar11 >> 0x18);
  iVar11 = -(uint)(auVar113._0_4_ == 0.0);
  bVar92 = (byte)iVar11;
  bVar93 = (byte)((uint)iVar11 >> 8);
  bVar94 = (byte)((uint)iVar11 >> 0x10);
  bVar95 = (byte)((uint)iVar11 >> 0x18);
  fVar118 = fVar59 * ((float)uVar99 * (float)uVar119 - (float)uVar28 * (float)uVar130);
  fVar126 = fVar101 * (fVar107 * fVar65 - fVar96 * fVar64);
  fVar127 = fVar103 * ((float)uVar115 * (float)uVar129 - (float)uVar122 * (float)uVar98);
  fVar128 = fVar105 * (fVar110 * fVar67 - fVar61 * fVar131);
  fVar97 = (float)CONCAT13((byte)((uint)fVar118 >> 0x18) & ~bVar75,
                           CONCAT12((byte)((uint)fVar118 >> 0x10) & ~bVar73,
                                    CONCAT11((byte)((uint)fVar118 >> 8) & ~bVar71,
                                             SUB41(fVar118,0) & ~bVar69)));
  fVar102 = (float)CONCAT13((byte)((uint)fVar127 >> 0x18) & ~bVar91,
                            CONCAT12((byte)((uint)fVar127 >> 0x10) & ~bVar89,
                                     CONCAT11((byte)((uint)fVar127 >> 8) & ~bVar87,
                                              SUB41(fVar127,0) & ~bVar85)));
  fVar62 = fVar59 * ((float)uVar130 * (float)uVar100 - (float)uVar119 * (float)uVar120);
  fVar64 = fVar101 * (fVar64 * fVar63 - fVar65 * fVar111);
  fVar65 = fVar103 * ((float)uVar98 * (float)uVar114 - (float)uVar129 * (float)uVar121);
  fVar67 = fVar105 * (fVar131 * fVar66 - fVar67 * fVar60);
  fVar59 = fVar59 * ((float)uVar28 * (float)uVar120 - (float)uVar100 * (float)uVar99);
  fVar101 = fVar101 * (fVar96 * fVar111 - fVar63 * fVar107);
  fVar103 = fVar103 * ((float)uVar122 * (float)uVar121 - (float)uVar114 * (float)uVar115);
  fVar105 = fVar105 * (fVar61 * fVar60 - fVar66 * fVar110);
  fVar63 = (float)CONCAT13((byte)((uint)fVar62 >> 0x18) & ~bVar75,
                           CONCAT12((byte)((uint)fVar62 >> 0x10) & ~bVar73,
                                    CONCAT11((byte)((uint)fVar62 >> 8) & ~bVar71,
                                             SUB41(fVar62,0) & ~bVar69)));
  fVar66 = (float)CONCAT13((byte)((uint)fVar65 >> 0x18) & ~bVar91,
                           CONCAT12((byte)((uint)fVar65 >> 0x10) & ~bVar89,
                                    CONCAT11((byte)((uint)fVar65 >> 8) & ~bVar87,
                                             SUB41(fVar65,0) & ~bVar85)));
  fVar96 = (fVar118 * -0.0 - fVar62 * 0.0) - fVar59 * 0.0;
  fVar60 = (fVar126 * -0.0 - fVar64 * 0.0) - fVar101 * 0.0;
  fVar61 = (fVar127 * -0.0 - fVar65 * 0.0) - fVar103 * 0.0;
  fVar65 = (fVar128 * -0.0 - fVar67 * 0.0) - fVar105 * 0.0;
  fVar111 = (float)CONCAT13((byte)((uint)fVar96 >> 0x18) & ~bVar75,
                            CONCAT12((byte)((uint)fVar96 >> 0x10) & ~bVar73,
                                     CONCAT11((byte)((uint)fVar96 >> 8) & ~bVar71,
                                              SUB41(fVar96,0) & ~bVar69)));
  fVar62 = (float)CONCAT13((byte)((uint)fVar61 >> 0x18) & ~bVar91,
                           CONCAT12((byte)((uint)fVar61 >> 0x10) & ~bVar89,
                                    CONCAT11((byte)((uint)fVar61 >> 8) & ~bVar87,
                                             SUB41(fVar61,0) & ~bVar85)));
  fVar61 = (float)local_50;
  fVar107 = (float)((ulong)local_50 >> 0x20);
  fVar110 = (float)uStack_48;
  fVar96 = fVar97 * fVar61 + fVar63 * fVar107 +
           (float)CONCAT13((byte)((uint)fVar59 >> 0x18) & ~bVar75,
                           CONCAT12((byte)((uint)fVar59 >> 0x10) & ~bVar73,
                                    CONCAT11((byte)((uint)fVar59 >> 8) & ~bVar71,
                                             SUB41(fVar59,0) & ~bVar69))) * fVar110 + fVar111;
  uVar39 = SUB41(fVar96,0);
  uVar40 = (undefined1)((uint)fVar96 >> 8);
  uVar41 = (undefined1)((uint)fVar96 >> 0x10);
  uVar42 = (undefined1)((uint)fVar96 >> 0x18);
  fVar96 = (float)(CONCAT17((byte)((uint)fVar126 >> 0x18) & ~bVar83,
                            CONCAT16((byte)((uint)fVar126 >> 0x10) & ~bVar81,
                                     CONCAT15((byte)((uint)fVar126 >> 8) & ~bVar79,
                                              CONCAT14(SUB41(fVar126,0) & ~bVar77,fVar97)))) >> 0x20
                  ) * fVar61 +
           (float)(CONCAT17((byte)((uint)fVar64 >> 0x18) & ~bVar83,
                            CONCAT16((byte)((uint)fVar64 >> 0x10) & ~bVar81,
                                     CONCAT15((byte)((uint)fVar64 >> 8) & ~bVar79,
                                              CONCAT14(SUB41(fVar64,0) & ~bVar77,fVar63)))) >> 0x20)
           * fVar107 +
           (float)CONCAT13((byte)((uint)fVar101 >> 0x18) & ~bVar83,
                           CONCAT12((byte)((uint)fVar101 >> 0x10) & ~bVar81,
                                    CONCAT11((byte)((uint)fVar101 >> 8) & ~bVar79,
                                             SUB41(fVar101,0) & ~bVar77))) * fVar110 +
           (float)(CONCAT17((byte)((uint)fVar60 >> 0x18) & ~bVar83,
                            CONCAT16((byte)((uint)fVar60 >> 0x10) & ~bVar81,
                                     CONCAT15((byte)((uint)fVar60 >> 8) & ~bVar79,
                                              CONCAT14(SUB41(fVar60,0) & ~bVar77,fVar111)))) >> 0x20
                  );
  uVar43 = SUB41(fVar96,0);
  uVar45 = (undefined1)((uint)fVar96 >> 8);
  uVar47 = (undefined1)((uint)fVar96 >> 0x10);
  uVar49 = (undefined1)((uint)fVar96 >> 0x18);
  fVar96 = fVar102 * fVar61 + fVar66 * fVar107 +
           (float)CONCAT13((byte)((uint)fVar103 >> 0x18) & ~bVar91,
                           CONCAT12((byte)((uint)fVar103 >> 0x10) & ~bVar89,
                                    CONCAT11((byte)((uint)fVar103 >> 8) & ~bVar87,
                                             SUB41(fVar103,0) & ~bVar85))) * fVar110 + fVar62;
  uVar51 = SUB41(fVar96,0);
  uVar52 = (undefined1)((uint)fVar96 >> 8);
  uVar53 = (undefined1)((uint)fVar96 >> 0x10);
  uVar54 = (undefined1)((uint)fVar96 >> 0x18);
  fVar96 = (float)(CONCAT17((byte)((uint)fVar128 >> 0x18) & ~bVar95,
                            CONCAT16((byte)((uint)fVar128 >> 0x10) & ~bVar94,
                                     CONCAT15((byte)((uint)fVar128 >> 8) & ~bVar93,
                                              CONCAT14(SUB41(fVar128,0) & ~bVar92,fVar102)))) >>
                  0x20) * fVar61 +
           (float)(CONCAT17((byte)((uint)fVar67 >> 0x18) & ~bVar95,
                            CONCAT16((byte)((uint)fVar67 >> 0x10) & ~bVar94,
                                     CONCAT15((byte)((uint)fVar67 >> 8) & ~bVar93,
                                              CONCAT14(SUB41(fVar67,0) & ~bVar92,fVar66)))) >> 0x20)
           * fVar107 +
           (float)CONCAT13((byte)((uint)fVar105 >> 0x18) & ~bVar95,
                           CONCAT12((byte)((uint)fVar105 >> 0x10) & ~bVar94,
                                    CONCAT11((byte)((uint)fVar105 >> 8) & ~bVar93,
                                             SUB41(fVar105,0) & ~bVar92))) * fVar110 +
           (float)(CONCAT17((byte)((uint)fVar65 >> 0x18) & ~bVar95,
                            CONCAT16((byte)((uint)fVar65 >> 0x10) & ~bVar94,
                                     CONCAT15((byte)((uint)fVar65 >> 8) & ~bVar93,
                                              CONCAT14(SUB41(fVar65,0) & ~bVar92,fVar62)))) >> 0x20)
  ;
  uVar55 = SUB41(fVar96,0);
  uVar56 = (undefined1)((uint)fVar96 >> 8);
  uVar57 = (undefined1)((uint)fVar96 >> 0x10);
  uVar58 = (undefined1)((uint)fVar96 >> 0x18);
LAB_71005d17ac:
  fVar96 = (float)((ulong)*param_2 >> 0x20) +
           (float)((ulong)uVar133 >> 0x20) *
           (float)CONCAT13(uVar49,CONCAT12(uVar47,CONCAT11(uVar45,uVar43))) * fVar132;
  fVar61 = (float)((ulong)param_2[1] >> 0x20) +
           (float)CONCAT13(uVar58,CONCAT12(uVar57,CONCAT11(uVar56,uVar55))) * 0.0 * fVar132;
  param_2[1] = CONCAT17((char)((uint)fVar61 >> 0x18),
                        CONCAT16((char)((uint)fVar61 >> 0x10),
                                 CONCAT15((char)((uint)fVar61 >> 8),
                                          CONCAT14(SUB41(fVar61,0),
                                                   (float)param_2[1] +
                                                   fVar10 * (float)CONCAT13(uVar54,CONCAT12(uVar53,
                                                  CONCAT11(uVar52,uVar51))) * fVar132))));
  *param_2 = CONCAT17((char)((uint)fVar96 >> 0x18),
                      CONCAT16((char)((uint)fVar96 >> 0x10),
                               CONCAT15((char)((uint)fVar96 >> 8),
                                        CONCAT14(SUB41(fVar96,0),
                                                 (float)*param_2 +
                                                 (float)uVar133 *
                                                 (float)CONCAT13(uVar42,CONCAT12(uVar41,CONCAT11(
                                                  uVar40,uVar39))) * fVar132))));
  return;
}



void FUN_71005d1828(float param_1,float param_2,float param_3,long *param_4,undefined8 *param_5)

{
  char *pcVar1;
  char *pcVar2;
  char *pcVar3;
  char *pcVar4;
  char *pcVar5;
  char *pcVar6;
  char *pcVar7;
  char *pcVar8;
  uint uVar9;
  uint uVar10;
  int iVar11;
  char cVar12;
  char cVar13;
  char cVar14;
  char cVar15;
  uint uVar16;
  uint uVar17;
  int iVar18;
  int iVar19;
  int iVar20;
  uint uVar21;
  long lVar22;
  uint uVar23;
  long lVar24;
  uint uVar25;
  long lVar26;
  long lVar27;
  long lVar28;
  long lVar29;
  float fVar30;
  float fVar31;
  float fVar32;
  float fVar33;
  float fVar34;
  float fVar35;
  float fVar36;
  float fVar37;
  float fVar38;
  float fVar39;
  float fVar40;
  
  uVar21 = (uint)param_1;
  uVar25 = (uint)param_2;
  iVar11 = (int)param_4[1];
  uVar23 = (uint)param_3;
  uVar16 = ~uVar21;
  uVar17 = -uVar21;
  if (-1 < (int)uVar21) {
    uVar17 = uVar21;
  }
  uVar9 = -uVar25;
  if (-1 < (int)uVar25) {
    uVar9 = uVar25;
  }
  uVar10 = -uVar23;
  if (-1 < (int)uVar23) {
    uVar10 = uVar23;
  }
  iVar18 = 0;
  if (iVar11 != 0) {
    iVar18 = (int)uVar9 / iVar11;
  }
  if (-1 < (int)(uVar21 + 1)) {
    uVar16 = uVar21 + 1;
  }
  lVar22 = *param_4;
  iVar18 = uVar9 - iVar18 * iVar11;
  iVar19 = 0;
  if (iVar11 != 0) {
    iVar19 = (int)uVar17 / iVar11;
  }
  iVar20 = 0;
  if (iVar11 != 0) {
    iVar20 = (int)uVar10 / iVar11;
  }
  lVar29 = (long)(int)(uVar10 - iVar20 * iVar11);
  iVar19 = (uVar17 - iVar19 * iVar11) * iVar11;
  lVar28 = (long)((iVar19 + iVar18) * iVar11);
  pcVar1 = (char *)(lVar22 + (lVar28 + lVar29) * 3);
  iVar20 = 0;
  if (iVar11 != 0) {
    iVar20 = (int)uVar16 / iVar11;
  }
  fVar30 = param_1 - (float)(int)param_1;
  fVar31 = param_2 - (float)(int)param_2;
  iVar20 = (uVar16 - iVar20 * iVar11) * iVar11;
  fVar32 = param_3 - (float)(int)param_3;
  lVar24 = (long)((iVar20 + iVar18) * iVar11);
  pcVar2 = (char *)(lVar22 + (lVar24 + lVar29) * 3);
  uVar17 = ~uVar25;
  if (-1 < (int)(uVar25 + 1)) {
    uVar17 = uVar25 + 1;
  }
  iVar18 = 0;
  if (iVar11 != 0) {
    iVar18 = (int)uVar17 / iVar11;
  }
  iVar18 = uVar17 - iVar18 * iVar11;
  lVar26 = (long)((iVar18 + iVar19) * iVar11);
  lVar27 = (long)((iVar18 + iVar20) * iVar11);
  pcVar3 = (char *)(lVar22 + (lVar26 + lVar29) * 3);
  pcVar4 = (char *)(lVar22 + (lVar27 + lVar29) * 3);
  uVar17 = ~uVar23;
  if (-1 < (int)(uVar23 + 1)) {
    uVar17 = uVar23 + 1;
  }
  iVar18 = 0;
  if (iVar11 != 0) {
    iVar18 = (int)uVar17 / iVar11;
  }
  lVar29 = (long)(int)(uVar17 - iVar18 * iVar11);
  pcVar5 = (char *)(lVar22 + (lVar29 + lVar28) * 3);
  pcVar6 = (char *)(lVar22 + (lVar29 + lVar24) * 3);
  pcVar7 = (char *)(lVar22 + (lVar29 + lVar26) * 3);
  pcVar8 = (char *)(lVar22 + (lVar29 + lVar27) * 3);
  cVar12 = *pcVar8;
  cVar13 = *pcVar7;
  cVar14 = pcVar7[1];
  cVar15 = pcVar8[1];
  fVar33 = (float)(int)*pcVar1 / 127.0 +
           ((float)(int)*pcVar2 / 127.0 - (float)(int)*pcVar1 / 127.0) * fVar30;
  fVar34 = (float)(int)pcVar1[1] / 127.0 +
           ((float)(int)pcVar2[1] / 127.0 - (float)(int)pcVar1[1] / 127.0) * fVar30;
  fVar35 = (float)(int)pcVar1[2] / 127.0 +
           ((float)(int)pcVar2[2] / 127.0 - (float)(int)pcVar1[2] / 127.0) * fVar30;
  fVar36 = fVar30 * 0.0 + 0.0;
  fVar33 = fVar33 + (((float)(int)*pcVar3 / 127.0 +
                     ((float)(int)*pcVar4 / 127.0 - (float)(int)*pcVar3 / 127.0) * fVar30) - fVar33)
                    * fVar31;
  fVar34 = fVar34 + (((float)(int)pcVar3[1] / 127.0 +
                     ((float)(int)pcVar4[1] / 127.0 - (float)(int)pcVar3[1] / 127.0) * fVar30) -
                    fVar34) * fVar31;
  fVar35 = fVar35 + (((float)(int)pcVar3[2] / 127.0 +
                     ((float)(int)pcVar4[2] / 127.0 - (float)(int)pcVar3[2] / 127.0) * fVar30) -
                    fVar35) * fVar31;
  fVar36 = fVar36 + ((fVar30 * 0.0 + 0.0) - fVar36) * fVar31;
  fVar37 = (float)(int)*pcVar5 / 127.0 +
           ((float)(int)*pcVar6 / 127.0 - (float)(int)*pcVar5 / 127.0) * fVar30;
  fVar38 = (float)(int)pcVar5[1] / 127.0 +
           ((float)(int)pcVar6[1] / 127.0 - (float)(int)pcVar5[1] / 127.0) * fVar30;
  fVar39 = (float)(int)pcVar5[2] / 127.0 +
           ((float)(int)pcVar6[2] / 127.0 - (float)(int)pcVar5[2] / 127.0) * fVar30;
  fVar40 = fVar30 * 0.0 + 0.0;
  param_5[1] = CONCAT44(fVar36 + ((fVar40 + ((fVar30 * 0.0 + 0.0) - fVar40) * fVar31) - fVar36) *
                                 fVar32,
                        fVar35 + ((fVar39 + (((float)(int)pcVar7[2] / 127.0 +
                                             ((float)(int)pcVar8[2] / 127.0 -
                                             (float)(int)pcVar7[2] / 127.0) * fVar30) - fVar39) *
                                            fVar31) - fVar35) * fVar32);
  *param_5 = CONCAT44(fVar34 + ((fVar38 + (((float)(int)cVar14 / 127.0 +
                                           ((float)(int)cVar15 / 127.0 - (float)(int)cVar14 / 127.0)
                                           * fVar30) - fVar38) * fVar31) - fVar34) * fVar32,
                      fVar33 + ((fVar37 + (((float)(int)cVar13 / 127.0 +
                                           ((float)(int)cVar12 / 127.0 - (float)(int)cVar13 / 127.0)
                                           * fVar30) - fVar37) * fVar31) - fVar33) * fVar32);
  return;
}



undefined * FUN_71005d1b70(void)

{
  return &DAT_7103ff3350;
}



void FUN_71005d1b80(undefined *UNRECOVERED_JUMPTABLE,undefined8 param_2)

{
                    // WARNING: Could not recover jumptable at 0x0071005d1b98. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)UNRECOVERED_JUMPTABLE)(DAT_7103a6fa08 + 0x260,DAT_7103a6fa08 + 0x120,param_2);
  return;
}



undefined8
FUN_71005d1c10(undefined8 *param_1,long param_2,int param_3,undefined4 param_4,undefined1 param_5,
              undefined8 *param_6)

{
  undefined4 uVar1;
  ulong uVar2;
  ulong uVar3;
  undefined8 uVar4;
  long lVar5;
  long *plVar6;
  undefined1 auVar7 [16];
  undefined8 local_70;
  undefined8 *puStack_68;
  
  param_1[4] = 0xffffffffffffffff;
  param_1[5] = 0xffffffffffffffff;
  param_1[3] = 0xffffffffffffffff;
  param_1[0x15] = *param_6;
  param_1[0x16] = param_6[1];
  param_1[0x17] = param_6[2];
  uVar4 = param_6[4];
  *(undefined4 *)(param_1 + 0x4c) = 0;
  param_1[0x18] = uVar4;
  if (param_2 == 0) {
    return 0;
  }
  param_1[0x11] = *(undefined8 *)(param_2 + 0x420);
  lVar5 = *(long *)(param_2 + 0x430) + (long)param_3 * 0x28;
  if (*(int *)(param_2 + 0x550) <= param_3) {
    lVar5 = 0;
  }
  param_1[2] = lVar5;
  if (lVar5 == 0) {
LAB_71005d1e60:
    uVar4 = 0;
  }
  else {
    for (plVar6 = *(long **)(lVar5 + 8); plVar6 != (long *)0x0; plVar6 = (long *)plVar6[0x7a]) {
      uVar2 = FUN_71005d4cf8(plVar6,param_2,*(undefined **)(param_1[0x15] + 0x2330),
                             *(undefined **)(param_1[0x15] + 0x2338));
      if ((uVar2 & 1) == 0) goto LAB_71005d1e60;
      if (*(char *)((long)plVar6 + 0xe5) != '\0') {
        uVar2 = 0;
        do {
          uVar3 = FUN_71005d4cf8((long *)plVar6[uVar2 + 0x6a],param_2,
                                 *(undefined **)(param_1[0x15] + 0x2330),
                                 *(undefined **)(param_1[0x15] + 0x2338));
          if ((uVar3 & 1) == 0) goto LAB_71005d1e60;
          uVar2 = uVar2 + 1;
        } while (uVar2 < *(byte *)((long)plVar6 + 0xe5));
      }
    }
    *(int *)(param_1 + 0x46) = param_3;
    *(undefined4 *)((long)param_1 + 0x234) = param_4;
    uVar1 = *(undefined4 *)(param_2 + 0x54c);
    *(undefined1 *)((long)param_1 + 0x65) = param_5;
    *(undefined1 *)((long)param_1 + 0x66) = 0x80;
    param_1[0x12] = 0;
    *(undefined1 *)((long)param_1 + 100) = 0;
    *(undefined4 *)(param_1 + 10) = uVar1;
    *param_1 = 0;
    param_1[1] = 0;
    param_1[0xf] = 0;
    param_1[0x10] = 0;
    uVar4 = param_6[3];
    param_1[0x13] = 0;
    *(undefined4 *)(param_1 + 0x47) = 0;
    *(undefined4 *)((long)param_1 + 0x25c) = 0x3f800000;
    *(undefined2 *)(param_1 + 0x1f) = 0;
    *(undefined4 *)((long)param_1 + 0x5c) = 0x3f800000;
    param_1[0x4d] = 0;
    *(undefined4 *)(param_1 + 0x49) = 0;
    param_1[0xe] = uVar4;
    param_1[6] = 0xffffffff00000000;
    *(undefined8 *)((long)param_1 + 0x24c) = 0x3f8000003f800000;
    *(undefined8 *)((long)param_1 + 0x54) = 0x3f80000000000000;
    param_1[0x3d] = 0x3f800000;
    param_1[0x3c] = 0x3f8000003f800000;
    param_1[0x19] = 0;
    param_1[0x1a] = 0;
    param_1[0x1b] = 0;
    param_1[0x1c] = 0;
    param_1[0x1d] = 0;
    param_1[0x1e] = 0;
    param_1[0x33] = 0x3f800000;
    param_1[0x32] = 0x3f8000003f800000;
    param_1[0x35] = 0x3f800000;
    param_1[0x34] = 0x3f8000003f800000;
    param_1[0x37] = 0;
    param_1[0x36] = 0;
    param_1[0x43] = 0;
    param_1[0x42] = 0;
    param_1[0x44] = param_6[5];
    param_1[0x45] = param_6[6];
    uVar1 = *(undefined4 *)(param_6 + 7);
    param_1[0x14] = 0;
    *(undefined4 *)((long)param_1 + 0x23c) = uVar1;
    *(uint *)(param_1 + 7) = *(uint *)(param_1 + 7) & 0xfffffc00 | 0x12;
    param_1[0x2e] = 0;
    param_1[0x2f] = 0;
    param_1[0x30] = 0;
    param_1[0x31] = 0;
    param_1[0x2d] = 0x3f800000;
    param_1[0x2c] = 0;
    param_1[0x21] = 0;
    param_1[0x20] = 0x3f800000;
    param_1[0x23] = 0;
    param_1[0x22] = 0x3f80000000000000;
    param_1[0x25] = 0x3f800000;
    param_1[0x24] = 0;
    param_1[0x27] = 0;
    param_1[0x26] = 0;
    param_1[0x29] = 0;
    param_1[0x28] = 0x3f800000;
    param_1[0x2b] = 0;
    param_1[0x2a] = 0x3f80000000000000;
    FUN_71005d1e90((long)param_1);
    auVar7 = NEON_fmov(0x3f800000,4);
    *(undefined4 *)((long)param_1 + 0x25c) = 0x3f800000;
    *(undefined8 *)((long)param_1 + 0x254) = 0x3f8000003f800000;
    param_1[9] = auVar7._8_8_;
    param_1[8] = auVar7._0_8_;
    param_1[0x39] = 0x3f800000;
    param_1[0x38] = 0x3f8000003f800000;
    param_1[0x3b] = 0x3f800000;
    param_1[0x3a] = 0x3f8000003f800000;
    param_1[0x3f] = 0;
    param_1[0x3e] = 0;
    if ((code *)param_1[0x44] != (code *)0x0) {
      local_70 = param_1[0xd];
      puStack_68 = param_1;
      (*(code *)param_1[0x44])(&local_70);
    }
    uVar4 = 1;
  }
  return uVar4;
}



void FUN_71005d1e90(long param_1)

{
  uint uVar1;
  uint uVar2;
  uint *puVar3;
  long *plVar4;
  long *plVar5;
  undefined8 *puVar6;
  long lVar7;
  int iVar8;
  int iVar9;
  long *plVar10;
  ulong uVar11;
  undefined1 auVar12 [16];
  
  puVar3 = (uint *)FUN_71005e46b0();
  uVar1 = *puVar3 ^ *puVar3 << 0xb;
  uVar2 = puVar3[3];
  *puVar3 = puVar3[1];
  puVar3[1] = puVar3[2];
  uVar1 = uVar1 >> 8 ^ uVar2 >> 0x13 ^ uVar1 ^ uVar2;
  puVar3[2] = uVar2;
  puVar3[3] = uVar1;
  *(uint *)(param_1 + 0x264) = uVar1;
  plVar10 = *(long **)(*(long *)(param_1 + 0x10) + 8);
  if (plVar10 != (long *)0x0) {
    auVar12 = NEON_fmov(0x3f800000,4);
    do {
      plVar4 = FUN_71005d206c(param_1,plVar10,*(undefined4 *)(param_1 + 0x23c),0,-1);
      if (plVar4 != (long *)0x0) {
        *(short *)(param_1 + 0xe8) = *(short *)(param_1 + 0xe8) + 1;
        if ((*(byte *)((long)plVar4 + 0x32) >> 4 & 1) == 0) {
          *(uint *)(param_1 + 0x38) = *(uint *)(param_1 + 0x38) | 0x40;
        }
        if (*(char *)(plVar4[8] + 0xe5) != '\0') {
          uVar11 = 0;
          do {
            plVar5 = *(long **)(plVar4[10] + uVar11 * 8);
            if (((plVar5 != (long *)0x0) && (*(char *)(*plVar5 + 0xd5c) == '\0')) &&
               (plVar5 = FUN_71005d206c(param_1,plVar5,0,(long)plVar4,(int)uVar11),
               plVar5 != (long *)0x0)) {
              *(undefined4 *)(plVar5[0xb] + 0x78) = *(undefined4 *)((long)plVar4 + 0xec);
              plVar5[0x21] = 0;
              plVar5[0x20] = 0x3f800000;
              plVar5[0x23] = 0;
              plVar5[0x22] = 0x3f80000000000000;
              plVar5[0x25] = 0x3f800000;
              plVar5[0x24] = 0;
              plVar5[0x27] = 0;
              plVar5[0x26] = 0;
              plVar5[0x29] = 0;
              plVar5[0x28] = 0x3f800000;
              plVar5[0x2b] = 0;
              plVar5[0x2a] = 0x3f80000000000000;
              plVar5[0x2d] = 0x3f800000;
              plVar5[0x2c] = 0;
              plVar5[0x2f] = 0;
              plVar5[0x2e] = 0;
              *(float *)(plVar5[0xb] + 0x88) = (float)*(int *)(plVar4[8] + 0xf0);
              *(undefined4 *)(plVar5[0xb] + 0x8c) = 0;
              *(undefined4 *)(plVar5[0xb] + 0x7c) = 0xffffffff;
              puVar6 = (undefined8 *)plVar5[0xb];
              puVar6[1] = auVar12._8_8_;
              *puVar6 = auVar12._0_8_;
              lVar7 = plVar5[0xb];
              *(undefined8 *)(lVar7 + 0x18) = 0;
              *(undefined8 *)(lVar7 + 0x10) = 0;
              lVar7 = plVar5[0xb];
              *(undefined8 *)(lVar7 + 0x28) = 0;
              *(undefined8 *)(lVar7 + 0x20) = 0;
            }
            uVar11 = uVar11 + 1;
          } while (uVar11 < *(byte *)(plVar4[8] + 0xe5));
        }
      }
      plVar10 = (long *)plVar10[0x7a];
    } while (plVar10 != (long *)0x0);
  }
  lVar7 = *(long *)(param_1 + 8);
  if (lVar7 == 0) {
    iVar9 = 0;
  }
  else {
    iVar8 = 0;
    do {
      plVar10 = (long *)(lVar7 + 0x40);
      lVar7 = *(long *)(lVar7 + 8);
      iVar9 = *(int *)(*plVar10 + 0xf0);
      if (iVar9 <= iVar8) {
        iVar9 = iVar8;
      }
      iVar8 = iVar9;
    } while (lVar7 != 0);
  }
  *(int *)(param_1 + 0x240) = iVar9;
  return;
}



long * FUN_71005d206c(long param_1,long *param_2,undefined4 param_3,long param_4,int param_5)

{
  byte bVar1;
  uint uVar2;
  long *plVar3;
  long lVar4;
  long *plVar5;
  long lVar6;
  long lVar7;
  long *local_f8;
  undefined8 uStack_f0;
  long local_e8;
  long *plStack_e0;
  undefined8 local_d8;
  long lStack_d0;
  undefined8 local_c8;
  undefined4 local_c0;
  long local_b8 [13];
  
  plVar3 = (long *)(**(code **)(**(long **)(param_1 + 0xb8) + 0x10))();
  if (plVar3 != (long *)0x0) {
    local_b8[0xb] = 0;
    local_b8[0xc] = 0;
    local_b8[9] = 0;
    local_b8[10] = 0;
    local_b8[0] = 0;
    local_b8[7] = 0;
    local_b8[8] = 0;
    local_b8[5] = 0;
    local_b8[6] = 0;
    local_b8[3] = 0;
    local_b8[4] = 0;
    local_b8[1] = 0;
    local_b8[2] = 0;
    bVar1 = FUN_71005c6740(local_b8,param_2,*(long *)(param_1 + 0xa8));
    if ((bVar1 >> 1 & 1) != 0) {
      *plVar3 = param_1;
    }
    uStack_f0 = *(undefined8 *)(param_1 + 0x88);
    local_d8 = *(undefined8 *)(param_1 + 0x70);
    local_c8 = *(undefined8 *)(param_1 + 0xb0);
    local_f8 = local_b8;
    local_e8 = param_1;
    plStack_e0 = param_2;
    lStack_d0 = param_4;
    local_c0 = param_3;
    uVar2 = FUN_71005c6b7c(plVar3,(long *)&local_f8);
    if ((uVar2 & 1) == 0) {
      FUN_71005c8cc8((long)plVar3,*(undefined8 *)(param_1 + 0x88),
                     (ulong)((*(uint *)(plVar3 + 6) & 0x20) == 0));
      FUN_71005c86e8((long)plVar3);
      (**(code **)(**(long **)(param_1 + 0xb8) + 0x18))(*(long **)(param_1 + 0xb8),plVar3);
      plVar3 = (long *)0x0;
    }
    else {
      FUN_71005c92a8((long)plVar3,*(undefined4 *)(*param_2 + 0xcd4));
      if (param_5 != -1) {
        *(int *)(plVar3[0xb] + 0x84) = param_5;
      }
      if ((*(byte *)(plVar3 + 6) & 1) == 0) {
        if (*(long *)(param_1 + 0x80) == 0) {
          *(long **)(param_1 + 0x80) = plVar3;
          plVar3[0x1f] = 0;
          plVar3[1] = 0;
          lVar6 = *(long *)(param_1 + 8);
        }
        else {
          *(long **)(*(long *)(param_1 + 0x80) + 8) = plVar3;
          plVar3[0x1f] = *(long *)(param_1 + 0x80);
          *(long **)(param_1 + 0x80) = plVar3;
          plVar3[1] = 0;
          lVar6 = *(long *)(param_1 + 8);
        }
        plVar5 = (long *)(param_1 + 8);
      }
      else {
        *(long *)(plVar3[0xb] + 0x70) = param_4;
        lVar4 = (long)*(int *)(plVar3[0xb] + 0x84);
        lVar6 = *(long *)(param_4 + 0x50) + lVar4 * 8;
        lVar7 = *(long *)(lVar6 + 0x100);
        if (lVar7 == 0) {
          *(long **)(lVar6 + 0x100) = plVar3;
          plVar3[0x1f] = 0;
          plVar3[1] = 0;
          plVar5 = (long *)(*(long *)(param_4 + 0x50) + lVar4 * 8 + 0x80);
          lVar6 = *plVar5;
        }
        else {
          *(long **)(lVar7 + 8) = plVar3;
          plVar3[0x1f] = *(long *)(*(long *)(param_4 + 0x50) + lVar4 * 8 + 0x100);
          *(long **)(*(long *)(param_4 + 0x50) + lVar4 * 8 + 0x100) = plVar3;
          plVar3[1] = 0;
          plVar5 = (long *)(*(long *)(param_4 + 0x50) + lVar4 * 8 + 0x80);
          lVar6 = *plVar5;
        }
      }
      if (lVar6 == 0) {
        *plVar5 = (long)plVar3;
      }
      *(undefined4 *)((long)plVar3 + 0xec) = *(undefined4 *)(param_1 + 0x238);
      *(int *)(param_1 + 0x238) = *(int *)(param_1 + 0x238) + 1;
    }
  }
  return plVar3;
}



undefined8 FUN_71005d2280(long param_1,long param_2)

{
  long lVar1;
  long lVar2;
  long lVar3;
  long lVar4;
  
  while (lVar1 = param_2, lVar1 != 0) {
    param_2 = *(long *)(lVar1 + 8);
    if ((*(int *)(lVar1 + 0xf0) == *(int *)(param_1 + 0x234)) && (*(long *)(lVar1 + 0x708) != 0)) {
      if (*(long *)(lVar1 + 0x50) != 0) {
        lVar3 = 0;
        do {
          lVar4 = *(long *)(*(long *)(lVar1 + 0x50) + lVar3 * 8 + 0x80);
          while (lVar2 = lVar4, lVar2 != 0) {
            lVar4 = *(long *)(lVar2 + 8);
            if ((*(int *)(lVar2 + 0xf0) == *(int *)(param_1 + 0x234)) &&
               (*(long *)(lVar2 + 0x708) != 0)) {
              FUN_71005c8cc8(lVar2,*(undefined8 *)(param_1 + 0x88),1);
              FUN_71005c86e8(lVar2);
              (**(code **)(**(long **)(param_1 + 0xb8) + 0x18))(*(long **)(param_1 + 0xb8),lVar2);
            }
          }
          lVar3 = lVar3 + 1;
        } while (lVar3 != 0x10);
      }
      FUN_71005c8cc8(lVar1,*(undefined8 *)(param_1 + 0x88),1);
      FUN_71005c86e8(lVar1);
      (**(code **)(**(long **)(param_1 + 0xb8) + 0x18))(*(long **)(param_1 + 0xb8),lVar1);
    }
  }
  return 1;
}



undefined8 FUN_71005d2390(long param_1)

{
  undefined8 local_30;
  long lStack_28;
  
  if (*(long *)(param_1 + 0x90) != 0) {
    FUN_71005d2280(param_1,*(long *)(param_1 + 0x90));
    *(undefined8 *)(param_1 + 0x90) = 0;
    *(undefined1 *)(param_1 + 100) = 0;
  }
  FUN_71005d2280(param_1,*(long *)(param_1 + 8));
  if (*(code **)(param_1 + 0x228) != (code *)0x0) {
    local_30 = *(undefined8 *)(param_1 + 0x68);
    lStack_28 = param_1;
    (**(code **)(param_1 + 0x228))(&local_30);
    *(undefined8 *)(param_1 + 0x228) = 0;
  }
  *(undefined4 *)(param_1 + 0x38) = 0;
  *(undefined4 *)(param_1 + 0x234) = 0xffffffff;
  return 1;
}



void FUN_71005d2410(float param_1,long param_2)

{
  long lVar1;
  undefined1 (*pauVar2) [12];
  int iVar3;
  
  if (0.0 < param_1) {
    iVar3 = (int)param_1;
    lVar1 = *(long *)(param_2 + 0x68) + 0xc70;
    pauVar2 = (undefined1 (*) [12])(*(long *)(param_2 + 0x68) + 0x7c);
    if (0 < iVar3) {
      do {
        FUN_71005d24e0(1.0,param_2,'\0',1,(undefined *)0x0,lVar1,pauVar2,(undefined *)0x0);
        iVar3 = iVar3 + -1;
      } while (iVar3 != 0);
    }
    if (0.0 < param_1 - (float)(int)(float)(int)param_1) {
      FUN_71005d24e0(param_1 - (float)(int)(float)(int)param_1,param_2,'\0',1,(undefined *)0x0,lVar1
                     ,pauVar2,(undefined *)0x0);
      return;
    }
  }
  return;
}



void FUN_71005d24e0(float param_1,long param_2,char param_3,uint param_4,undefined *param_5,
                   long param_6,undefined1 (*param_7) [12],undefined *param_8)

{
  char cVar1;
  bool bVar2;
  uint uVar3;
  uint uVar4;
  long lVar5;
  long lVar6;
  long *plVar7;
  long *plVar8;
  ulong uVar9;
  long *plVar10;
  long *plVar11;
  uint uVar12;
  long local_68;
  
  if (((*(long *)(param_2 + 0x90) == 0) || (cVar1 = *(char *)(param_2 + 100), cVar1 == '\0')) ||
     (*(char *)(param_2 + 100) = cVar1 + -1, cVar1 != '\x01')) {
    uVar3 = *(uint *)(param_2 + 0x38);
  }
  else {
    FUN_71005d2280(param_2,*(long *)(param_2 + 0x90));
    *(undefined8 *)(param_2 + 0x90) = 0;
    *(undefined1 *)(param_2 + 100) = 0;
    uVar3 = *(uint *)(param_2 + 0x38);
  }
  if ((uVar3 >> 1 & 1) != 0) {
    plVar7 = *(long **)(param_2 + 8);
    if (plVar7 != (long *)0x0) {
      Hint_Prefetch(plVar7,0,0,0);
      Hint_Prefetch(plVar7 + 8,0,0,0);
      Hint_Prefetch(plVar7 + 0x10,0,0,0);
      Hint_Prefetch(plVar7 + 0x18,0,0,0);
      Hint_Prefetch(plVar7 + 0x20,0,0,0);
      Hint_Prefetch(plVar7 + 0x28,0,0,0);
      Hint_Prefetch(plVar7 + 0x30,0,0,0);
      Hint_Prefetch(plVar7 + 0x38,0,0,0);
      Hint_Prefetch(plVar7 + 0x40,0,0,0);
      Hint_Prefetch(plVar7 + 0x48,0,0,0);
      Hint_Prefetch(plVar7 + 0x50,0,0,0);
      Hint_Prefetch(plVar7 + 0x58,0,0,0);
      Hint_Prefetch(plVar7 + 0x60,0,0,0);
      Hint_Prefetch(plVar7 + 0x68,0,0,0);
      Hint_Prefetch(plVar7 + 0x70,0,0,0);
      Hint_Prefetch(plVar7 + 0x78,0,0,0);
      Hint_Prefetch(plVar7 + 0x80,0,0,0);
      Hint_Prefetch(plVar7 + 0x88,0,0,0);
      Hint_Prefetch(plVar7 + 0x90,0,0,0);
      Hint_Prefetch(plVar7 + 0x98,0,0,0);
      Hint_Prefetch(plVar7 + 0xa0,0,0,0);
      Hint_Prefetch(plVar7 + 0xa8,0,0,0);
      Hint_Prefetch(plVar7 + 0xb0,0,0,0);
      Hint_Prefetch(plVar7 + 0xb8,0,0,0);
      Hint_Prefetch(plVar7 + 0xc0,0,0,0);
      Hint_Prefetch(plVar7 + 200,0,0,0);
      Hint_Prefetch(plVar7 + 0xd0,0,0,0);
      Hint_Prefetch(plVar7 + 0xd8,0,0,0);
      Hint_Prefetch(plVar7 + 0xe0,0,0,0);
    }
    *(undefined4 *)(param_2 + 0x67) = 1;
    *(undefined2 *)(param_2 + 0xf8) = 0;
    *(undefined4 *)(param_2 + 0x30) = 0;
    *(undefined8 *)(param_2 + 0x268) = 0;
    *(float *)(param_2 + 0x58) = param_1;
    *(undefined8 *)(param_2 + 0xe8) = 0;
    *(undefined8 *)(param_2 + 0xf0) = 0;
    *(undefined8 *)(param_2 + 0xd8) = 0;
    *(undefined8 *)(param_2 + 0xe0) = 0;
    *(undefined8 *)(param_2 + 200) = 0;
    *(undefined8 *)(param_2 + 0xd0) = 0;
    if ((0.0 < param_1) && (param_8 != (undefined *)0x0)) {
      local_68 = param_2;
      cVar1 = (*(code *)param_8)(&local_68);
      if (cVar1 == '\x02') {
        *(uint *)(param_2 + 0x38) = *(uint *)(param_2 + 0x38) | 0x20;
      }
      else if (cVar1 == '\x01') {
        FUN_71005f2fb0(*(long *)(param_2 + 0x68),param_2);
      }
      uVar3 = *(uint *)(param_2 + 0x38);
    }
    if ((uVar3 >> 2 & 1) == 0) {
      if (plVar7 == (long *)0x0) {
        *(undefined4 *)(param_2 + 0x67) = 0;
      }
      else {
        uVar12 = 0;
        do {
          plVar8 = (long *)plVar7[1];
          if (plVar8 != (long *)0x0) {
            Hint_Prefetch(plVar8,0,0,0);
            Hint_Prefetch(plVar8 + 8,0,0,0);
            Hint_Prefetch(plVar8 + 0x10,0,0,0);
            Hint_Prefetch(plVar8 + 0x18,0,0,0);
            Hint_Prefetch(plVar8 + 0x20,0,0,0);
            Hint_Prefetch(plVar8 + 0x28,0,0,0);
            Hint_Prefetch(plVar8 + 0x30,0,0,0);
            Hint_Prefetch(plVar8 + 0x38,0,0,0);
            Hint_Prefetch(plVar8 + 0x40,0,0,0);
            Hint_Prefetch(plVar8 + 0x48,0,0,0);
            Hint_Prefetch(plVar8 + 0x50,0,0,0);
            Hint_Prefetch(plVar8 + 0x58,0,0,0);
            Hint_Prefetch(plVar8 + 0x60,0,0,0);
            Hint_Prefetch(plVar8 + 0x68,0,0,0);
            Hint_Prefetch(plVar8 + 0x70,0,0,0);
            Hint_Prefetch(plVar8 + 0x78,0,0,0);
            Hint_Prefetch(plVar8 + 0x80,0,0,0);
            Hint_Prefetch(plVar8 + 0x88,0,0,0);
            Hint_Prefetch(plVar8 + 0x90,0,0,0);
            Hint_Prefetch(plVar8 + 0x98,0,0,0);
            Hint_Prefetch(plVar8 + 0xa0,0,0,0);
            Hint_Prefetch(plVar8 + 0xa8,0,0,0);
            Hint_Prefetch(plVar8 + 0xb0,0,0,0);
            Hint_Prefetch(plVar8 + 0xb8,0,0,0);
            Hint_Prefetch(plVar8 + 0xc0,0,0,0);
            Hint_Prefetch(plVar8 + 200,0,0,0);
            Hint_Prefetch(plVar8 + 0xd0,0,0,0);
            Hint_Prefetch(plVar8 + 0xd8,0,0,0);
            Hint_Prefetch(plVar8 + 0xe0,0,0,0);
          }
          if (((-1 < *(char *)(param_2 + 0x38)) ||
              ((int)plVar7[0x12] != 0 || *(int *)(param_2 + 0x248) != 0)) ||
             (*(float *)(plVar7 + 5) <= 0.0)) {
            uVar3 = FUN_71005d2a1c(param_1,param_2,plVar7,param_3,param_4 & 1,param_5,param_6,
                                   param_7);
            *(char *)((long)plVar7 + 0x83) = (char)uVar3;
            *(uint *)(plVar7 + 6) = *(uint *)(plVar7 + 6) & 0xffffffef;
            lVar5 = plVar7[8];
            if (*(char *)(lVar5 + 0xe5) != '\0') {
              uVar9 = 0;
              do {
                plVar10 = *(long **)(plVar7[10] + uVar9 * 8 + 0x80);
                if (plVar10 != (long *)0x0) {
                  do {
                    while( true ) {
                      plVar11 = (long *)plVar10[1];
                      if (plVar11 != (long *)0x0) {
                        Hint_Prefetch(plVar11,0,0,0);
                        Hint_Prefetch(plVar11 + 8,0,0,0);
                        Hint_Prefetch(plVar11 + 0x10,0,0,0);
                        Hint_Prefetch(plVar11 + 0x18,0,0,0);
                        Hint_Prefetch(plVar11 + 0x20,0,0,0);
                        Hint_Prefetch(plVar11 + 0x28,0,0,0);
                        Hint_Prefetch(plVar11 + 0x30,0,0,0);
                        Hint_Prefetch(plVar11 + 0x38,0,0,0);
                        Hint_Prefetch(plVar11 + 0x40,0,0,0);
                        Hint_Prefetch(plVar11 + 0x48,0,0,0);
                        Hint_Prefetch(plVar11 + 0x50,0,0,0);
                        Hint_Prefetch(plVar11 + 0x58,0,0,0);
                        Hint_Prefetch(plVar11 + 0x60,0,0,0);
                        Hint_Prefetch(plVar11 + 0x68,0,0,0);
                        Hint_Prefetch(plVar11 + 0x70,0,0,0);
                        Hint_Prefetch(plVar11 + 0x78,0,0,0);
                        Hint_Prefetch(plVar11 + 0x80,0,0,0);
                        Hint_Prefetch(plVar11 + 0x88,0,0,0);
                        Hint_Prefetch(plVar11 + 0x90,0,0,0);
                        Hint_Prefetch(plVar11 + 0x98,0,0,0);
                        Hint_Prefetch(plVar11 + 0xa0,0,0,0);
                        Hint_Prefetch(plVar11 + 0xa8,0,0,0);
                        Hint_Prefetch(plVar11 + 0xb0,0,0,0);
                        Hint_Prefetch(plVar11 + 0xb8,0,0,0);
                        Hint_Prefetch(plVar11 + 0xc0,0,0,0);
                        Hint_Prefetch(plVar11 + 200,0,0,0);
                        Hint_Prefetch(plVar11 + 0xd0,0,0,0);
                        Hint_Prefetch(plVar11 + 0xd8,0,0,0);
                        Hint_Prefetch(plVar11 + 0xe0,0,0,0);
                      }
                      uVar4 = FUN_71005d2a1c(param_1,param_2,plVar10,param_3,param_4 & 1,param_5,
                                             param_6,param_7);
                      *(char *)((long)plVar10 + 0x83) = (char)uVar3;
                      if ((uVar4 & 0xff) == 0) break;
                      FUN_71005d3300(param_2,(long)plVar10);
                      FUN_71005c8cc8((long)plVar10,*(undefined8 *)(param_2 + 0x88),1);
                      FUN_71005c86e8((long)plVar10);
                      (**(code **)(**(long **)(param_2 + 0xb8) + 0x18))
                                (*(long **)(param_2 + 0xb8),plVar10);
                      uVar12 = uVar12 | (*(byte *)((long)plVar10 + 0x31) & 4) >> 2;
                      plVar10 = plVar11;
                      if (plVar11 == (long *)0x0) goto LAB_71005d27a0;
                    }
                    *(uint *)(plVar7 + 6) = *(uint *)(plVar7 + 6) | 0x10;
                    uVar12 = uVar12 | (*(byte *)((long)plVar10 + 0x31) & 4) >> 2;
                    plVar10 = plVar11;
                  } while (plVar11 != (long *)0x0);
LAB_71005d27a0:
                  lVar5 = plVar7[8];
                }
                uVar9 = uVar9 + 1;
              } while (uVar9 < *(byte *)(lVar5 + 0xe5));
            }
            if (((uVar3 & 0xff) != 0) && ((*(byte *)(plVar7 + 6) >> 4 & 1) == 0))
            goto LAB_71005d2904;
          }
          else {
            *(float *)(plVar7 + 5) = *(float *)(plVar7 + 5) + param_1;
            *(short *)(param_2 + 0xe8) = *(short *)(param_2 + 0xe8) + 1;
            if (((-1 < *(char *)(param_2 + 0x38)) || (-1 < *(int *)(param_2 + 0x60))) &&
               (bVar2 = FUN_71005c92b0(plVar7), bVar2)) {
LAB_71005d2904:
              FUN_71005d3300(param_2,(long)plVar7);
              FUN_71005c8cc8((long)plVar7,*(undefined8 *)(param_2 + 0x88),1);
              FUN_71005c86e8((long)plVar7);
              (**(code **)(**(long **)(param_2 + 0xb8) + 0x18))(*(long **)(param_2 + 0xb8),plVar7);
            }
          }
          uVar12 = uVar12 | (*(byte *)((long)plVar7 + 0x31) & 4) >> 2;
          plVar7 = plVar8;
        } while (plVar8 != (long *)0x0);
        *(undefined4 *)(param_2 + 0x67) = 0;
        uVar3 = *(uint *)(param_2 + 0x38);
        if (uVar12 != 0) {
          uVar3 = uVar3 | 1;
          *(uint *)(param_2 + 0x38) = uVar3;
        }
      }
      if ((((uVar3 >> 7 & 1) != 0) && (0.0 < param_1)) && (0 < *(int *)(param_2 + 0x248))) {
        if (0 < *(int *)(param_2 + 0x244)) {
          lVar5 = 0;
          lVar6 = 0x50;
          do {
            lVar5 = lVar5 + 1;
            *(undefined8 *)(*(long *)(param_2 + 0xa0) + lVar6) = 0;
            lVar6 = lVar6 + 0x60;
          } while (lVar5 < *(int *)(param_2 + 0x244));
        }
        *(undefined4 *)(param_2 + 0x248) = 0;
      }
      *(float *)(param_2 + 0x54) = *(float *)(param_2 + 0x58) + *(float *)(param_2 + 0x54);
    }
    else {
      *(ushort *)(param_2 + 0xe8) = (ushort)*(byte *)(*(long *)(param_2 + 0x10) + 0x22);
      *(undefined4 *)(param_2 + 0x67) = 0;
    }
  }
  return;
}



void FUN_71005d2a00(long param_1)

{
  FUN_71005f2fb0(*(long *)(param_1 + 0x68),param_1);
  return;
}



uint FUN_71005d2a1c(float param_1,long param_2,long *param_3,char param_4,uint param_5,
                   undefined *param_6,long param_7,undefined1 (*param_8) [12])

{
  char cVar1;
  char cVar2;
  bool bVar3;
  ulong uVar4;
  long lVar5;
  uint uVar6;
  long *local_58;
  
  lVar5 = param_3[9];
  Hint_Prefetch(lVar5 + 0xd68,0,0,0);
  Hint_Prefetch(lVar5 + 0xda8,0,0,0);
  Hint_Prefetch(lVar5 + 0xde8,0,0,0);
  Hint_Prefetch(lVar5 + 0xe28,0,0,0);
  if (param_1 <= 0.0) {
    uVar4 = FUN_71005c8fd0((long)param_3,param_4);
    if ((uVar4 & 1) != 0) {
      FUN_71005d8578(param_3);
      FUN_71005d846c((long)param_3);
      FUN_71005da528(param_1,*(float *)((long)param_3 + 0x74),param_3);
    }
    FUN_71005d38bc((long *)(param_2 + 200),(long)param_3);
    uVar6 = 1;
    goto LAB_71005d2c10;
  }
  cVar1 = param_8[1][5];
  if (param_6 != (undefined *)0x0) {
    local_58 = param_3;
    cVar2 = (*(code *)param_6)(lVar5,&local_58);
    if (cVar2 == '\x01') {
      return 1;
    }
    if ((cVar2 == '\x02') && ((*(uint *)(param_3 + 6) >> 10 & 1) == 0)) {
      *(uint *)(param_3 + 6) = *(uint *)(param_3 + 6) | 0x400;
    }
  }
  if ((*(byte *)((long)param_3 + 0x31) >> 3 & 1) == 0) {
    bVar3 = FUN_71005d8ac0(param_1,param_3,param_4,*(uint *)(param_2 + 0x38) >> 5 & 1,
                           (*(uint *)(param_2 + 0x38) & 0x80) == 0,param_5 & 1,param_8,
                           *(undefined8 *)(param_2 + 0xc0));
    if (bVar3) {
      if (((cVar1 != '\0') && ((*(byte *)((long)param_3 + 0x32) & 1) != 0)) &&
         ((bVar3 = FUN_71005c93b8((long)param_3), !bVar3 || (*(long *)(param_3[8] + 0x1f8) != 0))))
      {
        FUN_71005d2c90(param_7,(long)param_3,0);
        lVar5 = param_3[8];
        if (*(long *)(lVar5 + 0x58) != 0) {
          FUN_71005d2c90(param_7 + 0x38,(long)param_3,1);
          lVar5 = param_3[8];
        }
        if (*(long *)(lVar5 + 0x60) != 0) {
          FUN_71005d2c90(param_7 + 0x70,(long)param_3,2);
        }
      }
      FUN_71005d38bc((long *)(param_2 + 200),(long)param_3);
      goto LAB_71005d2bf0;
    }
    uVar6 = 0;
  }
  else {
    *(float *)((long)param_3 + 0x2c) = param_1;
    uVar4 = FUN_71005c8fd0((long)param_3,param_4);
    if ((uVar4 & 1) != 0) {
      FUN_71005d8578(param_3);
      FUN_71005d846c((long)param_3);
      FUN_71005da528(param_1,*(float *)((long)param_3 + 0x74),param_3);
    }
    FUN_71005d38bc((long *)(param_2 + 200),(long)param_3);
    *(short *)(param_2 + 0xea) = *(short *)(param_2 + 0xea) + 1;
LAB_71005d2bf0:
    uVar6 = 1;
  }
  *(int *)(param_2 + 0x3c) = *(int *)(param_2 + 0x3c) + 1;
LAB_71005d2c10:
  *(uint *)(param_2 + 0x30) =
       *(uint *)(param_2 + 0x30) | 1 << (ulong)(*(uint *)(param_3 + 7) & 0x1f);
  uVar4 = FUN_71005c9038((long)param_3);
  if ((uVar4 & 1) != 0) {
    *(uint *)(param_2 + 0x268) =
         *(uint *)(param_2 + 0x268) | 1 << (ulong)(*(uint *)(param_3 + 7) & 0x1f);
  }
  uVar4 = FUN_71005c9170((long)param_3);
  if ((uVar4 & 1) != 0) {
    *(uint *)(param_2 + 0x26c) =
         *(uint *)(param_2 + 0x26c) | 1 << (ulong)(*(uint *)(param_3 + 7) & 0x1f);
  }
  return uVar6 ^ 1;
}



void FUN_71005d2c90(long param_1,long param_2,byte param_3)

{
  long lVar1;
  long lVar2;
  
  thunk_EXT_FUN_02e95df0(param_1 + 8);
  lVar1 = *(long *)(param_1 + 0x28);
  lVar2 = lVar1;
  if (lVar1 != 0) {
    do {
      if (lVar2 == param_2) goto LAB_71005d2d10;
      lVar2 = *(long *)(lVar2 + (ulong)param_3 * 8 + 0x10);
    } while (lVar2 != 0);
    if (lVar1 != 0) {
      *(long *)(*(long *)(param_1 + 0x30) + (ulong)param_3 * 8 + 0x10) = param_2;
      goto LAB_71005d2d04;
    }
  }
  *(long *)(param_1 + 0x28) = param_2;
LAB_71005d2d04:
  *(long *)(param_1 + 0x30) = param_2;
  *(undefined8 *)(param_2 + (ulong)param_3 * 8 + 0x10) = 0;
LAB_71005d2d10:
  thunk_EXT_FUN_02e95df0(param_1 + 8);
  return;
}



void FUN_71005d2d30(long param_1,long *param_2,byte param_3,long param_4,uint param_5,uint param_6,
                   undefined8 param_7,long *param_8,char *param_9,long param_10,int *param_11,
                   undefined *param_12,undefined *param_13)

{
  uint uVar1;
  uint uVar2;
  byte bVar3;
  bool bVar4;
  ulong uVar5;
  long lVar6;
  long *plVar7;
  ulong uVar8;
  long *plVar9;
  long *plVar10;
  long *local_a8;
  undefined8 uStack_a0;
  undefined8 local_98;
  long *plStack_90;
  undefined8 local_88;
  long *plStack_80;
  int *local_78;
  undefined4 local_70;
  undefined1 local_6c;
  byte local_6b;
  undefined1 local_6a;
  
  lVar6 = *(long *)(param_4 + 0x40);
  if (*(char *)(lVar6 + 0xe5) != '\0') {
    uVar8 = 0;
    do {
      if ((*(byte *)(**(long **)(lVar6 + uVar8 * 8 + 0x350) + 0xd59) == (param_3 & 1)) &&
         (plVar9 = *(long **)(*(long *)(param_4 + 0x50) + uVar8 * 8 + 0x80), plVar9 != (long *)0x0))
      {
        do {
          plVar7 = plVar9 + 8;
          lVar6 = *plVar7;
          Hint_Prefetch(lVar6,0,0,0);
          Hint_Prefetch(lVar6 + 0x40,0,0,0);
          Hint_Prefetch(lVar6 + 0x80,0,0,0);
          Hint_Prefetch(lVar6 + 0xc0,0,0,0);
          plVar10 = (long *)plVar9[1];
          Hint_Prefetch(plVar9,0,0,0);
          Hint_Prefetch(plVar7,0,0,0);
          Hint_Prefetch(plVar9 + 0x10,0,0,0);
          Hint_Prefetch(plVar9 + 0x18,0,0,0);
          lVar6 = plVar9[0xe1];
          if (((((*(uint *)(plVar9 + 6) ^ 0xffffffff) & 0x2004) != 0) ||
              ((bVar4 = FUN_71005c93b8((long)plVar9), bVar4 || (*(float *)(plVar9 + 0xf) <= 0.0))))
             || (((int)plVar9[0x12] < 1 &&
                 (((int)plVar9[0x12] != 0 || (2 < *(byte *)(*plVar7 + 0xe6) - 1)))))) {
            bVar4 = true;
            uVar1 = *(uint *)((long)plVar9 + 0x3c);
            uVar2 = *(uint *)(param_8 + 5);
            bVar3 = *(byte *)(plVar9 + 6);
          }
          else {
            bVar4 = false;
            uVar1 = *(uint *)((long)plVar9 + 0x3c);
            uVar2 = *(uint *)(param_8 + 5);
            bVar3 = *(byte *)(plVar9 + 6);
          }
          plVar7 = plVar9;
          if (((bVar3 & 1) != 0) && (*(char *)(plVar9[9] + 0xd58) != '\0')) {
            plVar7 = *(long **)(plVar9[0xb] + 0x70);
          }
          if (lVar6 == 0) {
            bVar4 = true;
          }
          if ((((!bVar4) && ((uVar2 & uVar1) != 0)) &&
              ((1 << (ulong)(*(uint *)(plVar7 + 7) & 0x1f) & param_5) != 0)) &&
             ((param_12 == (undefined *)0x0 ||
              (local_a8 = plVar9, uStack_a0 = param_7, uVar5 = (*(code *)param_12)(&local_a8),
              (uVar5 & 1) != 0)))) {
            if (param_13 == (undefined *)0x0) {
              FUN_71005c961c(plVar9,(long)param_2,param_6 & 1,param_7,param_8,param_9,param_10,
                             param_11);
            }
            else {
              local_6c = *(undefined1 *)((long)param_8 + 0x2c);
              local_98 = 0;
              local_6a = 0;
              uStack_a0 = *(undefined8 *)(param_1 + 0x68);
              local_70 = *(undefined4 *)(param_1 + 0x50);
              local_78 = param_11;
              local_a8 = param_2;
              plStack_90 = plVar9;
              local_88 = param_7;
              plStack_80 = param_8;
              local_6b = (byte)param_6 & 1;
              (*(code *)param_13)(&local_a8);
            }
          }
          plVar9 = plVar10;
        } while (plVar10 != (long *)0x0);
        lVar6 = *(long *)(param_4 + 0x40);
      }
      uVar8 = uVar8 + 1;
    } while (uVar8 < *(byte *)(lVar6 + 0xe5));
  }
  return;
}



void FUN_71005d2f98(long param_1,long *param_2,long *param_3,uint param_4,uint param_5,
                   undefined8 param_6,long *param_7,char *param_8,long param_9,int *param_10,
                   undefined *param_11,undefined *param_12)

{
  byte bVar1;
  bool bVar2;
  ulong uVar3;
  long *plVar4;
  long lVar5;
  long *local_a0;
  undefined8 uStack_98;
  undefined8 local_90;
  long *plStack_88;
  undefined8 local_80;
  long *plStack_78;
  int *local_70;
  undefined4 local_68;
  undefined1 local_64;
  byte local_63;
  undefined1 local_62;
  
  lVar5 = param_3[0xe1];
  if ((((((*(uint *)(param_3 + 6) ^ 0xffffffff) & 0x2004) != 0) ||
       (bVar2 = FUN_71005c93b8((long)param_3), bVar2)) || (*(float *)(param_3 + 0xf) <= 0.0)) ||
     (((int)param_3[0x12] < 1 &&
      (((int)param_3[0x12] != 0 || (2 < *(byte *)(param_3[8] + 0xe6) - 1)))))) {
    bVar2 = true;
    bVar1 = *(byte *)(param_3 + 6);
  }
  else {
    bVar2 = false;
    bVar1 = *(byte *)(param_3 + 6);
  }
  plVar4 = param_3;
  if (((bVar1 & 1) != 0) && (*(char *)(param_3[9] + 0xd58) != '\0')) {
    plVar4 = *(long **)(param_3[0xb] + 0x70);
  }
  if (lVar5 == 0) {
    bVar2 = true;
  }
  if ((((!bVar2) && ((*(uint *)(param_7 + 5) & *(uint *)((long)param_3 + 0x3c)) != 0)) &&
      ((1 << (ulong)(*(uint *)(plVar4 + 7) & 0x1f) & param_4) != 0)) &&
     ((param_11 == (undefined *)0x0 ||
      (local_a0 = param_3, uStack_98 = param_6, uVar3 = (*(code *)param_11)(&local_a0),
      (uVar3 & 1) != 0)))) {
    if (param_12 == (undefined *)0x0) {
      FUN_71005c961c(param_3,(long)param_2,param_5 & 1,param_6,param_7,param_8,param_9,param_10);
    }
    else {
      uStack_98 = *(undefined8 *)(param_1 + 0x68);
      local_63 = (byte)param_5 & 1;
      local_64 = *(undefined1 *)((long)param_7 + 0x2c);
      local_90 = 0;
      local_68 = *(undefined4 *)(param_1 + 0x50);
      local_62 = 0;
      local_70 = param_10;
      local_a0 = param_2;
      plStack_88 = param_3;
      local_80 = param_6;
      plStack_78 = param_7;
      (*(code *)param_12)(&local_a0);
    }
  }
  return;
}



void FUN_71005d3140(long param_1,long *param_2,uint param_3,uint param_4,undefined8 param_5,
                   long *param_6,char *param_7,long param_8,int *param_9,undefined *param_10,
                   undefined *param_11,undefined *param_12)

{
  ulong uVar1;
  long *plVar2;
  long *plVar3;
  long local_70;
  undefined8 uStack_68;
  
  if ((*(char *)(*(long *)(param_1 + 0x10) + 0x23) == '\0') && (*(char *)(param_1 + 0x65) == '?')) {
    return;
  }
  if (ABS(*(float *)(param_1 + 0x4c)) <= 1.1920929e-07) {
    return;
  }
  plVar2 = *(long **)(param_1 + 8);
  if (plVar2 == (long *)0x0) {
    if (param_12 == (undefined *)0x0) {
      return;
    }
  }
  else {
    Hint_Prefetch(plVar2,0,0,0);
    Hint_Prefetch(plVar2 + 8,0,0,0);
    Hint_Prefetch(plVar2 + 0x10,0,0,0);
    Hint_Prefetch(plVar2 + 0x18,0,0,0);
    if (param_12 == (undefined *)0x0) goto LAB_71005d31f8;
  }
  local_70 = param_1;
  uStack_68 = param_5;
  uVar1 = (*(code *)param_12)(&local_70);
  if (plVar2 == (long *)0x0) {
    return;
  }
  if ((uVar1 & 1) == 0) {
    return;
  }
LAB_71005d31f8:
  do {
    plVar3 = (long *)plVar2[1];
    if (plVar3 != (long *)0x0) {
      Hint_Prefetch(plVar3,0,0,0);
      Hint_Prefetch(plVar3 + 8,0,0,0);
      Hint_Prefetch(plVar3 + 0x10,0,0,0);
      Hint_Prefetch(plVar3 + 0x18,0,0,0);
    }
    if ((*(byte *)(plVar2 + 6) >> 4 & 1) != 0) {
      FUN_71005d2d30(param_1,param_2,1,(long)plVar2,param_3,param_4 & 1,param_5,param_6,param_7,
                     param_8,param_9,param_10,param_11);
    }
    FUN_71005d2f98(param_1,param_2,plVar2,param_3,param_4 & 1,param_5,param_6,param_7,param_8,
                   param_9,param_10,param_11);
    if ((*(byte *)(plVar2 + 6) >> 4 & 1) != 0) {
      FUN_71005d2d30(param_1,param_2,0,(long)plVar2,param_3,param_4 & 1,param_5,param_6,param_7,
                     param_8,param_9,param_10,param_11);
    }
    plVar2 = plVar3;
  } while (plVar3 != (long *)0x0);
  return;
}



void FUN_71005d3300(long param_1,long param_2)

{
  long lVar1;
  long lVar2;
  long lVar3;
  long lVar4;
  ulong uVar5;
  int iVar6;
  long lVar7;
  long lVar8;
  
  if ((*(byte *)(param_2 + 0x30) & 1) == 0) {
    lVar1 = *(long *)(param_2 + 0xf8);
    if ((lVar1 != 0) && (*(long *)(param_2 + 8) != 0)) {
      *(long *)(lVar1 + 8) = *(long *)(param_2 + 8);
      *(undefined8 *)(*(long *)(param_2 + 8) + 0xf8) = *(undefined8 *)(param_2 + 0xf8);
      return;
    }
    if (*(long *)(param_1 + 8) == param_2) {
      *(undefined8 *)(param_1 + 8) = *(undefined8 *)(param_2 + 8);
      if (*(long *)(param_2 + 8) != 0) {
        *(undefined8 *)(*(long *)(param_2 + 8) + 0xf8) = *(undefined8 *)(param_2 + 0xf8);
        return;
      }
      *(undefined8 *)(param_1 + 0x80) = 0;
      return;
    }
    if (*(long *)(param_1 + 0x80) == param_2) {
      *(long *)(param_1 + 0x80) = lVar1;
      if (*(long *)(param_2 + 0xf8) != 0) {
        *(undefined8 *)(*(long *)(param_2 + 0xf8) + 8) = *(undefined8 *)(param_2 + 8);
        return;
      }
      *(undefined8 *)(param_1 + 8) = 0;
      return;
    }
  }
  else {
    lVar3 = *(long *)(param_2 + 0x58);
    lVar1 = *(long *)(lVar3 + 0x70);
    lVar2 = (long)*(int *)(lVar3 + 0x84);
    lVar7 = *(long *)(*(long *)(lVar1 + 0x50) + 0x180);
    if (lVar7 != 0) {
      if (*(int *)(lVar3 + 0x7c) == -1) {
        iVar6 = *(int *)(lVar1 + 0x98);
        if (0 < iVar6) {
          lVar7 = 0;
          lVar3 = 0;
          do {
            lVar4 = *(long *)(*(long *)(lVar1 + 0x50) + 0x180);
            if ((lVar4 != 0) && (lVar8 = *(long *)(lVar1 + 0x40), *(char *)(lVar8 + 0xe5) != '\0'))
            {
              uVar5 = 0;
              lVar4 = lVar4 + lVar7;
              do {
                if (*(long *)(lVar4 + uVar5 * 8) == param_2) {
                  *(undefined8 *)(lVar4 + uVar5 * 8) = 0;
                  lVar8 = *(long *)(lVar1 + 0x40);
                }
                uVar5 = uVar5 + 1;
              } while (uVar5 < *(byte *)(lVar8 + 0xe5));
              iVar6 = *(int *)(lVar1 + 0x98);
            }
            lVar3 = lVar3 + 1;
            lVar7 = lVar7 + 0x158;
          } while (lVar3 < iVar6);
        }
      }
      else {
        lVar4 = *(long *)(lVar1 + 0x40);
        if (*(char *)(lVar4 + 0xe5) != '\0') {
          uVar5 = 0;
          lVar7 = lVar7 + (long)*(int *)(lVar3 + 0x7c) * 0x158;
          do {
            if (*(long *)(lVar7 + uVar5 * 8) == param_2) {
              *(undefined8 *)(lVar7 + uVar5 * 8) = 0;
              lVar4 = *(long *)(lVar1 + 0x40);
            }
            uVar5 = uVar5 + 1;
          } while (uVar5 < *(byte *)(lVar4 + 0xe5));
        }
      }
    }
    lVar3 = *(long *)(param_2 + 0xf8);
    if ((lVar3 != 0) && (*(long *)(param_2 + 8) != 0)) {
      *(long *)(lVar3 + 8) = *(long *)(param_2 + 8);
      *(undefined8 *)(*(long *)(param_2 + 8) + 0xf8) = *(undefined8 *)(param_2 + 0xf8);
      return;
    }
    lVar7 = *(long *)(lVar1 + 0x50) + lVar2 * 8;
    if (*(long *)(lVar7 + 0x80) == param_2) {
      *(long *)(lVar7 + 0x80) = *(long *)(param_2 + 8);
      if (*(long *)(param_2 + 8) != 0) {
        *(undefined8 *)(*(long *)(param_2 + 8) + 0xf8) = *(undefined8 *)(param_2 + 0xf8);
        return;
      }
      *(undefined8 *)(*(long *)(lVar1 + 0x50) + lVar2 * 8 + 0x100) = 0;
      return;
    }
    if (*(long *)(lVar7 + 0x100) == param_2) {
      *(long *)(lVar7 + 0x100) = lVar3;
      if (*(long *)(param_2 + 0xf8) != 0) {
        *(undefined8 *)(*(long *)(param_2 + 0xf8) + 8) = *(undefined8 *)(param_2 + 8);
        return;
      }
      *(undefined8 *)(*(long *)(lVar1 + 0x50) + lVar2 * 8 + 0x80) = 0;
      return;
    }
  }
  return;
}



void FUN_71005d351c(float param_1,long param_2)

{
  float fVar1;
  
  fVar1 = 1.0;
  if (param_1 <= 1.0) {
    fVar1 = param_1;
  }
  *(float *)(param_2 + 0x24c) = fVar1;
  return;
}



void FUN_71005d3530(float param_1,long param_2)

{
  float fVar1;
  
  fVar1 = 1.0;
  if (1.0 <= param_1) {
    fVar1 = param_1;
  }
  *(float *)(param_2 + 0x250) = fVar1;
  return;
}



void FUN_71005d3544(float param_1,long param_2)

{
  float fVar1;
  
  fVar1 = 1.0;
  if (param_1 <= 1.0) {
    fVar1 = param_1;
  }
  *(float *)(param_2 + 0x5c) = fVar1;
  return;
}



void FUN_71005d3558(long param_1,undefined8 *param_2)

{
  undefined1 auVar1 [16];
  undefined1 auVar2 [16];
  undefined1 auVar3 [16];
  undefined8 uVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  float fVar8;
  float fVar9;
  float fVar10;
  float fVar11;
  float fVar12;
  float fVar13;
  float fVar14;
  float fVar15;
  float fVar16;
  undefined1 auVar17 [16];
  undefined1 auVar18 [16];
  undefined1 auVar19 [16];
  
  uVar4 = param_2[7];
  *(undefined8 *)(param_1 + 0x128) = param_2[5];
  *(undefined8 *)(param_1 + 0x138) = uVar4;
  uVar4 = param_2[3];
  *(undefined8 *)(param_1 + 0x108) = param_2[1];
  *(undefined8 *)(param_1 + 0x118) = uVar4;
  uVar4 = *param_2;
  *(undefined8 *)(param_1 + 0x110) = param_2[2];
  *(undefined8 *)(param_1 + 0x100) = uVar4;
  uVar4 = param_2[4];
  *(undefined8 *)(param_1 + 0x130) = param_2[6];
  *(undefined8 *)(param_1 + 0x120) = uVar4;
  fVar15 = (float)param_2[5];
  fVar16 = (float)((ulong)param_2[5] >> 0x20);
  fVar13 = (float)param_2[4];
  fVar14 = (float)((ulong)param_2[4] >> 0x20);
  fVar7 = (float)param_2[1];
  fVar8 = (float)((ulong)param_2[1] >> 0x20);
  fVar5 = (float)*param_2;
  fVar6 = (float)((ulong)*param_2 >> 0x20);
  fVar11 = (float)param_2[3];
  fVar12 = (float)((ulong)param_2[3] >> 0x20);
  fVar9 = (float)param_2[2];
  fVar10 = (float)((ulong)param_2[2] >> 0x20);
  fVar9 = fVar9 * fVar9;
  fVar10 = fVar10 * fVar10;
  fVar11 = fVar11 * fVar11;
  fVar12 = fVar12 * fVar12;
  auVar19._4_4_ = fVar10;
  auVar19._0_4_ = fVar9;
  auVar19._8_4_ = fVar11;
  auVar19._12_4_ = fVar12;
  auVar1._4_4_ = fVar10;
  auVar1._0_4_ = fVar9;
  auVar1._8_4_ = fVar11;
  auVar1._12_4_ = fVar12;
  auVar19 = NEON_ext(auVar19,auVar1,8,1);
  fVar5 = fVar5 * fVar5;
  fVar6 = fVar6 * fVar6;
  fVar7 = fVar7 * fVar7;
  fVar8 = fVar8 * fVar8;
  auVar17._4_4_ = fVar6;
  auVar17._0_4_ = fVar5;
  auVar17._8_4_ = fVar7;
  auVar17._12_4_ = fVar8;
  auVar18._4_4_ = fVar6;
  auVar18._0_4_ = fVar5;
  auVar18._8_4_ = fVar7;
  auVar18._12_4_ = fVar8;
  auVar17 = NEON_ext(auVar17,auVar18,8,1);
  fVar13 = fVar13 * fVar13;
  fVar14 = fVar14 * fVar14;
  fVar15 = fVar15 * fVar15;
  fVar16 = fVar16 * fVar16;
  auVar2._4_4_ = fVar14;
  auVar2._0_4_ = fVar13;
  auVar2._8_4_ = fVar15;
  auVar2._12_4_ = fVar16;
  auVar3._4_4_ = fVar14;
  auVar3._0_4_ = fVar13;
  auVar3._8_4_ = fVar15;
  auVar3._12_4_ = fVar16;
  auVar18 = NEON_ext(auVar2,auVar3,8,1);
  fVar11 = 0.0;
  fVar12 = 0.0;
  fVar15 = 0.0;
  fVar8 = 0.0;
  fVar7 = SQRT(auVar18._0_4_ + fVar13 + auVar18._4_4_ + fVar14);
  *(ulong *)(param_1 + 0x1a0) =
       CONCAT44(SQRT(auVar19._0_4_ + fVar9 + auVar19._4_4_ + fVar10),
                SQRT(auVar17._0_4_ + fVar5 + auVar17._4_4_ + fVar6));
  uVar4 = *(undefined8 *)(param_1 + 0x1a0);
  fVar5 = (float)uVar4;
  fVar6 = (float)((ulong)uVar4 >> 0x20);
  *(ulong *)(param_1 + 0x1a8) = (ulong)(uint)fVar7;
  *(undefined8 *)(param_1 + 0x1a0) = uVar4;
  if (0.0 < fVar5) {
    fVar9 = 1.0 / fVar5;
    uVar4 = *param_2;
    *(ulong *)(param_1 + 0x148) =
         CONCAT44((float)((ulong)param_2[1] >> 0x20) * fVar9,(float)param_2[1] * fVar9);
    *(ulong *)(param_1 + 0x140) =
         CONCAT44((float)((ulong)uVar4 >> 0x20) * fVar9,(float)uVar4 * fVar9);
  }
  else {
    *(undefined8 *)(param_1 + 0x148) = 0;
    *(undefined8 *)(param_1 + 0x140) = 0;
  }
  if (0.0 < fVar6) {
    fVar9 = 1.0 / fVar6;
    uVar4 = param_2[2];
    *(ulong *)(param_1 + 0x158) =
         CONCAT44((float)((ulong)param_2[3] >> 0x20) * fVar9,(float)param_2[3] * fVar9);
    *(ulong *)(param_1 + 0x150) =
         CONCAT44((float)((ulong)uVar4 >> 0x20) * fVar9,(float)uVar4 * fVar9);
  }
  else {
    *(undefined8 *)(param_1 + 0x158) = 0;
    *(undefined8 *)(param_1 + 0x150) = 0;
  }
  if (0.0 < fVar7) {
    fVar8 = 1.0 / fVar7;
    fVar11 = (float)param_2[4] * fVar8;
    fVar12 = (float)((ulong)param_2[4] >> 0x20) * fVar8;
    fVar15 = (float)param_2[5] * fVar8;
    fVar8 = (float)((ulong)param_2[5] >> 0x20) * fVar8;
  }
  *(ulong *)(param_1 + 0x168) = CONCAT44(fVar8,fVar15);
  *(ulong *)(param_1 + 0x160) = CONCAT44(fVar12,fVar11);
  uVar4 = param_2[6];
  *(undefined8 *)(param_1 + 0x178) = param_2[7];
  *(undefined8 *)(param_1 + 0x170) = uVar4;
  *(ulong *)(param_1 + 0x1e8) =
       CONCAT44((float)((ulong)*(undefined8 *)(param_1 + 0x1c8) >> 0x20) * 0.0,
                fVar7 * (float)*(undefined8 *)(param_1 + 0x1c8));
  *(ulong *)(param_1 + 0x1e0) =
       CONCAT44(fVar6 * (float)((ulong)*(undefined8 *)(param_1 + 0x1c0) >> 0x20),
                fVar5 * (float)*(undefined8 *)(param_1 + 0x1c0));
  return;
}



void FUN_71005d3698(long param_1,undefined8 *param_2)

{
  undefined8 uVar1;
  
  uVar1 = *param_2;
  *(undefined8 *)(param_1 + 0x138) = param_2[1];
  *(undefined8 *)(param_1 + 0x130) = uVar1;
  uVar1 = *param_2;
  *(undefined8 *)(param_1 + 0x178) = param_2[1];
  *(undefined8 *)(param_1 + 0x170) = uVar1;
  return;
}



undefined1 FUN_71005d36ac(long param_1)

{
  return *(undefined1 *)(*(long *)(param_1 + 0x10) + 0x26);
}



void FUN_71005d36c0(long param_1,undefined8 *param_2,undefined8 *param_3,undefined8 param_4)

{
  float *pfVar1;
  undefined8 uVar2;
  undefined8 uVar3;
  undefined8 uVar4;
  bool bVar5;
  ulong uVar6;
  int iVar7;
  undefined8 *puVar8;
  long lVar9;
  float fVar10;
  
  if ((*(char *)(param_1 + 0x38) < '\0') &&
     (iVar7 = *(int *)(param_1 + 0x248), iVar7 < *(int *)(param_1 + 0x244))) {
    lVar9 = *(long *)(param_1 + 8);
    if (lVar9 != 0) {
      bVar5 = false;
      do {
        fVar10 = *(float *)(param_1 + 0x24c);
        uVar6 = FUN_71005c95e0(lVar9);
        if ((*(byte *)(lVar9 + 0x31) >> 6 & 1) != 0) {
          pfVar1 = (float *)(*(long *)(lVar9 + 0x48) + 0xd78);
          if ((uVar6 & 1) == 0) {
            pfVar1 = (float *)(lVar9 + 0x414);
          }
          bVar5 = (bool)(*(int *)(lVar9 + 0xf4) <
                         *(int *)(lVar9 + 0xa0) + (int)(*(float *)(lVar9 + 0xdc) * fVar10 * *pfVar1)
                        | bVar5);
        }
        lVar9 = *(long *)(lVar9 + 8);
      } while (lVar9 != 0);
      if (bVar5) {
        return;
      }
      iVar7 = *(int *)(param_1 + 0x248);
    }
    puVar8 = (undefined8 *)(*(long *)(param_1 + 0xa0) + (long)iVar7 * 0x60);
    uVar2 = *param_2;
    uVar3 = param_2[1];
    uVar4 = param_2[3];
    puVar8[2] = param_2[2];
    puVar8[3] = uVar4;
    *puVar8 = uVar2;
    puVar8[1] = uVar3;
    uVar2 = param_2[4];
    uVar3 = param_2[5];
    uVar4 = param_2[7];
    puVar8[6] = param_2[6];
    puVar8[7] = uVar4;
    puVar8[4] = uVar2;
    puVar8[5] = uVar3;
    *(undefined8 *)(*(long *)(param_1 + 0xa0) + (long)iVar7 * 0x60 + 0x50) = param_4;
    *(undefined1 *)(*(long *)(param_1 + 0xa0) + (long)iVar7 * 0x60 + 0x5c) = 1;
    *(undefined4 *)(*(long *)(param_1 + 0xa0) + (long)iVar7 * 0x60 + 0x58) =
         *(undefined4 *)(param_1 + 0x24c);
    lVar9 = *(long *)(param_1 + 0xa0) + (long)iVar7 * 0x60;
    uVar2 = param_3[1];
    *(undefined8 *)(lVar9 + 0x40) = *param_3;
    *(undefined8 *)(lVar9 + 0x48) = uVar2;
    *(int *)(param_1 + 0x248) = *(int *)(param_1 + 0x248) + 1;
  }
  return;
}



void FUN_71005d3810(long param_1,undefined8 *param_2)

{
  long lVar1;
  
  for (lVar1 = *(long *)(param_1 + 8); lVar1 != 0; lVar1 = *(long *)(lVar1 + 8)) {
    *(undefined8 *)(lVar1 + 0xb8) = param_2[1];
    *(undefined8 *)(lVar1 + 0xb0) = *param_2;
  }
  return;
}



void FUN_71005d3840(long param_1,undefined8 *param_2)

{
  long lVar1;
  
  for (lVar1 = *(long *)(param_1 + 8); lVar1 != 0; lVar1 = *(long *)(lVar1 + 8)) {
    *(undefined8 *)(lVar1 + 200) = param_2[1];
    *(undefined8 *)(lVar1 + 0xc0) = *param_2;
  }
  return;
}



void FUN_71005d3870(long param_1,undefined8 param_2)

{
  long lVar1;
  
  for (lVar1 = *(long *)(param_1 + 8); lVar1 != 0; lVar1 = *(long *)(lVar1 + 8)) {
    *(undefined8 *)(lVar1 + 0x380) = param_2;
  }
  return;
}



long FUN_71005d3890(long *param_1)

{
  long lVar1;
  
  lVar1 = *param_1;
  if (lVar1 != 0) {
    if ((int)param_1[1] != *(int *)(lVar1 + 0x234)) {
      lVar1 = 0;
    }
    return lVar1;
  }
  return 0;
}



void FUN_71005d38bc(long *param_1,long param_2)

{
  uint uVar1;
  char cVar2;
  bool bVar3;
  byte bVar4;
  int iVar5;
  ulong uVar6;
  long lVar7;
  
  Hint_Prefetch(param_2 + 0x4d0,0,0,0);
  Hint_Prefetch(param_2 + 0x510,0,0,0);
  Hint_Prefetch(param_2 + 0x550,0,0,0);
  Hint_Prefetch(param_2 + 0x590,0,0,0);
  Hint_Prefetch(param_2 + 0x5d0,0,0,0);
  Hint_Prefetch(param_2 + 0x5e0,0,0,0);
  Hint_Prefetch(param_2 + 0x5f0,0,0,0);
  Hint_Prefetch(param_2 + 0x600,0,0,0);
  Hint_Prefetch(param_2 + 0x610,0,0,0);
  Hint_Prefetch(param_2 + 0x620,0,0,0);
  uVar1 = *(uint *)(param_2 + 0x30);
  if ((uVar1 >> 0xe & 1) == 0) {
    if ((uVar1 >> 0xf & 1) == 0) {
      if ((uVar1 >> 0x10 & 1) != 0) {
        bVar3 = FUN_71005c93b8(param_2);
        if ((!bVar3) && ((*(byte *)(param_2 + 0x31) >> 3 & 1) == 0)) {
          *(int *)((long)param_1 + 0x1c) = *(int *)((long)param_1 + 0x1c) + *(int *)(param_2 + 0x90)
          ;
        }
        *(short *)(param_1 + 5) = (short)param_1[5] + 1;
      }
    }
    else {
      bVar3 = FUN_71005c93b8(param_2);
      if ((!bVar3) && ((*(byte *)(param_2 + 0x31) >> 3 & 1) == 0)) {
        *(int *)(param_1 + 3) = (int)param_1[3] + *(int *)(param_2 + 0x90);
      }
      *(short *)((long)param_1 + 0x26) = *(short *)((long)param_1 + 0x26) + 1;
    }
  }
  else {
    bVar3 = FUN_71005c93b8(param_2);
    if ((!bVar3) && ((*(byte *)(param_2 + 0x31) >> 3 & 1) == 0)) {
      *(int *)((long)param_1 + 0x14) = *(int *)((long)param_1 + 0x14) + *(int *)(param_2 + 0xa0);
    }
    *(short *)((long)param_1 + 0x24) = *(short *)((long)param_1 + 0x24) + 1;
  }
  *(short *)(param_1 + 4) = (short)param_1[4] + 1;
  cVar2 = *(char *)(*(long *)(param_2 + 0x40) + 0xe6);
  if (cVar2 == '\x03') {
    iVar5 = FUN_71005ef1e0(param_2);
    *(short *)((long)param_1 + 0x2e) = *(short *)((long)param_1 + 0x2e) + (short)iVar5;
  }
  else if (cVar2 == '\x02') {
    iVar5 = FUN_71005ebbb0(param_2);
    *(short *)((long)param_1 + 0x2c) = *(short *)((long)param_1 + 0x2c) + (short)iVar5;
  }
  else if (cVar2 == '\x01') {
    *(short *)(param_1 + 6) = (short)param_1[6] + 1;
  }
  *(uint *)(param_1 + 2) = (int)param_1[2] + (uint)*(byte *)(param_2 + 0x81);
  *param_1 = *param_1 + *(long *)(param_2 + 0x6f8);
  uVar6 = FUN_71005c959c(param_2);
  param_1[1] = param_1[1] + uVar6;
  bVar3 = FUN_71005cf5e4((long *)(param_2 + 0x668));
  lVar7 = *(long *)(param_2 + 0x670);
  if (!bVar3) {
    lVar7 = 0;
  }
  param_1[1] = param_1[1] + lVar7;
  bVar4 = FUN_71005cf3e4((undefined1 *)(param_2 + 0x4d0));
  if ((bVar4 & 1) == 0) {
    bVar4 = FUN_71005cf3e4((undefined1 *)(param_2 + 0x510));
  }
  else {
    bVar3 = FUN_71005cf5e4((long *)(param_2 + 0x4d8));
    lVar7 = *(long *)(param_2 + 0x4e0);
    if (!bVar3) {
      lVar7 = 0;
    }
    param_1[1] = param_1[1] + lVar7;
    bVar4 = FUN_71005cf3e4((undefined1 *)(param_2 + 0x510));
  }
  if ((bVar4 & 1) == 0) {
    bVar4 = FUN_71005cf3e4((undefined1 *)(param_2 + 0x550));
  }
  else {
    bVar3 = FUN_71005cf5e4((long *)(param_2 + 0x518));
    lVar7 = *(long *)(param_2 + 0x520);
    if (!bVar3) {
      lVar7 = 0;
    }
    param_1[1] = param_1[1] + lVar7;
    bVar4 = FUN_71005cf3e4((undefined1 *)(param_2 + 0x550));
  }
  if ((bVar4 & 1) == 0) {
    bVar4 = FUN_71005cf3e4((undefined1 *)(param_2 + 0x590));
  }
  else {
    bVar3 = FUN_71005cf5e4((long *)(param_2 + 0x558));
    lVar7 = *(long *)(param_2 + 0x560);
    if (!bVar3) {
      lVar7 = 0;
    }
    param_1[1] = param_1[1] + lVar7;
    bVar4 = FUN_71005cf3e4((undefined1 *)(param_2 + 0x590));
  }
  if ((bVar4 & 1) == 0) {
    lVar7 = param_1[1];
  }
  else {
    bVar3 = FUN_71005cf5e4((long *)(param_2 + 0x598));
    lVar7 = *(long *)(param_2 + 0x5a0);
    if (!bVar3) {
      lVar7 = 0;
    }
    lVar7 = param_1[1] + lVar7;
    param_1[1] = lVar7;
  }
  lVar7 = lVar7 + (ulong)*(uint *)(param_2 + 0x5dc);
  param_1[1] = lVar7;
  lVar7 = lVar7 + (ulong)*(uint *)(param_2 + 0x5ec);
  param_1[1] = lVar7;
  lVar7 = lVar7 + (ulong)*(uint *)(param_2 + 0x5fc);
  param_1[1] = lVar7;
  lVar7 = lVar7 + (ulong)*(uint *)(param_2 + 0x60c);
  param_1[1] = lVar7;
  lVar7 = lVar7 + (ulong)*(uint *)(param_2 + 0x61c);
  param_1[1] = lVar7;
  param_1[1] = lVar7 + (ulong)*(uint *)(param_2 + 0x62c);
  return;
}



void FUN_71005d3bb0(undefined8 *param_1)

{
  FUN_7100603b04(param_1 + 0x1f);
  FUN_7100603b04(param_1 + 0x23);
  FUN_7100603b04(param_1 + 0x27);
  FUN_7100603b04(param_1 + 0x2b);
  FUN_7100603b04(param_1 + 0x2f);
  FUN_7100603b04(param_1 + 0x33);
  FUN_7100603b04(param_1 + 0x37);
  FUN_7100603b04(param_1 + 0x3b);
  FUN_7100603678(param_1 + 0x59);
  FUN_71006038b8(param_1 + 0x5e);
  FUN_71006034a4((undefined8 *)((long)param_1 + 0x30c));
  *(undefined2 *)((long)param_1 + 0xed) = 0;
  *(undefined1 *)((long)param_1 + 0xe9) = 1;
  *(undefined2 *)((long)param_1 + 0xe7) = 0;
  *(undefined1 *)((long)param_1 + 0xef) = 0;
  *(undefined2 *)((long)param_1 + 0xea) = 0;
  *(undefined1 *)((long)param_1 + 0xe5) = 0;
  param_1[0x68] = 0;
  param_1[0x69] = 0;
  param_1[0x6a] = 0;
  param_1[0x6b] = 0;
  param_1[0x6c] = 0;
  param_1[0x6d] = 0;
  param_1[0x6e] = 0;
  param_1[0x6f] = 0;
  param_1[0x70] = 0;
  param_1[0x71] = 0;
  param_1[0x72] = 0;
  param_1[0x73] = 0;
  param_1[0x74] = 0;
  param_1[0x75] = 0;
  param_1[0x76] = 0;
  param_1[0x77] = 0;
  param_1[0x78] = 0;
  param_1[0x79] = 0;
  param_1[0x7a] = 0;
  param_1[0x9f] = 0;
  param_1[0x9e] = 0;
  param_1[0xa0] = 0;
  *(undefined1 *)((long)param_1 + 0xe6) = 0;
  param_1[0x3f] = 0;
  param_1[0xc] = 0;
  param_1[0x98] = 0;
  param_1[0x97] = 0;
  param_1[0x96] = 0;
  param_1[0x95] = 0;
  param_1[0x94] = 0;
  param_1[0x93] = 0;
  param_1[0x92] = 0;
  param_1[0x91] = 0;
  param_1[0x90] = 0;
  param_1[0x8f] = 0;
  param_1[0x8e] = 0;
  param_1[0x8d] = 0;
  param_1[0x8c] = 0;
  param_1[0x8b] = 0;
  param_1[0x8a] = 0;
  param_1[0x89] = 0;
  param_1[0x88] = 0;
  param_1[0x87] = 0;
  param_1[0x86] = 0;
  param_1[0x85] = 0;
  param_1[0x84] = 0;
  param_1[0x83] = 0;
  param_1[0x82] = 0;
  param_1[0x81] = 0;
  param_1[0x80] = 0;
  param_1[0x7f] = 0;
  param_1[0x7e] = 0;
  param_1[0x7d] = 0;
  param_1[0x7c] = 0;
  param_1[0x7b] = 0;
  *(undefined4 *)(param_1 + 0x1e) = 0;
  param_1[0x16] = 0;
  param_1[0x17] = 0;
  param_1[0x18] = 0;
  param_1[0x19] = 0;
  *param_1 = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  param_1[3] = 0;
  param_1[4] = 0;
  param_1[5] = 0;
  param_1[6] = 0;
  param_1[7] = 0;
  param_1[8] = 0;
  param_1[9] = 0;
  param_1[10] = 0;
  param_1[0xb] = 0;
  param_1[0xe] = 0;
  param_1[0xf] = 0;
  param_1[0x10] = 0;
  param_1[0x11] = 0;
  param_1[0x12] = 0;
  param_1[0x13] = 0;
  param_1[0x14] = 0;
  param_1[0x15] = 0;
  param_1[0x1a] = 0;
  param_1[0x1b] = 0xffffffffffffffff;
  *(undefined8 *)((long)param_1 + 0xdd) = 0xffffffffffffffff;
  param_1[0x41] = 0;
  param_1[0x40] = 0x3f800000;
  param_1[0x43] = 0;
  param_1[0x42] = 0x3f80000000000000;
  param_1[0x45] = 0x3f800000;
  param_1[0x44] = 0;
  param_1[0x47] = 0;
  param_1[0x46] = 0;
  param_1[0x49] = 0;
  param_1[0x48] = 0x3f800000;
  param_1[0x4b] = 0;
  param_1[0x4a] = 0x3f80000000000000;
  param_1[0x4d] = 0x3f800000;
  param_1[0x4c] = 0;
  param_1[0x4f] = 0;
  param_1[0x4e] = 0;
  return;
}



void FUN_71005d3d88(long *param_1,undefined8 param_2)

{
  FUN_71005e4774((long)(param_1 + 0x52),param_2,*param_1 + 0xe08);
  return;
}



void FUN_71005d3d9c(long param_1)

{
  FUN_71005e4960(param_1 + 0x290);
  return;
}



undefined8 FUN_71005d3da4(long param_1,long param_2)

{
  ulong uVar1;
  long lVar2;
  
  *(long *)(param_1 + 0x70) = param_2;
  *(int *)(param_1 + 0x4f0) = (int)*(undefined8 *)(param_2 + 0x198);
  uVar1 = (*(long *)(param_2 + 0x168) + 0xcbfU & -*(long *)(param_2 + 0x168)) +
          *(long *)(param_2 + 0x198);
  if (uVar1 <= *(ulong *)(param_2 + 0x170)) {
    *(ulong *)(param_2 + 0x198) = uVar1;
  }
  if (*(long *)(param_1 + 0x1f8) != 0) {
    lVar2 = *(long *)(param_1 + 0x70);
    *(int *)(param_1 + 0x4f4) = (int)*(undefined8 *)(lVar2 + 0x198);
    uVar1 = (*(long *)(lVar2 + 0x168) + 0x7fU & -*(long *)(lVar2 + 0x168)) +
            *(long *)(lVar2 + 0x198);
    if (uVar1 <= *(ulong *)(lVar2 + 0x170)) {
      *(ulong *)(lVar2 + 0x198) = uVar1;
    }
  }
  if (*(long *)(param_1 + 0x498) != 0) {
    lVar2 = *(long *)(param_1 + 0x70);
    *(int *)(param_1 + 0x4f8) = (int)*(undefined8 *)(lVar2 + 0x198);
    uVar1 = (((ulong)*(uint *)(param_1 + 0x500) + *(long *)(lVar2 + 0x168)) - 1 &
            -*(long *)(lVar2 + 0x168)) + *(long *)(lVar2 + 0x198);
    if (uVar1 <= *(ulong *)(lVar2 + 0x170)) {
      *(ulong *)(lVar2 + 0x198) = uVar1;
    }
  }
  if (*(char *)(param_1 + 0xee) != '\0') {
    lVar2 = *(long *)(param_1 + 0x70);
    *(int *)(param_1 + 0x4fc) = (int)*(undefined8 *)(lVar2 + 0x198);
    uVar1 = (*(long *)(lVar2 + 0x168) + 0x15fU & -*(long *)(lVar2 + 0x168)) +
            *(long *)(lVar2 + 0x198);
    if (uVar1 <= *(ulong *)(lVar2 + 0x170)) {
      *(ulong *)(lVar2 + 0x198) = uVar1;
    }
  }
  return 1;
}



undefined8
FUN_71005d3e90(long param_1,short *param_2,undefined1 *param_3,undefined8 *param_4,byte param_5)

{
  byte bVar1;
  long *plVar2;
  long lVar3;
  bool bVar4;
  undefined2 uVar5;
  uint uVar6;
  undefined4 uVar7;
  uint uVar8;
  long *plVar9;
  undefined8 uVar10;
  long lVar11;
  ushort uVar12;
  short sVar13;
  undefined8 *puVar14;
  long lVar15;
  ulong uVar16;
  byte bVar17;
  undefined1 *puVar18;
  short sVar19;
  byte local_88;
  uint local_6c;
  
  plVar2 = DAT_7103a6fa40;
  if ((7 < param_5) ||
     (plVar9 = *(long **)(param_1 + (ulong)param_5 * 8 + 0x10), plVar9 == (long *)0x0)) {
    return 0;
  }
  lVar15 = *plVar9;
  if (*(long *)(param_1 + 8) == 0) {
    local_6c = 0;
    local_88 = 0;
    bVar17 = local_88;
    if (2 < *(byte *)(param_1 + 0xe6) - 1) goto LAB_71005d3fa0;
LAB_71005d4330:
    uVar6 = 0;
    uVar8 = 0;
    local_88 = bVar17;
    if (local_6c != 0) goto LAB_71005d4344;
LAB_71005d4050:
    plVar2 = DAT_7103a6fa50;
    sVar19 = (short)uVar6;
    uVar8 = FUN_7100602fd0(lVar15,0,0,*DAT_7103a6fa50);
    puVar18 = param_3 + (long)(int)(char)bVar17 * 0x28;
    FUN_71005fbecc(puVar18);
    bVar4 = uVar8 != 0xffffffff;
    if (bVar4) {
      *(short *)(puVar18 + 2) = (short)uVar8;
      bVar17 = bVar17 + 1;
      lVar11 = *plVar2;
      *(undefined2 *)(puVar18 + 4) = 0;
      *(undefined8 *)(puVar18 + 8) = 0x190500000000;
      *(long *)(puVar18 + 0x10) = lVar11;
    }
    uVar12 = (ushort)bVar4;
    uVar8 = FUN_7100602fd0(lVar15,0,0,plVar2[1]);
    puVar18 = param_3 + (long)(int)(char)bVar17 * 0x28;
    FUN_71005fbecc(puVar18);
    if (uVar8 != 0xffffffff) {
      *(short *)(puVar18 + 2) = (short)uVar8;
      bVar17 = bVar17 + 1;
      lVar11 = plVar2[1];
      uVar12 = bVar4 + 1;
      *(undefined2 *)(puVar18 + 4) = 0;
      *(undefined8 *)(puVar18 + 8) = 0x190500000010;
      *(long *)(puVar18 + 0x10) = lVar11;
    }
    uVar8 = FUN_7100602fd0(lVar15,0,0,plVar2[2]);
    puVar18 = param_3 + (long)(int)(char)bVar17 * 0x28;
    FUN_71005fbecc(puVar18);
    if (uVar8 != 0xffffffff) {
      *(short *)(puVar18 + 2) = (short)uVar8;
      bVar17 = bVar17 + 1;
      lVar11 = plVar2[2];
      uVar12 = uVar12 + 1;
      *(undefined2 *)(puVar18 + 4) = 0;
      *(undefined8 *)(puVar18 + 8) = 0x190500000020;
      *(long *)(puVar18 + 0x10) = lVar11;
    }
    uVar8 = FUN_7100602fd0(lVar15,0,0,plVar2[3]);
    puVar18 = param_3 + (long)(int)(char)bVar17 * 0x28;
    FUN_71005fbecc(puVar18);
    if (uVar8 != 0xffffffff) {
      *(short *)(puVar18 + 2) = (short)uVar8;
      bVar17 = bVar17 + 1;
      lVar11 = plVar2[3];
      uVar12 = uVar12 + 1;
      *(undefined2 *)(puVar18 + 4) = 0;
      *(undefined8 *)(puVar18 + 8) = 0x190500000030;
      *(long *)(puVar18 + 0x10) = lVar11;
    }
    uVar8 = FUN_7100602fd0(lVar15,0,0,plVar2[4]);
    puVar18 = param_3 + (long)(int)(char)bVar17 * 0x28;
    FUN_71005fbecc(puVar18);
    if (uVar8 != 0xffffffff) {
      *(short *)(puVar18 + 2) = (short)uVar8;
      bVar17 = bVar17 + 1;
      lVar11 = plVar2[4];
      uVar12 = uVar12 + 1;
      *(undefined2 *)(puVar18 + 4) = 0;
      *(undefined8 *)(puVar18 + 8) = 0x190500000040;
      *(long *)(puVar18 + 0x10) = lVar11;
    }
    uVar8 = FUN_7100602fd0(lVar15,0,0,plVar2[5]);
    puVar18 = param_3 + (long)(int)(char)bVar17 * 0x28;
    FUN_71005fbecc(puVar18);
    if (uVar8 != 0xffffffff) {
      *(short *)(puVar18 + 2) = (short)uVar8;
      uVar12 = uVar12 + 1;
      lVar15 = plVar2[5];
      *(undefined2 *)(puVar18 + 4) = 0;
      *(undefined8 *)(puVar18 + 8) = 0x190500000050;
      *(long *)(puVar18 + 0x10) = lVar15;
      *(undefined1 *)(param_1 + 0xe3) = 0;
      FUN_71005fbee0(param_4);
LAB_71005d45b8:
      sVar13 = 1;
      *(undefined4 *)param_4 = 0x60;
      goto LAB_71005d45cc;
    }
    *(undefined1 *)(param_1 + 0xe3) = 0;
    FUN_71005fbee0(param_4);
    uVar8 = uVar6;
    if (uVar12 != 0) goto LAB_71005d45b8;
  }
  else {
    uVar6 = FUN_7100602fd0(lVar15,0,0,*DAT_7103a6fa40);
    if (uVar6 != 0xffffffff) {
      FUN_71005fbecc(param_3);
      *(short *)(param_3 + 2) = (short)uVar6;
      *(long *)(param_3 + 0x10) = *plVar2;
      uVar5 = (**(code **)(**(long **)(param_1 + 8) + 0x38))(*(long **)(param_1 + 8),0);
      *(undefined2 *)(param_3 + 4) = uVar5;
      uVar7 = (**(code **)(**(long **)(param_1 + 8) + 0x40))(*(long **)(param_1 + 8),0);
      *(undefined4 *)(param_3 + 0xc) = uVar7;
      uVar7 = (**(code **)(**(long **)(param_1 + 8) + 0x50))(*(long **)(param_1 + 8),0);
      *(undefined4 *)(param_3 + 8) = uVar7;
    }
    local_6c = (uint)(uVar6 != 0xffffffff);
    uVar6 = FUN_7100602fd0(lVar15,0,0,plVar2[1]);
    if (uVar6 != 0xffffffff) {
      puVar18 = param_3 + (ulong)local_6c * 0x28;
      FUN_71005fbecc(puVar18);
      *(short *)(puVar18 + 2) = (short)uVar6;
      *(long *)(puVar18 + 0x10) = plVar2[1];
      uVar5 = (**(code **)(**(long **)(param_1 + 8) + 0x38))(*(long **)(param_1 + 8),1);
      *(undefined2 *)(puVar18 + 4) = uVar5;
      uVar7 = (**(code **)(**(long **)(param_1 + 8) + 0x40))(*(long **)(param_1 + 8),1);
      *(undefined4 *)(puVar18 + 0xc) = uVar7;
      uVar7 = (**(code **)(**(long **)(param_1 + 8) + 0x50))(*(long **)(param_1 + 8),1);
      local_6c = local_6c + 1;
      *(undefined4 *)(puVar18 + 8) = uVar7;
    }
    uVar6 = FUN_7100602fd0(lVar15,0,0,plVar2[2]);
    if (uVar6 != 0xffffffff) {
      puVar18 = param_3 + (ulong)local_6c * 0x28;
      FUN_71005fbecc(puVar18);
      *(short *)(puVar18 + 2) = (short)uVar6;
      *(long *)(puVar18 + 0x10) = plVar2[2];
      uVar5 = (**(code **)(**(long **)(param_1 + 8) + 0x38))(*(long **)(param_1 + 8),2);
      *(undefined2 *)(puVar18 + 4) = uVar5;
      uVar7 = (**(code **)(**(long **)(param_1 + 8) + 0x40))(*(long **)(param_1 + 8),2);
      *(undefined4 *)(puVar18 + 0xc) = uVar7;
      uVar7 = (**(code **)(**(long **)(param_1 + 8) + 0x50))(*(long **)(param_1 + 8),2);
      local_6c = local_6c + 1;
      *(undefined4 *)(puVar18 + 8) = uVar7;
    }
    uVar6 = FUN_7100602fd0(lVar15,0,0,plVar2[3]);
    if (uVar6 != 0xffffffff) {
      puVar18 = param_3 + (ulong)local_6c * 0x28;
      FUN_71005fbecc(puVar18);
      *(short *)(puVar18 + 2) = (short)uVar6;
      *(long *)(puVar18 + 0x10) = plVar2[3];
      uVar5 = (**(code **)(**(long **)(param_1 + 8) + 0x38))(*(long **)(param_1 + 8),3);
      *(undefined2 *)(puVar18 + 4) = uVar5;
      uVar7 = (**(code **)(**(long **)(param_1 + 8) + 0x40))(*(long **)(param_1 + 8),3);
      *(undefined4 *)(puVar18 + 0xc) = uVar7;
      uVar7 = (**(code **)(**(long **)(param_1 + 8) + 0x50))(*(long **)(param_1 + 8),3);
      local_6c = local_6c + 1;
      *(undefined4 *)(puVar18 + 8) = uVar7;
    }
    uVar6 = FUN_7100602fd0(lVar15,0,0,plVar2[4]);
    if (uVar6 != 0xffffffff) {
      puVar18 = param_3 + (ulong)local_6c * 0x28;
      FUN_71005fbecc(puVar18);
      *(short *)(puVar18 + 2) = (short)uVar6;
      *(long *)(puVar18 + 0x10) = plVar2[4];
      uVar5 = (**(code **)(**(long **)(param_1 + 8) + 0x38))(*(long **)(param_1 + 8),4);
      *(undefined2 *)(puVar18 + 4) = uVar5;
      uVar7 = (**(code **)(**(long **)(param_1 + 8) + 0x40))(*(long **)(param_1 + 8),4);
      *(undefined4 *)(puVar18 + 0xc) = uVar7;
      uVar7 = (**(code **)(**(long **)(param_1 + 8) + 0x50))(*(long **)(param_1 + 8),4);
      local_6c = local_6c + 1;
      *(undefined4 *)(puVar18 + 8) = uVar7;
    }
    local_88 = (**(code **)(**(long **)(param_1 + 8) + 0x30))();
    bVar17 = local_88;
    if (*(byte *)(param_1 + 0xe6) - 1 < 3) goto LAB_71005d4330;
LAB_71005d3fa0:
    lVar3 = DAT_7103a6fa48;
    lVar11 = 0;
    uVar6 = 0;
    bVar17 = local_88;
    do {
      while (uVar8 = FUN_7100602fd0(lVar15,0,0,*(long *)(lVar3 + lVar11 * 8)), uVar8 == 0xffffffff)
      {
        *(undefined1 *)(param_1 + 0xd8 + lVar11) = 0xff;
        lVar11 = lVar11 + 1;
        if (lVar11 == 0xd) goto LAB_71005d4044;
      }
      puVar18 = param_3 + (long)(int)(uVar6 + local_6c) * 0x28;
      FUN_71005fbecc(puVar18);
      *(short *)(puVar18 + 2) = (short)uVar8;
      uVar6 = uVar6 + 1;
      uVar10 = *(undefined8 *)(lVar3 + lVar11 * 8);
      *(short *)(puVar18 + 4) = (short)(char)bVar17;
      bVar1 = bVar17 + 1;
      *(undefined8 *)(puVar18 + 8) = 0x190500000000;
      *(undefined8 *)(puVar18 + 0x10) = uVar10;
      *(byte *)(param_1 + 0xd8 + lVar11) = bVar17;
      lVar11 = lVar11 + 1;
      bVar17 = bVar1;
    } while (lVar11 != 0xd);
LAB_71005d4044:
    uVar8 = uVar6;
    if (local_6c == 0 && uVar6 == 0) goto LAB_71005d4050;
LAB_71005d4344:
    FUN_71005fbee0(param_4);
    if (('\0' < (char)local_88) && (local_6c != 0)) {
      uVar16 = 0;
      puVar14 = param_4;
      do {
        uVar7 = (**(code **)(**(long **)(param_1 + 8) + 0x10))
                          (*(long **)(param_1 + 8),uVar16 & 0xffffffff);
        uVar16 = uVar16 + 1;
        *(undefined4 *)puVar14 = uVar7;
        puVar14 = puVar14 + 2;
      } while (local_88 != uVar16);
    }
    if (0 < (int)uVar8) {
      uVar16 = (ulong)uVar8;
      puVar14 = param_4 + (long)(char)local_88 * 2;
      do {
        FUN_71005fbee0(puVar14);
        uVar16 = uVar16 - 1;
        *puVar14 = 0x100000010;
        puVar14 = puVar14 + 2;
      } while (uVar16 != 0);
    }
  }
  uVar12 = 0;
  sVar19 = (short)uVar8;
  sVar13 = 0;
LAB_71005d45cc:
  FUN_71005fbee8((undefined4 *)param_2);
  *(undefined1 **)(param_2 + 4) = param_3;
  *(undefined8 **)(param_2 + 8) = param_4;
  *param_2 = sVar19 + (short)local_6c + uVar12;
  param_2[1] = sVar19 + (char)local_88 + sVar13;
  return 1;
}



undefined8 FUN_71005d461c(long param_1,undefined8 param_2)

{
  ulong uVar1;
  long lVar2;
  undefined8 local_3e0;
  undefined8 uStack_3d8;
  undefined8 local_3d0;
  undefined8 uStack_3c8;
  undefined8 local_3c0;
  undefined8 uStack_3b8;
  undefined8 local_3b0;
  undefined8 uStack_3a8;
  undefined8 local_3a0;
  undefined8 uStack_398;
  undefined8 local_390;
  undefined8 uStack_388;
  undefined8 local_380;
  undefined8 uStack_378;
  undefined8 local_370;
  undefined8 uStack_368;
  undefined8 local_360;
  undefined8 uStack_358;
  undefined8 local_350;
  undefined8 uStack_348;
  undefined8 local_340;
  undefined8 uStack_338;
  undefined8 local_330;
  undefined8 uStack_328;
  undefined8 local_320;
  undefined8 uStack_318;
  undefined8 local_310;
  undefined8 uStack_308;
  undefined8 local_300;
  undefined8 uStack_2f8;
  undefined8 local_2f0;
  undefined8 uStack_2e8;
  undefined1 auStack_2e0 [640];
  ushort local_60 [24];
  
  if (*(long *)(param_1 + 0x10) != 0) {
    local_60[0x10] = 0;
    local_60[0x11] = 0;
    local_60[0x12] = 0;
    local_60[0x13] = 0;
    local_60[0x14] = 0;
    local_60[0x15] = 0;
    local_60[0x16] = 0;
    local_60[0x17] = 0;
    local_60[8] = 0;
    local_60[9] = 0;
    local_60[10] = 0;
    local_60[0xb] = 0;
    local_60[0xc] = 0;
    local_60[0xd] = 0;
    local_60[0xe] = 0;
    local_60[0xf] = 0;
    local_60[0] = 0;
    local_60[1] = 0;
    local_60[2] = 0;
    local_60[3] = 0;
    local_60[4] = 0;
    local_60[5] = 0;
    local_60[6] = 0;
    local_60[7] = 0;
    thunk_EXT_FUN_02e95df0(auStack_2e0,0,0x280);
    local_2f0 = 0;
    uStack_2e8 = 0;
    local_300 = 0;
    uStack_2f8 = 0;
    local_310 = 0;
    uStack_308 = 0;
    local_320 = 0;
    uStack_318 = 0;
    local_330 = 0;
    uStack_328 = 0;
    local_340 = 0;
    uStack_338 = 0;
    local_350 = 0;
    uStack_348 = 0;
    local_360 = 0;
    uStack_358 = 0;
    local_370 = 0;
    uStack_368 = 0;
    local_380 = 0;
    uStack_378 = 0;
    local_390 = 0;
    uStack_388 = 0;
    local_3a0 = 0;
    uStack_398 = 0;
    local_3b0 = 0;
    uStack_3a8 = 0;
    local_3c0 = 0;
    uStack_3b8 = 0;
    local_3d0 = 0;
    uStack_3c8 = 0;
    local_3e0 = 0;
    uStack_3d8 = 0;
    uVar1 = FUN_71005d3e90(param_1,(short *)local_60,auStack_2e0,&local_3e0,0);
    if ((uVar1 & 1) == 0) goto LAB_71005d4bf0;
    lVar2 = FUN_7100603a80(local_60);
    FUN_7100603b14(param_1 + 0xf8,*(undefined8 *)(param_1 + 0x4b0),(int)lVar2);
    FUN_7100603b20((undefined1 *)(param_1 + 0xf8),param_2,local_60,**(long **)(param_1 + 0x10));
  }
  if (*(long *)(param_1 + 0x18) != 0) {
    local_60[0x10] = 0;
    local_60[0x11] = 0;
    local_60[0x12] = 0;
    local_60[0x13] = 0;
    local_60[0x14] = 0;
    local_60[0x15] = 0;
    local_60[0x16] = 0;
    local_60[0x17] = 0;
    local_60[8] = 0;
    local_60[9] = 0;
    local_60[10] = 0;
    local_60[0xb] = 0;
    local_60[0xc] = 0;
    local_60[0xd] = 0;
    local_60[0xe] = 0;
    local_60[0xf] = 0;
    local_60[0] = 0;
    local_60[1] = 0;
    local_60[2] = 0;
    local_60[3] = 0;
    local_60[4] = 0;
    local_60[5] = 0;
    local_60[6] = 0;
    local_60[7] = 0;
    thunk_EXT_FUN_02e95df0(auStack_2e0,0,0x280);
    local_2f0 = 0;
    uStack_2e8 = 0;
    local_300 = 0;
    uStack_2f8 = 0;
    local_310 = 0;
    uStack_308 = 0;
    local_320 = 0;
    uStack_318 = 0;
    local_330 = 0;
    uStack_328 = 0;
    local_340 = 0;
    uStack_338 = 0;
    local_350 = 0;
    uStack_348 = 0;
    local_360 = 0;
    uStack_358 = 0;
    local_370 = 0;
    uStack_368 = 0;
    local_380 = 0;
    uStack_378 = 0;
    local_390 = 0;
    uStack_388 = 0;
    local_3a0 = 0;
    uStack_398 = 0;
    local_3b0 = 0;
    uStack_3a8 = 0;
    local_3c0 = 0;
    uStack_3b8 = 0;
    local_3d0 = 0;
    uStack_3c8 = 0;
    local_3e0 = 0;
    uStack_3d8 = 0;
    uVar1 = FUN_71005d3e90(param_1,(short *)local_60,auStack_2e0,&local_3e0,1);
    if ((uVar1 & 1) == 0) goto LAB_71005d4bf0;
    lVar2 = FUN_7100603a80(local_60);
    FUN_7100603b14(param_1 + 0x118,*(undefined8 *)(param_1 + 0x4b8),(int)lVar2);
    FUN_7100603b20((undefined1 *)(param_1 + 0x118),param_2,local_60,**(long **)(param_1 + 0x18));
  }
  if (*(long *)(param_1 + 0x20) != 0) {
    local_60[0x10] = 0;
    local_60[0x11] = 0;
    local_60[0x12] = 0;
    local_60[0x13] = 0;
    local_60[0x14] = 0;
    local_60[0x15] = 0;
    local_60[0x16] = 0;
    local_60[0x17] = 0;
    local_60[8] = 0;
    local_60[9] = 0;
    local_60[10] = 0;
    local_60[0xb] = 0;
    local_60[0xc] = 0;
    local_60[0xd] = 0;
    local_60[0xe] = 0;
    local_60[0xf] = 0;
    local_60[0] = 0;
    local_60[1] = 0;
    local_60[2] = 0;
    local_60[3] = 0;
    local_60[4] = 0;
    local_60[5] = 0;
    local_60[6] = 0;
    local_60[7] = 0;
    thunk_EXT_FUN_02e95df0(auStack_2e0,0,0x280);
    local_2f0 = 0;
    uStack_2e8 = 0;
    local_300 = 0;
    uStack_2f8 = 0;
    local_310 = 0;
    uStack_308 = 0;
    local_320 = 0;
    uStack_318 = 0;
    local_330 = 0;
    uStack_328 = 0;
    local_340 = 0;
    uStack_338 = 0;
    local_350 = 0;
    uStack_348 = 0;
    local_360 = 0;
    uStack_358 = 0;
    local_370 = 0;
    uStack_368 = 0;
    local_380 = 0;
    uStack_378 = 0;
    local_390 = 0;
    uStack_388 = 0;
    local_3a0 = 0;
    uStack_398 = 0;
    local_3b0 = 0;
    uStack_3a8 = 0;
    local_3c0 = 0;
    uStack_3b8 = 0;
    local_3d0 = 0;
    uStack_3c8 = 0;
    local_3e0 = 0;
    uStack_3d8 = 0;
    uVar1 = FUN_71005d3e90(param_1,(short *)local_60,auStack_2e0,&local_3e0,2);
    if ((uVar1 & 1) == 0) goto LAB_71005d4bf0;
    lVar2 = FUN_7100603a80(local_60);
    FUN_7100603b14(param_1 + 0x138,*(undefined8 *)(param_1 + 0x4c0),(int)lVar2);
    FUN_7100603b20((undefined1 *)(param_1 + 0x138),param_2,local_60,**(long **)(param_1 + 0x20));
  }
  if (*(long *)(param_1 + 0x28) != 0) {
    local_60[0x10] = 0;
    local_60[0x11] = 0;
    local_60[0x12] = 0;
    local_60[0x13] = 0;
    local_60[0x14] = 0;
    local_60[0x15] = 0;
    local_60[0x16] = 0;
    local_60[0x17] = 0;
    local_60[8] = 0;
    local_60[9] = 0;
    local_60[10] = 0;
    local_60[0xb] = 0;
    local_60[0xc] = 0;
    local_60[0xd] = 0;
    local_60[0xe] = 0;
    local_60[0xf] = 0;
    local_60[0] = 0;
    local_60[1] = 0;
    local_60[2] = 0;
    local_60[3] = 0;
    local_60[4] = 0;
    local_60[5] = 0;
    local_60[6] = 0;
    local_60[7] = 0;
    thunk_EXT_FUN_02e95df0(auStack_2e0,0,0x280);
    local_2f0 = 0;
    uStack_2e8 = 0;
    local_300 = 0;
    uStack_2f8 = 0;
    local_310 = 0;
    uStack_308 = 0;
    local_320 = 0;
    uStack_318 = 0;
    local_330 = 0;
    uStack_328 = 0;
    local_340 = 0;
    uStack_338 = 0;
    local_350 = 0;
    uStack_348 = 0;
    local_360 = 0;
    uStack_358 = 0;
    local_370 = 0;
    uStack_368 = 0;
    local_380 = 0;
    uStack_378 = 0;
    local_390 = 0;
    uStack_388 = 0;
    local_3a0 = 0;
    uStack_398 = 0;
    local_3b0 = 0;
    uStack_3a8 = 0;
    local_3c0 = 0;
    uStack_3b8 = 0;
    local_3d0 = 0;
    uStack_3c8 = 0;
    local_3e0 = 0;
    uStack_3d8 = 0;
    uVar1 = FUN_71005d3e90(param_1,(short *)local_60,auStack_2e0,&local_3e0,3);
    if ((uVar1 & 1) == 0) goto LAB_71005d4bf0;
    lVar2 = FUN_7100603a80(local_60);
    FUN_7100603b14(param_1 + 0x158,*(undefined8 *)(param_1 + 0x4c8),(int)lVar2);
    FUN_7100603b20((undefined1 *)(param_1 + 0x158),param_2,local_60,**(long **)(param_1 + 0x28));
  }
  if (*(long *)(param_1 + 0x30) != 0) {
    local_60[0x10] = 0;
    local_60[0x11] = 0;
    local_60[0x12] = 0;
    local_60[0x13] = 0;
    local_60[0x14] = 0;
    local_60[0x15] = 0;
    local_60[0x16] = 0;
    local_60[0x17] = 0;
    local_60[8] = 0;
    local_60[9] = 0;
    local_60[10] = 0;
    local_60[0xb] = 0;
    local_60[0xc] = 0;
    local_60[0xd] = 0;
    local_60[0xe] = 0;
    local_60[0xf] = 0;
    local_60[0] = 0;
    local_60[1] = 0;
    local_60[2] = 0;
    local_60[3] = 0;
    local_60[4] = 0;
    local_60[5] = 0;
    local_60[6] = 0;
    local_60[7] = 0;
    thunk_EXT_FUN_02e95df0(auStack_2e0,0,0x280);
    local_2f0 = 0;
    uStack_2e8 = 0;
    local_300 = 0;
    uStack_2f8 = 0;
    local_310 = 0;
    uStack_308 = 0;
    local_320 = 0;
    uStack_318 = 0;
    local_330 = 0;
    uStack_328 = 0;
    local_340 = 0;
    uStack_338 = 0;
    local_350 = 0;
    uStack_348 = 0;
    local_360 = 0;
    uStack_358 = 0;
    local_370 = 0;
    uStack_368 = 0;
    local_380 = 0;
    uStack_378 = 0;
    local_390 = 0;
    uStack_388 = 0;
    local_3a0 = 0;
    uStack_398 = 0;
    local_3b0 = 0;
    uStack_3a8 = 0;
    local_3c0 = 0;
    uStack_3b8 = 0;
    local_3d0 = 0;
    uStack_3c8 = 0;
    local_3e0 = 0;
    uStack_3d8 = 0;
    uVar1 = FUN_71005d3e90(param_1,(short *)local_60,auStack_2e0,&local_3e0,4);
    if ((uVar1 & 1) == 0) goto LAB_71005d4bf0;
    lVar2 = FUN_7100603a80(local_60);
    FUN_7100603b14(param_1 + 0x178,*(undefined8 *)(param_1 + 0x4d0),(int)lVar2);
    FUN_7100603b20((undefined1 *)(param_1 + 0x178),param_2,local_60,**(long **)(param_1 + 0x30));
  }
  if (*(long *)(param_1 + 0x38) != 0) {
    local_60[0x10] = 0;
    local_60[0x11] = 0;
    local_60[0x12] = 0;
    local_60[0x13] = 0;
    local_60[0x14] = 0;
    local_60[0x15] = 0;
    local_60[0x16] = 0;
    local_60[0x17] = 0;
    local_60[8] = 0;
    local_60[9] = 0;
    local_60[10] = 0;
    local_60[0xb] = 0;
    local_60[0xc] = 0;
    local_60[0xd] = 0;
    local_60[0xe] = 0;
    local_60[0xf] = 0;
    local_60[0] = 0;
    local_60[1] = 0;
    local_60[2] = 0;
    local_60[3] = 0;
    local_60[4] = 0;
    local_60[5] = 0;
    local_60[6] = 0;
    local_60[7] = 0;
    thunk_EXT_FUN_02e95df0(auStack_2e0,0,0x280);
    local_2f0 = 0;
    uStack_2e8 = 0;
    local_300 = 0;
    uStack_2f8 = 0;
    local_310 = 0;
    uStack_308 = 0;
    local_320 = 0;
    uStack_318 = 0;
    local_330 = 0;
    uStack_328 = 0;
    local_340 = 0;
    uStack_338 = 0;
    local_350 = 0;
    uStack_348 = 0;
    local_360 = 0;
    uStack_358 = 0;
    local_370 = 0;
    uStack_368 = 0;
    local_380 = 0;
    uStack_378 = 0;
    local_390 = 0;
    uStack_388 = 0;
    local_3a0 = 0;
    uStack_398 = 0;
    local_3b0 = 0;
    uStack_3a8 = 0;
    local_3c0 = 0;
    uStack_3b8 = 0;
    local_3d0 = 0;
    uStack_3c8 = 0;
    local_3e0 = 0;
    uStack_3d8 = 0;
    uVar1 = FUN_71005d3e90(param_1,(short *)local_60,auStack_2e0,&local_3e0,5);
    if ((uVar1 & 1) == 0) goto LAB_71005d4bf0;
    lVar2 = FUN_7100603a80(local_60);
    FUN_7100603b14(param_1 + 0x198,*(undefined8 *)(param_1 + 0x4d8),(int)lVar2);
    FUN_7100603b20((undefined1 *)(param_1 + 0x198),param_2,local_60,**(long **)(param_1 + 0x38));
  }
  if (*(long *)(param_1 + 0x40) != 0) {
    local_60[0x10] = 0;
    local_60[0x11] = 0;
    local_60[0x12] = 0;
    local_60[0x13] = 0;
    local_60[0x14] = 0;
    local_60[0x15] = 0;
    local_60[0x16] = 0;
    local_60[0x17] = 0;
    local_60[8] = 0;
    local_60[9] = 0;
    local_60[10] = 0;
    local_60[0xb] = 0;
    local_60[0xc] = 0;
    local_60[0xd] = 0;
    local_60[0xe] = 0;
    local_60[0xf] = 0;
    local_60[0] = 0;
    local_60[1] = 0;
    local_60[2] = 0;
    local_60[3] = 0;
    local_60[4] = 0;
    local_60[5] = 0;
    local_60[6] = 0;
    local_60[7] = 0;
    thunk_EXT_FUN_02e95df0(auStack_2e0,0,0x280);
    local_2f0 = 0;
    uStack_2e8 = 0;
    local_300 = 0;
    uStack_2f8 = 0;
    local_310 = 0;
    uStack_308 = 0;
    local_320 = 0;
    uStack_318 = 0;
    local_330 = 0;
    uStack_328 = 0;
    local_340 = 0;
    uStack_338 = 0;
    local_350 = 0;
    uStack_348 = 0;
    local_360 = 0;
    uStack_358 = 0;
    local_370 = 0;
    uStack_368 = 0;
    local_380 = 0;
    uStack_378 = 0;
    local_390 = 0;
    uStack_388 = 0;
    local_3a0 = 0;
    uStack_398 = 0;
    local_3b0 = 0;
    uStack_3a8 = 0;
    local_3c0 = 0;
    uStack_3b8 = 0;
    local_3d0 = 0;
    uStack_3c8 = 0;
    local_3e0 = 0;
    uStack_3d8 = 0;
    uVar1 = FUN_71005d3e90(param_1,(short *)local_60,auStack_2e0,&local_3e0,6);
    if ((uVar1 & 1) == 0) goto LAB_71005d4bf0;
    lVar2 = FUN_7100603a80(local_60);
    FUN_7100603b14(param_1 + 0x1b8,*(undefined8 *)(param_1 + 0x4e0),(int)lVar2);
    FUN_7100603b20((undefined1 *)(param_1 + 0x1b8),param_2,local_60,**(long **)(param_1 + 0x40));
  }
  if (*(long *)(param_1 + 0x48) != 0) {
    local_60[0x10] = 0;
    local_60[0x11] = 0;
    local_60[0x12] = 0;
    local_60[0x13] = 0;
    local_60[0x14] = 0;
    local_60[0x15] = 0;
    local_60[0x16] = 0;
    local_60[0x17] = 0;
    local_60[8] = 0;
    local_60[9] = 0;
    local_60[10] = 0;
    local_60[0xb] = 0;
    local_60[0xc] = 0;
    local_60[0xd] = 0;
    local_60[0xe] = 0;
    local_60[0xf] = 0;
    local_60[0] = 0;
    local_60[1] = 0;
    local_60[2] = 0;
    local_60[3] = 0;
    local_60[4] = 0;
    local_60[5] = 0;
    local_60[6] = 0;
    local_60[7] = 0;
    thunk_EXT_FUN_02e95df0(auStack_2e0,0,0x280);
    local_2f0 = 0;
    uStack_2e8 = 0;
    local_300 = 0;
    uStack_2f8 = 0;
    local_310 = 0;
    uStack_308 = 0;
    local_320 = 0;
    uStack_318 = 0;
    local_330 = 0;
    uStack_328 = 0;
    local_340 = 0;
    uStack_338 = 0;
    local_350 = 0;
    uStack_348 = 0;
    local_360 = 0;
    uStack_358 = 0;
    local_370 = 0;
    uStack_368 = 0;
    local_380 = 0;
    uStack_378 = 0;
    local_390 = 0;
    uStack_388 = 0;
    local_3a0 = 0;
    uStack_398 = 0;
    local_3b0 = 0;
    uStack_3a8 = 0;
    local_3c0 = 0;
    uStack_3b8 = 0;
    local_3d0 = 0;
    uStack_3c8 = 0;
    local_3e0 = 0;
    uStack_3d8 = 0;
    uVar1 = FUN_71005d3e90(param_1,(short *)local_60,auStack_2e0,&local_3e0,7);
    if ((uVar1 & 1) == 0) {
LAB_71005d4bf0:
      FUN_71005dee10();
      return 0;
    }
    lVar2 = FUN_7100603a80(local_60);
    FUN_7100603b14(param_1 + 0x1d8,*(undefined8 *)(param_1 + 0x4e8),(int)lVar2);
    FUN_7100603b20((undefined1 *)(param_1 + 0x1d8),param_2,local_60,**(long **)(param_1 + 0x48));
  }
  return 1;
}



void FUN_71005d4c14(long param_1)

{
  if (*(char *)(param_1 + 0xed) != '\0') {
    if (*(char *)(param_1 + 0xf8) != '\0') {
      FUN_7100603e84((char *)(param_1 + 0xf8));
    }
    *(undefined8 *)(param_1 + 0x4b0) = 0;
    if (*(char *)(param_1 + 0x118) != '\0') {
      FUN_7100603e84((undefined1 *)(param_1 + 0x118));
    }
    *(undefined8 *)(param_1 + 0x4b8) = 0;
    if (*(char *)(param_1 + 0x138) != '\0') {
      FUN_7100603e84((undefined1 *)(param_1 + 0x138));
    }
    *(undefined8 *)(param_1 + 0x4c0) = 0;
    if (*(char *)(param_1 + 0x158) != '\0') {
      FUN_7100603e84((undefined1 *)(param_1 + 0x158));
    }
    *(undefined8 *)(param_1 + 0x4c8) = 0;
    if (*(char *)(param_1 + 0x178) != '\0') {
      FUN_7100603e84((undefined1 *)(param_1 + 0x178));
    }
    *(undefined8 *)(param_1 + 0x4d0) = 0;
    if (*(char *)(param_1 + 0x198) != '\0') {
      FUN_7100603e84((undefined1 *)(param_1 + 0x198));
    }
    *(undefined8 *)(param_1 + 0x4d8) = 0;
    if (*(char *)(param_1 + 0x1b8) != '\0') {
      FUN_7100603e84((undefined1 *)(param_1 + 0x1b8));
    }
    *(undefined8 *)(param_1 + 0x4e0) = 0;
    if (*(char *)(param_1 + 0x1d8) != '\0') {
      FUN_7100603e84((undefined1 *)(param_1 + 0x1d8));
    }
    *(undefined8 *)(param_1 + 0x4e8) = 0;
  }
  return;
}



undefined8 FUN_71005d4cf8(long *param_1,long param_2,undefined *param_3,undefined *param_4)

{
  long lVar1;
  ulong uVar2;
  undefined8 uVar3;
  
  if (*(char *)((long)param_1 + 0xed) != '\0') {
    return 1;
  }
  if (*(char *)(param_2 + 0x3d9) != '\0') {
    uVar3 = *(undefined8 *)(param_2 + 0x420);
    if ((*(long *)(*param_1 + 0xe38) != -1) && (*(byte *)((long)param_1 + 0xe6) - 4 < 0xfffffffd)) {
      lVar1 = branch_71005E7D10_0x71005e7d1c(param_2,*(long *)(*param_1 + 0xe38));
      param_1[1] = lVar1;
    }
    uVar2 = FUN_71005d4df0(param_1,param_2 + 0x3a0,param_2 + 0x3e0,param_3,param_4);
    if (((uVar2 & 1) != 0) && (uVar2 = FUN_71005d461c((long)param_1,uVar3), (uVar2 & 1) != 0)) {
      *(undefined1 *)((long)param_1 + 0xed) = 1;
      return 1;
    }
  }
  FUN_71005dee10();
  return 0;
}



undefined8
FUN_71005d4df0(long *param_1,long param_2,long param_3,undefined *param_4,undefined *param_5)

{
  int iVar1;
  long lVar2;
  int *piVar3;
  long *plVar4;
  long *plVar5;
  long *plVar6;
  long *plVar7;
  long *plVar8;
  long *plVar9;
  long *plVar10;
  long *plVar11;
  long *plVar12;
  
  plVar6 = param_1 + 2;
  lVar2 = *param_1;
  plVar12 = param_1 + 3;
  *plVar12 = 0;
  plVar4 = param_1 + 4;
  *plVar4 = 0;
  plVar5 = param_1 + 5;
  *plVar5 = 0;
  plVar8 = param_1 + 6;
  *plVar8 = 0;
  plVar11 = param_1 + 7;
  *plVar11 = 0;
  plVar10 = param_1 + 8;
  *plVar10 = 0;
  plVar9 = param_1 + 9;
  *plVar9 = 0;
  if (*(char *)(lVar2 + 0xe89) == '\0') {
    if (((param_4 != (undefined *)0x0) && (piVar3 = *(int **)(param_2 + 0x28), piVar3 != (int *)0x0)
        ) && (*(int *)(lVar2 + 0xe94) <= *piVar3)) {
      (*(code *)param_4)((long)piVar3 + (long)(piVar3[1] * *(int *)(lVar2 + 0xe94)) + 8,piVar3[1],
                         plVar6);
    }
    plVar7 = (long *)*plVar6;
  }
  else {
    if (*(char *)(param_2 + 0x39) == '\0') {
      *plVar6 = 0;
      goto LAB_71005d5654;
    }
    plVar7 = (long *)(*(long *)(param_2 + 0x18) + (long)*(int *)(lVar2 + 0xe94) * 0x90);
    if (*(char *)((long)plVar7 + 0x8c) == '\0') {
      FUN_71017ca69c(param_2,plVar7,
                     *(long *)(*(long *)(param_2 + 0x10) + 0x20) +
                     (long)*(int *)(lVar2 + 0xe94) * 0x40);
      *plVar6 = (long)plVar7;
    }
    else {
      *plVar6 = (long)plVar7;
    }
  }
  if (plVar7 == (long *)0x0) {
LAB_71005d5654:
    FUN_71005dee10();
    return 0;
  }
  lVar2 = *param_1;
  iVar1 = *(int *)(lVar2 + 0xe98);
  if (iVar1 != -1) {
    if (*(char *)(lVar2 + 0xe8a) == '\0') {
      if (((param_4 != (undefined *)0x0) &&
          (piVar3 = *(int **)(param_2 + 0x28), piVar3 != (int *)0x0)) && (iVar1 <= *piVar3)) {
        (*(code *)param_4)((long)piVar3 + (long)(piVar3[1] * iVar1) + 8,piVar3[1],plVar12);
      }
      plVar6 = (long *)*plVar12;
    }
    else {
      if (*(char *)(param_2 + 0x39) == '\0') {
        *plVar12 = 0;
        goto LAB_71005d5654;
      }
      plVar6 = (long *)(*(long *)(param_2 + 0x18) + (long)iVar1 * 0x90);
      if (*(char *)((long)plVar6 + 0x8c) == '\0') {
        FUN_71017ca69c(param_2,plVar6,
                       *(long *)(*(long *)(param_2 + 0x10) + 0x20) + (long)iVar1 * 0x40);
        *plVar12 = (long)plVar6;
      }
      else {
        *plVar12 = (long)plVar6;
      }
    }
    if (plVar6 == (long *)0x0) goto LAB_71005d5654;
    lVar2 = *param_1;
  }
  iVar1 = *(int *)(lVar2 + 0xe9c);
  if (iVar1 != -1) {
    if (*(char *)(lVar2 + 0xe8b) == '\0') {
      if (((param_4 != (undefined *)0x0) &&
          (piVar3 = *(int **)(param_2 + 0x28), piVar3 != (int *)0x0)) && (iVar1 <= *piVar3)) {
        (*(code *)param_4)((long)piVar3 + (long)(piVar3[1] * iVar1) + 8,piVar3[1],plVar4);
      }
      plVar6 = (long *)*plVar4;
    }
    else {
      if (*(char *)(param_2 + 0x39) == '\0') {
        *plVar4 = 0;
        goto LAB_71005d5654;
      }
      plVar6 = (long *)(*(long *)(param_2 + 0x18) + (long)iVar1 * 0x90);
      if (*(char *)((long)plVar6 + 0x8c) == '\0') {
        FUN_71017ca69c(param_2,plVar6,
                       *(long *)(*(long *)(param_2 + 0x10) + 0x20) + (long)iVar1 * 0x40);
      }
      *plVar4 = (long)plVar6;
    }
    if (plVar6 == (long *)0x0) goto LAB_71005d5654;
    lVar2 = *param_1;
  }
  iVar1 = *(int *)(lVar2 + 0xea0);
  if (iVar1 != -1) {
    if (*(char *)(lVar2 + 0xe8c) == '\0') {
      if (((param_4 != (undefined *)0x0) &&
          (piVar3 = *(int **)(param_2 + 0x28), piVar3 != (int *)0x0)) && (iVar1 <= *piVar3)) {
        (*(code *)param_4)((long)piVar3 + (long)(piVar3[1] * iVar1) + 8,piVar3[1],plVar5);
      }
      plVar4 = (long *)*plVar5;
    }
    else {
      if (*(char *)(param_2 + 0x39) == '\0') {
        *plVar5 = 0;
        goto LAB_71005d5654;
      }
      plVar4 = (long *)(*(long *)(param_2 + 0x18) + (long)iVar1 * 0x90);
      if (*(char *)((long)plVar4 + 0x8c) == '\0') {
        FUN_71017ca69c(param_2,plVar4,
                       *(long *)(*(long *)(param_2 + 0x10) + 0x20) + (long)iVar1 * 0x40);
      }
      *plVar5 = (long)plVar4;
    }
    if (plVar4 == (long *)0x0) goto LAB_71005d5654;
    lVar2 = *param_1;
  }
  iVar1 = *(int *)(lVar2 + 0xea4);
  if (iVar1 != -1) {
    if (*(char *)(lVar2 + 0xe8d) == '\0') {
      if (((param_4 != (undefined *)0x0) &&
          (piVar3 = *(int **)(param_2 + 0x28), piVar3 != (int *)0x0)) && (iVar1 <= *piVar3)) {
        (*(code *)param_4)((long)piVar3 + (long)(piVar3[1] * iVar1) + 8,piVar3[1],plVar8);
      }
      plVar5 = (long *)*plVar8;
    }
    else {
      if (*(char *)(param_2 + 0x39) == '\0') {
        *plVar8 = 0;
        goto LAB_71005d5654;
      }
      plVar5 = (long *)(*(long *)(param_2 + 0x18) + (long)iVar1 * 0x90);
      if (*(char *)((long)plVar5 + 0x8c) == '\0') {
        FUN_71017ca69c(param_2,plVar5,
                       *(long *)(*(long *)(param_2 + 0x10) + 0x20) + (long)iVar1 * 0x40);
      }
      *plVar8 = (long)plVar5;
    }
    if (plVar5 == (long *)0x0) goto LAB_71005d5654;
    lVar2 = *param_1;
  }
  iVar1 = *(int *)(lVar2 + 0xea8);
  if (iVar1 != -1) {
    if (*(char *)(lVar2 + 0xe8e) == '\0') {
      if (((param_4 != (undefined *)0x0) &&
          (piVar3 = *(int **)(param_2 + 0x28), piVar3 != (int *)0x0)) && (iVar1 <= *piVar3)) {
        (*(code *)param_4)((long)piVar3 + (long)(piVar3[1] * iVar1) + 8,piVar3[1],plVar11);
      }
      plVar5 = (long *)*plVar11;
    }
    else {
      if (*(char *)(param_2 + 0x39) == '\0') {
        *plVar11 = 0;
        goto LAB_71005d5654;
      }
      plVar5 = (long *)(*(long *)(param_2 + 0x18) + (long)iVar1 * 0x90);
      if (*(char *)((long)plVar5 + 0x8c) == '\0') {
        FUN_71017ca69c(param_2,plVar5,
                       *(long *)(*(long *)(param_2 + 0x10) + 0x20) + (long)iVar1 * 0x40);
      }
      *plVar11 = (long)plVar5;
    }
    if (plVar5 == (long *)0x0) goto LAB_71005d5654;
    lVar2 = *param_1;
  }
  iVar1 = *(int *)(lVar2 + 0xeac);
  if (iVar1 != -1) {
    if (*(char *)(lVar2 + 0xe8f) == '\0') {
      if (((param_4 != (undefined *)0x0) &&
          (piVar3 = *(int **)(param_2 + 0x28), piVar3 != (int *)0x0)) && (iVar1 <= *piVar3)) {
        (*(code *)param_4)((long)piVar3 + (long)(piVar3[1] * iVar1) + 8,piVar3[1],plVar10);
      }
      plVar5 = (long *)*plVar10;
    }
    else {
      if (*(char *)(param_2 + 0x39) == '\0') {
        *plVar10 = 0;
        goto LAB_71005d5654;
      }
      plVar5 = (long *)(*(long *)(param_2 + 0x18) + (long)iVar1 * 0x90);
      if (*(char *)((long)plVar5 + 0x8c) == '\0') {
        FUN_71017ca69c(param_2,plVar5,
                       *(long *)(*(long *)(param_2 + 0x10) + 0x20) + (long)iVar1 * 0x40);
      }
      *plVar10 = (long)plVar5;
    }
    if (plVar5 == (long *)0x0) goto LAB_71005d5654;
    lVar2 = *param_1;
  }
  iVar1 = *(int *)(lVar2 + 0xeb0);
  if (iVar1 == -1) {
    iVar1 = *(int *)(lVar2 + 0xeb4);
  }
  else {
    if (*(char *)(lVar2 + 0xe90) == '\0') {
      if (((param_4 != (undefined *)0x0) &&
          (piVar3 = *(int **)(param_2 + 0x28), piVar3 != (int *)0x0)) && (iVar1 <= *piVar3)) {
        (*(code *)param_4)((long)piVar3 + (long)(piVar3[1] * iVar1) + 8,piVar3[1],plVar9);
      }
      plVar5 = (long *)*plVar9;
    }
    else {
      if (*(char *)(param_2 + 0x39) == '\0') {
        plVar5 = (long *)0x0;
      }
      else {
        plVar5 = (long *)(*(long *)(param_2 + 0x18) + (long)iVar1 * 0x90);
        if (*(char *)((long)plVar5 + 0x8c) == '\0') {
          FUN_71017ca69c(param_2,plVar5,
                         *(long *)(*(long *)(param_2 + 0x10) + 0x20) + (long)iVar1 * 0x40);
        }
      }
      *plVar9 = (long)plVar5;
    }
    if (plVar5 == (long *)0x0) goto LAB_71005d5654;
    lVar2 = *param_1;
    iVar1 = *(int *)(lVar2 + 0xeb4);
  }
  if ((iVar1 != -1) && (*(char *)(param_3 + 0x39) != '\0')) {
    if (*(char *)(lVar2 + 0xe91) == '\0') {
      if (((param_5 != (undefined *)0x0) &&
          (piVar3 = *(int **)(param_3 + 0x28), piVar3 != (int *)0x0)) && (iVar1 <= *piVar3)) {
        (*(code *)param_5)((long)piVar3 + (long)(piVar3[1] * iVar1) + 8,piVar3[1],param_1 + 10);
      }
    }
    else {
      plVar5 = FUN_71005d567c(param_3,iVar1);
      param_1[10] = (long)plVar5;
    }
    if (param_1[10] == 0) goto LAB_71005d5654;
    lVar2 = *param_1;
  }
  iVar1 = *(int *)(lVar2 + 0xeb8);
  if (iVar1 != -1) {
    if (*(char *)(lVar2 + 0xe92) == '\0') {
      if (((param_5 != (undefined *)0x0) &&
          (piVar3 = *(int **)(param_3 + 0x28), piVar3 != (int *)0x0)) && (iVar1 <= *piVar3)) {
        (*(code *)param_5)((long)piVar3 + (long)(piVar3[1] * iVar1) + 8,piVar3[1],param_1 + 0xb);
      }
    }
    else if (*(char *)(param_3 + 0x39) == '\0') {
      param_1[0xb] = 0;
    }
    else {
      plVar5 = (long *)(*(long *)(param_3 + 0x18) + (long)iVar1 * 0x58);
      if (*(char *)((long)plVar5 + 0x53) == '\0') {
        FUN_71017ca764(param_3,plVar5,
                       *(long *)(*(long *)(param_3 + 0x10) + 0x20) + (long)iVar1 * 0x40);
      }
      param_1[0xb] = (long)plVar5;
    }
    if (param_1[0xb] == 0) goto LAB_71005d5654;
    lVar2 = *param_1;
  }
  iVar1 = *(int *)(lVar2 + 0xebc);
  if (iVar1 != -1) {
    if (*(char *)(lVar2 + 0xe93) == '\0') {
      if (((param_5 != (undefined *)0x0) &&
          (piVar3 = *(int **)(param_3 + 0x28), piVar3 != (int *)0x0)) && (iVar1 <= *piVar3)) {
        (*(code *)param_5)((long)piVar3 + (long)(piVar3[1] * iVar1) + 8,piVar3[1],param_1 + 0xc);
      }
    }
    else if (*(char *)(param_3 + 0x39) == '\0') {
      param_1[0xc] = 0;
    }
    else {
      plVar5 = (long *)(*(long *)(param_3 + 0x18) + (long)iVar1 * 0x58);
      if (*(char *)((long)plVar5 + 0x53) == '\0') {
        FUN_71017ca764(param_3,plVar5,
                       *(long *)(*(long *)(param_3 + 0x10) + 0x20) + (long)iVar1 * 0x40);
      }
      param_1[0xc] = (long)plVar5;
    }
    if (param_1[0xc] == 0) goto LAB_71005d5654;
  }
  return 1;
}



long * FUN_71005d567c(long param_1,int param_2)

{
  long *plVar1;
  
  if (*(char *)(param_1 + 0x39) == '\0') {
    return (long *)0x0;
  }
  plVar1 = (long *)(*(long *)(param_1 + 0x18) + (long)param_2 * 0x58);
  if (*(char *)((long)plVar1 + 0x53) != '\0') {
    return plVar1;
  }
  FUN_71017ca764(param_1,plVar1,*(long *)(*(long *)(param_1 + 0x10) + 0x20) + (long)param_2 * 0x40);
  return plVar1;
}



// WARNING: Type propagation algorithm not settling

void FUN_71005d56f0(long *param_1,long param_2,long *param_3)

{
  undefined8 *puVar1;
  undefined4 *puVar2;
  undefined8 uVar3;
  undefined8 uVar4;
  char cVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  undefined1 auVar9 [16];
  undefined1 auVar10 [12];
  long lVar11;
  long lVar12;
  uint uVar13;
  ulong uVar14;
  undefined8 *puVar15;
  undefined4 *puVar16;
  byte *pbVar17;
  long lVar18;
  undefined8 uVar19;
  float *pfVar20;
  float fVar21;
  byte bVar22;
  undefined4 uVar23;
  int iVar24;
  undefined4 uVar25;
  float fVar26;
  float fVar29;
  undefined1 auVar27 [16];
  undefined1 auVar28 [16];
  float fVar30;
  float fVar31;
  float fVar32;
  undefined1 auVar33 [16];
  undefined1 auVar34 [16];
  undefined1 auVar35 [16];
  byte bVar36;
  byte bVar37;
  byte bVar38;
  byte bVar39;
  byte bVar40;
  byte bVar41;
  byte bVar42;
  byte bVar43;
  float fVar44;
  float fVar45;
  float fVar46;
  float fVar47;
  float fVar48;
  float fVar49;
  float fVar50;
  float fVar51;
  float fVar52;
  float fVar53;
  undefined1 auVar54 [16];
  undefined1 auVar55 [16];
  undefined1 auVar56 [16];
  uint local_3c [3];
  
  lVar12 = *param_1;
  if (*(long *)(lVar12 + 0x1038) != -1) {
    lVar11 = (**(code **)(*param_3 + 0x20))(param_3,lVar12 + 0x1038);
    lVar12 = *param_1;
    param_1[0x15] = lVar11;
  }
  if (*(long *)(lVar12 + 0x1050) != -1) {
    lVar11 = (**(code **)(*param_3 + 0x20))(param_3,lVar12 + 0x1050);
    lVar12 = *param_1;
    param_1[0x16] = lVar11;
  }
  if (*(long *)(lVar12 + 0x1068) != -1) {
    lVar11 = (**(code **)(*param_3 + 0x20))(param_3,lVar12 + 0x1068);
    lVar12 = *param_1;
    param_1[0x17] = lVar11;
  }
  if (*(long *)(lVar12 + 0x1080) != -1) {
    lVar11 = (**(code **)(*param_3 + 0x20))(param_3,lVar12 + 0x1080);
    lVar12 = *param_1;
    param_1[0x18] = lVar11;
  }
  if (*(long *)(lVar12 + 0x1098) != -1) {
    lVar11 = (**(code **)(*param_3 + 0x20))(param_3,lVar12 + 0x1098);
    lVar12 = *param_1;
    param_1[0x19] = lVar11;
  }
  if (*(long *)(lVar12 + 0x10b0) != -1) {
    lVar11 = (**(code **)(*param_3 + 0x20))(param_3,lVar12 + 0x10b0);
    lVar12 = *param_1;
    param_1[0x1a] = lVar11;
  }
  if (*(char *)(lVar12 + 0xfe4) == '\0') {
    *(undefined4 *)(lVar12 + 0x6b8) = *(undefined4 *)(lVar12 + 0xff0);
    *(undefined8 *)(lVar12 + 0x6b0) = *(undefined8 *)(lVar12 + 0xfe8);
    lVar12 = *param_1;
    cVar5 = *(char *)(lVar12 + 0xfe6);
  }
  else {
    cVar5 = *(char *)(lVar12 + 0xfe6);
  }
  if (cVar5 == '\0') {
    *(undefined4 *)(lVar12 + 0x730) = *(undefined4 *)(lVar12 + 0xff4);
    lVar12 = *param_1;
    cVar5 = *(char *)(lVar12 + 0xfe5);
  }
  else {
    cVar5 = *(char *)(lVar12 + 0xfe5);
  }
  if (cVar5 == '\0') {
    *(undefined4 *)(lVar12 + 0x7b8) = *(undefined4 *)(lVar12 + 0x1000);
    *(undefined8 *)(lVar12 + 0x7b0) = *(undefined8 *)(lVar12 + 0xff8);
    lVar12 = *param_1;
    cVar5 = *(char *)(lVar12 + 0xfe7);
  }
  else {
    cVar5 = *(char *)(lVar12 + 0xfe7);
  }
  if (cVar5 == '\0') {
    *(undefined4 *)(lVar12 + 0x830) = *(undefined4 *)(lVar12 + 0x1004);
    lVar12 = *param_1;
  }
  if ((ulong)(long)*(char *)(lVar12 + 0x10cc) < 4) {
    lVar11 = (long)*(char *)(lVar12 + 0x10cc) * 4;
    uVar23 = *(undefined4 *)(&DAT_7102ebfae0 + lVar11);
    *(undefined4 *)(lVar12 + 0x500) = *(undefined4 *)(&DAT_7102ebfb70 + lVar11);
    *(undefined4 *)(*param_1 + 0x504) = uVar23;
    lVar12 = *param_1;
    cVar5 = *(char *)(lVar12 + 0x10dc);
  }
  else {
    lVar12 = *param_1;
    cVar5 = *(char *)(lVar12 + 0x10dc);
  }
  if ((ulong)(long)cVar5 < 4) {
    lVar11 = (long)cVar5 * 4;
    uVar23 = *(undefined4 *)(&DAT_7102ebfae0 + lVar11);
    *(undefined4 *)(lVar12 + 0x550) = *(undefined4 *)(&DAT_7102ebfb70 + lVar11);
    *(undefined4 *)(*param_1 + 0x554) = uVar23;
    lVar12 = *param_1;
    cVar5 = *(char *)(lVar12 + 0x10ec);
  }
  else {
    lVar12 = *param_1;
    cVar5 = *(char *)(lVar12 + 0x10ec);
  }
  if ((ulong)(long)cVar5 < 4) {
    lVar11 = (long)cVar5 * 4;
    uVar23 = *(undefined4 *)(&DAT_7102ebfae0 + lVar11);
    *(undefined4 *)(lVar12 + 0x5a0) = *(undefined4 *)(&DAT_7102ebfb70 + lVar11);
    *(undefined4 *)(*param_1 + 0x5a4) = uVar23;
    lVar12 = *param_1;
    cVar5 = *(char *)(lVar12 + 0x10fc);
  }
  else {
    lVar12 = *param_1;
    cVar5 = *(char *)(lVar12 + 0x10fc);
  }
  if ((ulong)(long)cVar5 < 4) {
    lVar11 = (long)cVar5 * 4;
    uVar23 = *(undefined4 *)(&DAT_7102ebfae0 + lVar11);
    *(undefined4 *)(lVar12 + 0x5f0) = *(undefined4 *)(&DAT_7102ebfb70 + lVar11);
    *(undefined4 *)(*param_1 + 0x5f4) = uVar23;
    lVar12 = *param_1;
    cVar5 = *(char *)(lVar12 + 0x110c);
  }
  else {
    lVar12 = *param_1;
    cVar5 = *(char *)(lVar12 + 0x110c);
  }
  if ((ulong)(long)cVar5 < 4) {
    lVar11 = (long)cVar5 * 4;
    uVar23 = *(undefined4 *)(&DAT_7102ebfae0 + lVar11);
    *(undefined4 *)(lVar12 + 0x640) = *(undefined4 *)(&DAT_7102ebfb70 + lVar11);
    *(undefined4 *)(*param_1 + 0x644) = uVar23;
    lVar12 = *param_1;
    cVar5 = *(char *)(lVar12 + 0x111c);
  }
  else {
    lVar12 = *param_1;
    cVar5 = *(char *)(lVar12 + 0x111c);
  }
  if ((ulong)(long)cVar5 < 4) {
    lVar11 = (long)cVar5 * 4;
    uVar23 = *(undefined4 *)(&DAT_7102ebfae0 + lVar11);
    *(undefined4 *)(lVar12 + 0x690) = *(undefined4 *)(&DAT_7102ebfb70 + lVar11);
    *(undefined4 *)(*param_1 + 0x694) = uVar23;
    lVar12 = *param_1;
    cVar5 = *(char *)(lVar12 + 0x10c9);
  }
  else {
    lVar12 = *param_1;
    cVar5 = *(char *)(lVar12 + 0x10c9);
  }
  if (cVar5 == '\0') {
    *(undefined4 *)(lVar12 + 0x4c8) = 0;
    *(undefined4 *)(*param_1 + 0x4cc) = 0;
    *(undefined4 *)(*param_1 + 0x4c0) = 0;
    *(undefined4 *)(*param_1 + 0x4c4) = 0;
    *(undefined4 *)(*param_1 + 0x4d0) = 0;
    *(undefined4 *)(*param_1 + 0x4d4) = 0;
    lVar12 = *param_1;
    cVar5 = *(char *)(lVar12 + 0x10d9);
  }
  else {
    cVar5 = *(char *)(lVar12 + 0x10d9);
  }
  if (cVar5 == '\0') {
    *(undefined4 *)(lVar12 + 0x518) = 0;
    *(undefined4 *)(*param_1 + 0x51c) = 0;
    *(undefined4 *)(*param_1 + 0x510) = 0;
    *(undefined4 *)(*param_1 + 0x514) = 0;
    *(undefined4 *)(*param_1 + 0x520) = 0;
    *(undefined4 *)(*param_1 + 0x524) = 0;
    lVar12 = *param_1;
    cVar5 = *(char *)(lVar12 + 0x10e9);
  }
  else {
    cVar5 = *(char *)(lVar12 + 0x10e9);
  }
  if (cVar5 == '\0') {
    *(undefined4 *)(lVar12 + 0x568) = 0;
    *(undefined4 *)(*param_1 + 0x56c) = 0;
    *(undefined4 *)(*param_1 + 0x560) = 0;
    *(undefined4 *)(*param_1 + 0x564) = 0;
    *(undefined4 *)(*param_1 + 0x570) = 0;
    *(undefined4 *)(*param_1 + 0x574) = 0;
    lVar12 = *param_1;
    cVar5 = *(char *)(lVar12 + 0x10f9);
  }
  else {
    cVar5 = *(char *)(lVar12 + 0x10f9);
  }
  if (cVar5 == '\0') {
    *(undefined4 *)(lVar12 + 0x5b8) = 0;
    *(undefined4 *)(*param_1 + 0x5bc) = 0;
    *(undefined4 *)(*param_1 + 0x5b0) = 0;
    *(undefined4 *)(*param_1 + 0x5b4) = 0;
    *(undefined4 *)(*param_1 + 0x5c0) = 0;
    *(undefined4 *)(*param_1 + 0x5c4) = 0;
    lVar12 = *param_1;
    cVar5 = *(char *)(lVar12 + 0x1109);
  }
  else {
    cVar5 = *(char *)(lVar12 + 0x1109);
  }
  if (cVar5 == '\0') {
    *(undefined4 *)(lVar12 + 0x608) = 0;
    *(undefined4 *)(*param_1 + 0x60c) = 0;
    *(undefined4 *)(*param_1 + 0x600) = 0;
    *(undefined4 *)(*param_1 + 0x604) = 0;
    *(undefined4 *)(*param_1 + 0x610) = 0;
    *(undefined4 *)(*param_1 + 0x614) = 0;
    lVar12 = *param_1;
    cVar5 = *(char *)(lVar12 + 0x1119);
  }
  else {
    cVar5 = *(char *)(lVar12 + 0x1119);
  }
  if (cVar5 == '\0') {
    *(undefined4 *)(lVar12 + 0x658) = 0;
    *(undefined4 *)(*param_1 + 0x65c) = 0;
    *(undefined4 *)(*param_1 + 0x650) = 0;
    *(undefined4 *)(*param_1 + 0x654) = 0;
    *(undefined4 *)(*param_1 + 0x660) = 0;
    *(undefined4 *)(*param_1 + 0x664) = 0;
    lVar12 = *param_1;
    cVar5 = *(char *)(lVar12 + 0x10ca);
  }
  else {
    cVar5 = *(char *)(lVar12 + 0x10ca);
  }
  if (cVar5 == '\0') {
    *(undefined4 *)(lVar12 + 0x4f0) = 0;
    *(undefined4 *)(*param_1 + 0x4f4) = 0;
    *(undefined4 *)(*param_1 + 0x4f8) = 0;
    lVar12 = *param_1;
    cVar5 = *(char *)(lVar12 + 0x10da);
  }
  else {
    cVar5 = *(char *)(lVar12 + 0x10da);
  }
  if (cVar5 == '\0') {
    *(undefined4 *)(lVar12 + 0x540) = 0;
    *(undefined4 *)(*param_1 + 0x544) = 0;
    *(undefined4 *)(*param_1 + 0x548) = 0;
    lVar12 = *param_1;
    cVar5 = *(char *)(lVar12 + 0x10ea);
  }
  else {
    cVar5 = *(char *)(lVar12 + 0x10ea);
  }
  if (cVar5 == '\0') {
    *(undefined4 *)(lVar12 + 0x590) = 0;
    *(undefined4 *)(*param_1 + 0x594) = 0;
    *(undefined4 *)(*param_1 + 0x598) = 0;
    lVar12 = *param_1;
    cVar5 = *(char *)(lVar12 + 0x10fa);
  }
  else {
    cVar5 = *(char *)(lVar12 + 0x10fa);
  }
  if (cVar5 == '\0') {
    *(undefined4 *)(lVar12 + 0x5e0) = 0;
    *(undefined4 *)(*param_1 + 0x5e4) = 0;
    *(undefined4 *)(*param_1 + 0x5e8) = 0;
    lVar12 = *param_1;
    cVar5 = *(char *)(lVar12 + 0x110a);
  }
  else {
    cVar5 = *(char *)(lVar12 + 0x110a);
  }
  if (cVar5 == '\0') {
    *(undefined4 *)(lVar12 + 0x630) = 0;
    *(undefined4 *)(*param_1 + 0x634) = 0;
    *(undefined4 *)(*param_1 + 0x638) = 0;
    lVar12 = *param_1;
    cVar5 = *(char *)(lVar12 + 0x111a);
  }
  else {
    cVar5 = *(char *)(lVar12 + 0x111a);
  }
  if (cVar5 == '\0') {
    *(undefined4 *)(lVar12 + 0x680) = 0;
    *(undefined4 *)(*param_1 + 0x684) = 0;
    *(undefined4 *)(*param_1 + 0x688) = 0;
    lVar12 = *param_1;
    cVar5 = *(char *)(lVar12 + 0x10cb);
  }
  else {
    cVar5 = *(char *)(lVar12 + 0x10cb);
  }
  if (cVar5 == '\0') {
    *(undefined4 *)(lVar12 + 0x4e0) = 0x3f800000;
    *(undefined4 *)(*param_1 + 0x4e4) = 0x3f800000;
    *(undefined4 *)(*param_1 + 0x4d8) = 0;
    *(undefined4 *)(*param_1 + 0x4dc) = 0;
    *(undefined4 *)(*param_1 + 0x4e8) = 0;
    *(undefined4 *)(*param_1 + 0x4ec) = 0;
    lVar12 = *param_1;
    cVar5 = *(char *)(lVar12 + 0x10db);
  }
  else {
    cVar5 = *(char *)(lVar12 + 0x10db);
  }
  if (cVar5 == '\0') {
    *(undefined4 *)(lVar12 + 0x530) = 0x3f800000;
    *(undefined4 *)(*param_1 + 0x534) = 0x3f800000;
    *(undefined4 *)(*param_1 + 0x528) = 0;
    *(undefined4 *)(*param_1 + 0x52c) = 0;
    *(undefined4 *)(*param_1 + 0x538) = 0;
    *(undefined4 *)(*param_1 + 0x53c) = 0;
    lVar12 = *param_1;
    cVar5 = *(char *)(lVar12 + 0x10eb);
  }
  else {
    cVar5 = *(char *)(lVar12 + 0x10eb);
  }
  if (cVar5 == '\0') {
    *(undefined4 *)(lVar12 + 0x580) = 0x3f800000;
    *(undefined4 *)(*param_1 + 0x584) = 0x3f800000;
    *(undefined4 *)(*param_1 + 0x578) = 0;
    *(undefined4 *)(*param_1 + 0x57c) = 0;
    *(undefined4 *)(*param_1 + 0x588) = 0;
    *(undefined4 *)(*param_1 + 0x58c) = 0;
    lVar12 = *param_1;
    cVar5 = *(char *)(lVar12 + 0x10fb);
  }
  else {
    cVar5 = *(char *)(lVar12 + 0x10fb);
  }
  if (cVar5 == '\0') {
    *(undefined4 *)(lVar12 + 0x5d0) = 0x3f800000;
    *(undefined4 *)(*param_1 + 0x5d4) = 0x3f800000;
    *(undefined4 *)(*param_1 + 0x5c8) = 0;
    *(undefined4 *)(*param_1 + 0x5cc) = 0;
    *(undefined4 *)(*param_1 + 0x5d8) = 0;
    *(undefined4 *)(*param_1 + 0x5dc) = 0;
    lVar12 = *param_1;
    cVar5 = *(char *)(lVar12 + 0x110b);
  }
  else {
    cVar5 = *(char *)(lVar12 + 0x110b);
  }
  if (cVar5 == '\0') {
    *(undefined4 *)(lVar12 + 0x620) = 0x3f800000;
    *(undefined4 *)(*param_1 + 0x624) = 0x3f800000;
    *(undefined4 *)(*param_1 + 0x618) = 0;
    *(undefined4 *)(*param_1 + 0x61c) = 0;
    *(undefined4 *)(*param_1 + 0x628) = 0;
    *(undefined4 *)(*param_1 + 0x62c) = 0;
    lVar12 = *param_1;
    cVar5 = *(char *)(lVar12 + 0x111b);
  }
  else {
    cVar5 = *(char *)(lVar12 + 0x111b);
  }
  if (cVar5 == '\0') {
    *(undefined4 *)(lVar12 + 0x670) = 0x3f800000;
    *(undefined4 *)(*param_1 + 0x674) = 0x3f800000;
    *(undefined4 *)(*param_1 + 0x668) = 0;
    *(undefined4 *)(*param_1 + 0x66c) = 0;
    *(undefined4 *)(*param_1 + 0x678) = 0;
    *(undefined4 *)(*param_1 + 0x67c) = 0;
    lVar12 = *param_1;
    cVar5 = *(char *)(lVar12 + 0xe20);
  }
  else {
    cVar5 = *(char *)(lVar12 + 0xe20);
  }
  if (cVar5 == '\0') {
    *(undefined4 *)(lVar12 + 0xc30) = 0;
    *(undefined4 *)(*param_1 + 0xc40) = 0;
    *(undefined4 *)(*param_1 + 0xc50) = 0;
    *(undefined4 *)(*param_1 + 0xc60) = 0;
    *(undefined4 *)(*param_1 + 0xc80) = 0;
    *(undefined4 *)(*param_1 + 0xc90) = 0x3f800000;
    *(undefined4 *)(*param_1 + 0xca0) = 0;
    *(undefined4 *)(*param_1 + 0xcb0) = 0;
    lVar12 = *param_1;
    cVar5 = *(char *)(lVar12 + 0xe21);
  }
  else {
    cVar5 = *(char *)(lVar12 + 0xe21);
  }
  if (cVar5 == '\0') {
    *(undefined4 *)(lVar12 + 0xc34) = 0;
    *(undefined4 *)(*param_1 + 0xc44) = 0;
    *(undefined4 *)(*param_1 + 0xc54) = 0;
    *(undefined4 *)(*param_1 + 0xc64) = 0;
    *(undefined4 *)(*param_1 + 0xc84) = 0;
    *(undefined4 *)(*param_1 + 0xc94) = 0x3f800000;
    *(undefined4 *)(*param_1 + 0xca4) = 0;
    *(undefined4 *)(*param_1 + 0xcb4) = 0;
    lVar12 = *param_1;
    cVar5 = *(char *)(lVar12 + 0xe22);
  }
  else {
    cVar5 = *(char *)(lVar12 + 0xe22);
  }
  if (cVar5 == '\0') {
    *(undefined4 *)(lVar12 + 0xc38) = 0;
    *(undefined4 *)(*param_1 + 0xc48) = 0;
    *(undefined4 *)(*param_1 + 0xc58) = 0;
    *(undefined4 *)(*param_1 + 0xc68) = 0;
    *(undefined4 *)(*param_1 + 0xc88) = 0;
    *(undefined4 *)(*param_1 + 0xc98) = 0x3f800000;
    *(undefined4 *)(*param_1 + 0xca8) = 0;
    *(undefined4 *)(*param_1 + 0xcb8) = 0;
    lVar12 = *param_1;
    bVar22 = *(byte *)(lVar12 + 0x10c8);
  }
  else {
    bVar22 = *(byte *)(lVar12 + 0x10c8);
  }
  if (bVar22 - 5 < 2) {
    lVar11 = FUN_71005e7bc0(param_2,*(long *)(lVar12 + 0x1038));
    lVar12 = *param_1;
    if (lVar11 != 0) {
      *(float *)(lVar12 + 0x160) = (float)*(int *)(lVar11 + 0x30);
      lVar12 = *param_1;
    }
  }
  if (*(byte *)(lVar12 + 0x10d8) - 5 < 2) {
    lVar11 = FUN_71005e7bc0(param_2,*(long *)(lVar12 + 0x1050));
    lVar12 = *param_1;
    if (lVar11 != 0) {
      *(float *)(lVar12 + 0x1f0) = (float)*(int *)(lVar11 + 0x30);
      lVar12 = *param_1;
    }
  }
  if (*(byte *)(lVar12 + 0x10e8) - 5 < 2) {
    lVar11 = FUN_71005e7bc0(param_2,*(long *)(lVar12 + 0x1068));
    lVar12 = *param_1;
    if (lVar11 != 0) {
      *(float *)(lVar12 + 0x280) = (float)*(int *)(lVar11 + 0x30);
      lVar12 = *param_1;
    }
  }
  if (*(byte *)(lVar12 + 0x10f8) - 5 < 2) {
    lVar11 = FUN_71005e7bc0(param_2,*(long *)(lVar12 + 0x1080));
    lVar12 = *param_1;
    if (lVar11 != 0) {
      *(float *)(lVar12 + 0x310) = (float)*(int *)(lVar11 + 0x30);
      lVar12 = *param_1;
    }
  }
  if (*(byte *)(lVar12 + 0x1108) - 5 < 2) {
    lVar11 = FUN_71005e7bc0(param_2,*(long *)(lVar12 + 0x1098));
    lVar12 = *param_1;
    if (lVar11 != 0) {
      *(float *)(lVar12 + 0x3a0) = (float)*(int *)(lVar11 + 0x30);
      lVar12 = *param_1;
    }
  }
  if (*(byte *)(lVar12 + 0x1118) - 5 < 2) {
    lVar11 = FUN_71005e7bc0(param_2,*(long *)(lVar12 + 0x10b0));
    lVar12 = *param_1;
    if (lVar11 != 0) {
      *(float *)(lVar12 + 0x430) = (float)*(int *)(lVar11 + 0x30);
      lVar12 = *param_1;
    }
  }
  uVar14 = (ulong)*(uint *)(lVar12 + 0x80);
  if (*(uint *)(lVar12 + 0x80) - 1 < 7) {
    lVar12 = uVar14 * 0x10 + 0x6b0;
    do {
      lVar18 = *param_1;
      iVar24 = (int)uVar14;
      uVar14 = (ulong)(iVar24 + 1);
      lVar11 = lVar18 + (long)*(int *)(lVar18 + 0x80) * 0x10;
      uVar19 = *(undefined8 *)(lVar11 + 0x6a8);
      *(undefined8 *)(lVar18 + lVar12) = *(undefined8 *)(lVar11 + 0x6a0);
      ((undefined8 *)(lVar18 + lVar12))[1] = uVar19;
      lVar11 = *param_1 + lVar12;
      lVar12 = lVar12 + 0x10;
      *(float *)(lVar11 + 0xc) = *(float *)(lVar11 + 0xc) + (float)iVar24;
    } while (iVar24 < 7);
    lVar12 = *param_1;
    uVar13 = *(uint *)(lVar12 + 0x88);
  }
  else {
    uVar13 = *(uint *)(lVar12 + 0x88);
  }
  if (uVar13 - 1 < 7) {
    uVar14 = (ulong)uVar13;
    lVar12 = uVar14 * 0x10 + 0x7b0;
    do {
      lVar18 = *param_1;
      iVar24 = (int)uVar14;
      uVar14 = (ulong)(iVar24 + 1);
      lVar11 = lVar18 + (long)*(int *)(lVar18 + 0x88) * 0x10;
      uVar19 = *(undefined8 *)(lVar11 + 0x7a8);
      *(undefined8 *)(lVar18 + lVar12) = *(undefined8 *)(lVar11 + 0x7a0);
      ((undefined8 *)(lVar18 + lVar12))[1] = uVar19;
      lVar11 = *param_1 + lVar12;
      lVar12 = lVar12 + 0x10;
      *(float *)(lVar11 + 0xc) = *(float *)(lVar11 + 0xc) + (float)iVar24;
    } while (iVar24 < 7);
    lVar12 = *param_1;
    uVar13 = *(uint *)(lVar12 + 0x84);
  }
  else {
    uVar13 = *(uint *)(lVar12 + 0x84);
  }
  if (uVar13 - 1 < 7) {
    uVar14 = (ulong)uVar13;
    lVar12 = uVar14 * 0x10 + 0x730;
    do {
      lVar18 = *param_1;
      iVar24 = (int)uVar14;
      uVar14 = (ulong)(iVar24 + 1);
      lVar11 = lVar18 + (long)*(int *)(lVar18 + 0x84) * 0x10;
      uVar19 = *(undefined8 *)(lVar11 + 0x728);
      *(undefined8 *)(lVar18 + lVar12) = *(undefined8 *)(lVar11 + 0x720);
      ((undefined8 *)(lVar18 + lVar12))[1] = uVar19;
      lVar11 = *param_1 + lVar12;
      lVar12 = lVar12 + 0x10;
      *(float *)(lVar11 + 0xc) = *(float *)(lVar11 + 0xc) + (float)iVar24;
    } while (iVar24 < 7);
    lVar12 = *param_1;
    uVar13 = *(uint *)(lVar12 + 0x8c);
  }
  else {
    uVar13 = *(uint *)(lVar12 + 0x8c);
  }
  if (uVar13 - 1 < 7) {
    uVar14 = (ulong)uVar13;
    lVar12 = uVar14 * 0x10 + 0x830;
    do {
      lVar18 = *param_1;
      iVar24 = (int)uVar14;
      uVar14 = (ulong)(iVar24 + 1);
      lVar11 = lVar18 + (long)*(int *)(lVar18 + 0x8c) * 0x10;
      uVar19 = *(undefined8 *)(lVar11 + 0x828);
      *(undefined8 *)(lVar18 + lVar12) = *(undefined8 *)(lVar11 + 0x820);
      ((undefined8 *)(lVar18 + lVar12))[1] = uVar19;
      lVar11 = *param_1 + lVar12;
      lVar12 = lVar12 + 0x10;
      *(float *)(lVar11 + 0xc) = *(float *)(lVar11 + 0xc) + (float)iVar24;
    } while (iVar24 < 7);
    lVar12 = *param_1;
    uVar13 = *(uint *)(lVar12 + 0x90);
  }
  else {
    uVar13 = *(uint *)(lVar12 + 0x90);
  }
  if (uVar13 - 1 < 7) {
    uVar14 = (ulong)uVar13;
    lVar12 = uVar14 * 0x10 + 0x8f0;
    do {
      lVar18 = *param_1;
      iVar24 = (int)uVar14;
      uVar14 = (ulong)(iVar24 + 1);
      lVar11 = lVar18 + (long)*(int *)(lVar18 + 0x90) * 0x10;
      uVar19 = *(undefined8 *)(lVar11 + 0x8e8);
      *(undefined8 *)(lVar18 + lVar12) = *(undefined8 *)(lVar11 + 0x8e0);
      ((undefined8 *)(lVar18 + lVar12))[1] = uVar19;
      lVar11 = *param_1 + lVar12;
      lVar12 = lVar12 + 0x10;
      *(float *)(lVar11 + 0xc) = *(float *)(lVar11 + 0xc) + (float)iVar24;
    } while (iVar24 < 7);
    lVar12 = *param_1;
    uVar13 = *(uint *)(lVar12 + 0x94);
  }
  else {
    uVar13 = *(uint *)(lVar12 + 0x94);
  }
  if (uVar13 - 1 < 7) {
    uVar14 = (ulong)uVar13;
    lVar12 = uVar14 * 0x10 + 0x970;
    do {
      lVar18 = *param_1;
      iVar24 = (int)uVar14;
      uVar14 = (ulong)(iVar24 + 1);
      lVar11 = lVar18 + (long)*(int *)(lVar18 + 0x94) * 0x10;
      uVar19 = *(undefined8 *)(lVar11 + 0x968);
      *(undefined8 *)(lVar18 + lVar12) = *(undefined8 *)(lVar11 + 0x960);
      ((undefined8 *)(lVar18 + lVar12))[1] = uVar19;
      lVar11 = *param_1 + lVar12;
      lVar12 = lVar12 + 0x10;
      *(float *)(lVar11 + 0xc) = *(float *)(lVar11 + 0xc) + (float)iVar24;
    } while (iVar24 < 7);
    lVar12 = *param_1;
    uVar13 = *(uint *)(lVar12 + 0x98);
  }
  else {
    uVar13 = *(uint *)(lVar12 + 0x98);
  }
  if (uVar13 - 1 < 7) {
    uVar14 = (ulong)uVar13;
    lVar12 = uVar14 * 0x10 + 0x9f0;
    do {
      lVar18 = *param_1;
      iVar24 = (int)uVar14;
      uVar14 = (ulong)(iVar24 + 1);
      lVar11 = lVar18 + (long)*(int *)(lVar18 + 0x98) * 0x10;
      uVar19 = *(undefined8 *)(lVar11 + 0x9e8);
      *(undefined8 *)(lVar18 + lVar12) = *(undefined8 *)(lVar11 + 0x9e0);
      ((undefined8 *)(lVar18 + lVar12))[1] = uVar19;
      lVar11 = *param_1 + lVar12;
      lVar12 = lVar12 + 0x10;
      *(float *)(lVar11 + 0xc) = *(float *)(lVar11 + 0xc) + (float)iVar24;
    } while (iVar24 < 7);
    lVar12 = *param_1;
    uVar13 = *(uint *)(lVar12 + 0x9c);
  }
  else {
    uVar13 = *(uint *)(lVar12 + 0x9c);
  }
  if (uVar13 - 2 < 6) {
    uVar14 = (ulong)uVar13;
    lVar12 = uVar14 * 0x10 + 0xa70;
    do {
      lVar18 = *param_1;
      iVar24 = (int)uVar14;
      uVar14 = (ulong)(iVar24 + 1);
      lVar11 = lVar18 + (long)*(int *)(lVar18 + 0x9c) * 0x10;
      uVar19 = *(undefined8 *)(lVar11 + 0xa68);
      *(undefined8 *)(lVar18 + lVar12) = *(undefined8 *)(lVar11 + 0xa60);
      ((undefined8 *)(lVar18 + lVar12))[1] = uVar19;
      lVar11 = *param_1 + lVar12;
      lVar12 = lVar12 + 0x10;
      *(float *)(lVar11 + 0xc) = *(float *)(lVar11 + 0xc) + (float)iVar24;
    } while (iVar24 < 7);
    lVar12 = *param_1;
    uVar13 = *(uint *)(lVar12 + 0xa0);
  }
  else {
    uVar13 = *(uint *)(lVar12 + 0xa0);
  }
  if (uVar13 - 2 < 6) {
    uVar14 = (ulong)uVar13;
    lVar12 = uVar14 * 0x10 + 0xaf0;
    do {
      lVar18 = *param_1;
      iVar24 = (int)uVar14;
      uVar14 = (ulong)(iVar24 + 1);
      lVar11 = lVar18 + (long)*(int *)(lVar18 + 0xa0) * 0x10;
      uVar19 = *(undefined8 *)(lVar11 + 0xae8);
      *(undefined8 *)(lVar18 + lVar12) = *(undefined8 *)(lVar11 + 0xae0);
      ((undefined8 *)(lVar18 + lVar12))[1] = uVar19;
      lVar11 = *param_1 + lVar12;
      lVar12 = lVar12 + 0x10;
      *(float *)(lVar11 + 0xc) = *(float *)(lVar11 + 0xc) + (float)iVar24;
    } while (iVar24 < 7);
    lVar12 = *param_1;
    uVar13 = *(uint *)(lVar12 + 0xa4);
  }
  else {
    uVar13 = *(uint *)(lVar12 + 0xa4);
  }
  if (uVar13 - 2 < 6) {
    uVar14 = (ulong)uVar13;
    lVar12 = uVar14 * 0x10 + 0xb70;
    do {
      lVar18 = *param_1;
      iVar24 = (int)uVar14;
      uVar14 = (ulong)(iVar24 + 1);
      lVar11 = lVar18 + (long)*(int *)(lVar18 + 0xa4) * 0x10;
      uVar19 = *(undefined8 *)(lVar11 + 0xb68);
      *(undefined8 *)(lVar18 + lVar12) = *(undefined8 *)(lVar11 + 0xb60);
      ((undefined8 *)(lVar18 + lVar12))[1] = uVar19;
      lVar11 = *param_1 + lVar12;
      lVar12 = lVar12 + 0x10;
      *(float *)(lVar11 + 0xc) = *(float *)(lVar11 + 0xc) + (float)iVar24;
    } while (iVar24 < 7);
    lVar12 = *param_1;
    cVar5 = *(char *)(lVar12 + 0xe48);
  }
  else {
    cVar5 = *(char *)(lVar12 + 0xe48);
  }
  uVar23 = 0;
  if (cVar5 != '\0') {
    uVar23 = NEON_ucvtf((uint)*(ushort *)(lVar12 + 0xe5c));
  }
  uVar25 = 0;
  *(undefined4 *)(lVar12 + 0xb0) = uVar23;
  uVar23 = 0;
  if (*(char *)(*param_1 + 0xe51) != '\0') {
    uVar23 = 0x3f800000;
  }
  *(undefined4 *)(*param_1 + 0xc4) = uVar23;
  lVar12 = *param_1;
  if (*(char *)(lVar12 + 0xe49) != '\0') {
    uVar25 = NEON_ucvtf((uint)*(ushort *)(lVar12 + 0xe5e));
  }
  *(undefined4 *)(lVar12 + 0xb4) = uVar25;
  uVar23 = 0;
  uVar25 = 0;
  if (*(char *)(*param_1 + 0xe52) != '\0') {
    uVar25 = 0x3f800000;
  }
  *(undefined4 *)(*param_1 + 200) = uVar25;
  uVar25 = 0;
  lVar12 = *param_1;
  if (*(char *)(lVar12 + 0xe4a) != '\0') {
    uVar25 = NEON_ucvtf((uint)*(ushort *)(lVar12 + 0xe60));
  }
  *(undefined4 *)(lVar12 + 0xb8) = uVar25;
  uVar25 = 0;
  if (*(char *)(*param_1 + 0xe53) != '\0') {
    uVar25 = 0x3f800000;
  }
  *(undefined4 *)(*param_1 + 0xcc) = uVar25;
  lVar12 = *param_1;
  if (*(char *)(lVar12 + 0xe4b) != '\0') {
    uVar23 = NEON_ucvtf((uint)*(ushort *)(lVar12 + 0xe62));
  }
  *(undefined4 *)(lVar12 + 0xbc) = uVar23;
  fVar26 = 0.0;
  uVar23 = 0;
  if (*(char *)(*param_1 + 0xe54) != '\0') {
    uVar23 = 0x3f800000;
  }
  *(undefined4 *)(*param_1 + 0xd0) = uVar23;
  fVar31 = 0.0;
  lVar12 = *param_1;
  if (*(char *)(lVar12 + 0xe4c) != '\0') {
    fVar31 = (float)*(int *)(lVar12 + 0xe64);
  }
  *(float *)(lVar12 + 0xc0) = fVar31;
  uVar23 = 0;
  if (*(char *)(*param_1 + 0xe55) != '\0') {
    uVar23 = 0x3f800000;
  }
  *(undefined4 *)(*param_1 + 0xd4) = uVar23;
  lVar12 = *param_1;
  if (*(char *)(lVar12 + 0xe4d) != '\0') {
    fVar26 = (float)*(int *)(lVar12 + 0xe68);
  }
  *(float *)(lVar12 + 0xe0) = fVar26;
  fVar26 = 0.0;
  uVar23 = 0;
  if (*(char *)(*param_1 + 0xe56) != '\0') {
    uVar23 = 0x3f800000;
  }
  *(undefined4 *)(*param_1 + 0xf0) = uVar23;
  fVar31 = 0.0;
  lVar12 = *param_1;
  if (*(char *)(lVar12 + 0xe4e) != '\0') {
    fVar31 = (float)*(int *)(lVar12 + 0xe6c);
  }
  *(float *)(lVar12 + 0xe4) = fVar31;
  uVar23 = 0;
  if (*(char *)(*param_1 + 0xe57) != '\0') {
    uVar23 = 0x3f800000;
  }
  *(undefined4 *)(*param_1 + 0xf4) = uVar23;
  lVar12 = *param_1;
  if (*(char *)(lVar12 + 0xe4f) != '\0') {
    fVar26 = (float)*(int *)(lVar12 + 0xe70);
  }
  *(float *)(lVar12 + 0xe8) = fVar26;
  uVar23 = 0;
  if (*(char *)(*param_1 + 0xe58) != '\0') {
    uVar23 = 0x3f800000;
  }
  *(undefined4 *)(*param_1 + 0xf8) = uVar23;
  fVar26 = 0.0;
  lVar12 = *param_1;
  if (*(char *)(lVar12 + 0xe50) != '\0') {
    fVar26 = (float)*(int *)(lVar12 + 0xe74);
  }
  *(float *)(lVar12 + 0xec) = fVar26;
  uVar23 = 0;
  if (*(char *)(*param_1 + 0xe59) != '\0') {
    uVar23 = 0x3f800000;
  }
  *(undefined4 *)(*param_1 + 0xfc) = uVar23;
  bVar22 = *(byte *)(*param_1 + 0xdb0);
  if ((0xf < bVar22) || (uVar13 = (uint)bVar22, (1 << (ulong)(uVar13 & 0x1f) & 0xa064U) == 0)) {
    *(undefined4 *)(*param_1 + 0xdec) = 0xffffffff;
    uVar13 = (uint)*(byte *)(*param_1 + 0xdb0);
  }
  if (0xd < uVar13 - 2) {
    local_3c[0] = 0;
    local_3c[1] = 0;
    local_3c[2] = 0;
    FUN_71005d7160(local_3c,param_1);
    *(uint *)(*param_1 + 0x70) = local_3c[0];
    *(uint *)(*param_1 + 0x74) = local_3c[1];
    *(uint *)(*param_1 + 0x78) = local_3c[2];
    if ((undefined4 *)param_1[0x84] != (undefined4 *)0x0) {
      *(undefined4 *)(*param_1 + 0x7c) = *(undefined4 *)param_1[0x84];
    }
    lVar12 = *param_1;
    auVar10 = *(undefined1 (*) [12])(lVar12 + 0xcf8);
    uVar13 = *(uint *)(lVar12 + 0xce8);
    lVar11 = *(long *)(lVar12 + 0xce0);
    fVar31 = *DAT_7103a66e88;
    fVar26 = *DAT_7103a66e90;
    auVar27._0_4_ = auVar10._0_4_ - (float)(int)(auVar10._0_4_ * fVar31) * fVar26;
    auVar27._4_4_ = auVar10._4_4_ - (float)(int)(auVar10._4_4_ * fVar31) * fVar26;
    auVar27._8_4_ = auVar10._8_4_ - (float)(int)(auVar10._8_4_ * fVar31) * fVar26;
    auVar27._12_4_ = 0.0 - (float)(int)(fVar31 * 0.0) * fVar26;
    fVar26 = *DAT_7103a66e68;
    fVar44 = *DAT_7103a66e70;
    fVar32 = -fVar26;
    fVar45 = -fVar44;
    iVar24 = -(uint)(fVar26 < auVar27._0_4_);
    iVar6 = -(uint)(fVar26 < auVar27._4_4_);
    bVar22 = (byte)((uint)iVar6 >> 8);
    bVar36 = (byte)((uint)iVar6 >> 0x10);
    bVar37 = (byte)((uint)iVar6 >> 0x18);
    iVar7 = -(uint)(fVar26 < auVar27._8_4_);
    bVar38 = (byte)((uint)iVar7 >> 8);
    bVar39 = (byte)((uint)iVar7 >> 0x10);
    bVar40 = (byte)((uint)iVar7 >> 0x18);
    iVar8 = -(uint)(fVar26 < auVar27._12_4_);
    bVar41 = (byte)((uint)iVar8 >> 8);
    bVar42 = (byte)((uint)iVar8 >> 0x10);
    bVar43 = (byte)((uint)iVar8 >> 0x18);
    fVar31 = DAT_7103a66e78[1];
    fVar21 = DAT_7103a66e78[3];
    auVar54._0_4_ = fVar44 - auVar27._0_4_;
    auVar54._4_4_ = fVar44 - auVar27._4_4_;
    auVar54._8_4_ = fVar44 - auVar27._8_4_;
    auVar54._12_4_ = fVar44 - auVar27._12_4_;
    auVar55[4] = (byte)iVar6;
    auVar55._0_4_ = iVar24;
    auVar55[5] = bVar22;
    auVar55[6] = bVar36;
    auVar55[7] = bVar37;
    auVar55[8] = (byte)iVar7;
    auVar55[9] = bVar38;
    auVar55[10] = bVar39;
    auVar55[0xb] = bVar40;
    auVar55[0xc] = (byte)iVar8;
    auVar55[0xd] = bVar41;
    auVar55[0xe] = bVar42;
    auVar55[0xf] = bVar43;
    auVar27 = auVar27 ^ (auVar27 ^ auVar54) & auVar55;
    fVar50 = *DAT_7103a66e78;
    auVar33._0_4_ = -(uint)(auVar27._0_4_ < fVar32);
    auVar33._4_4_ = -(uint)(auVar27._4_4_ < fVar32);
    auVar33._8_4_ = -(uint)(auVar27._8_4_ < fVar32);
    auVar33._12_4_ = -(uint)(auVar27._12_4_ < fVar32);
    auVar9._4_4_ = fVar45 - auVar27._4_4_;
    auVar9._0_4_ = fVar45 - auVar27._0_4_;
    auVar9._8_4_ = fVar45 - auVar27._8_4_;
    auVar9._12_4_ = fVar45 - auVar27._12_4_;
    auVar27 = auVar27 ^ (auVar27 ^ auVar9) & auVar33;
    auVar34[0] = (byte)auVar33._0_4_ | (byte)iVar24;
    auVar34[1] = (byte)((uint)auVar33._0_4_ >> 8) | (byte)((uint)iVar24 >> 8);
    auVar34[2] = (byte)((uint)auVar33._0_4_ >> 0x10) | (byte)((uint)iVar24 >> 0x10);
    auVar34[3] = (byte)((uint)auVar33._0_4_ >> 0x18) | (byte)((uint)iVar24 >> 0x18);
    auVar34[4] = (byte)auVar33._4_4_ | (byte)iVar6;
    auVar34[5] = (byte)((uint)auVar33._4_4_ >> 8) | bVar22;
    auVar34[6] = (byte)((uint)auVar33._4_4_ >> 0x10) | bVar36;
    auVar34[7] = (byte)((uint)auVar33._4_4_ >> 0x18) | bVar37;
    auVar34[8] = (byte)auVar33._8_4_ | (byte)iVar7;
    auVar34[9] = (byte)((uint)auVar33._8_4_ >> 8) | bVar38;
    auVar34[10] = (byte)((uint)auVar33._8_4_ >> 0x10) | bVar39;
    auVar34[0xb] = (byte)((uint)auVar33._8_4_ >> 0x18) | bVar40;
    auVar34[0xc] = (byte)auVar33._12_4_ | (byte)iVar8;
    auVar34[0xd] = (byte)((uint)auVar33._12_4_ >> 8) | bVar41;
    auVar34[0xe] = (byte)((uint)auVar33._12_4_ >> 0x10) | bVar42;
    auVar34[0xf] = (byte)((uint)auVar33._12_4_ >> 0x18) | bVar43;
    fVar26 = *DAT_7103a66e80;
    fVar45 = auVar27._0_4_;
    fVar46 = fVar45 * fVar45;
    fVar30 = auVar27._4_4_;
    fVar47 = fVar30 * fVar30;
    fVar29 = auVar27._8_4_;
    fVar48 = fVar29 * fVar29;
    fVar53 = auVar27._12_4_;
    fVar49 = fVar53 * fVar53;
    fVar51 = -DAT_7103a66e78[2];
    fVar52 = -DAT_7103a66e78[4];
    auVar55 = NEON_fmov(0x3f800000,4);
    fVar32 = DAT_7103a66e80[1];
    fVar44 = DAT_7103a66e80[3];
    auVar28._0_4_ =
         fVar45 * (auVar55._0_4_ +
                  fVar46 * (fVar52 + fVar46 * (fVar21 + fVar46 * (fVar51 + fVar46 * (fVar31 - fVar46
                                                                                              * 
                                                  fVar50)))));
    auVar28._4_4_ =
         fVar30 * (auVar55._4_4_ +
                  fVar47 * (fVar52 + fVar47 * (fVar21 + fVar47 * (fVar51 + fVar47 * (fVar31 - fVar47
                                                                                              * 
                                                  fVar50)))));
    auVar28._8_4_ =
         fVar29 * (auVar55._8_4_ +
                  fVar48 * (fVar52 + fVar48 * (fVar21 + fVar48 * (fVar51 + fVar48 * (fVar31 - fVar48
                                                                                              * 
                                                  fVar50)))));
    auVar28._12_4_ =
         fVar53 * (auVar55._12_4_ +
                  fVar49 * (fVar52 + fVar49 * (fVar21 + fVar49 * (fVar51 + fVar49 * (fVar31 - fVar49
                                                                                              * 
                                                  fVar50)))));
    fVar31 = -DAT_7103a66e80[2];
    fVar21 = -DAT_7103a66e80[4];
    auVar35._0_4_ =
         auVar55._0_4_ +
         fVar46 * (fVar21 + fVar46 * (fVar44 + fVar46 * (fVar31 + fVar46 * (fVar32 - fVar46 * fVar26
                                                                           ))));
    auVar35._4_4_ =
         auVar55._4_4_ +
         fVar47 * (fVar21 + fVar47 * (fVar44 + fVar47 * (fVar31 + fVar47 * (fVar32 - fVar47 * fVar26
                                                                           ))));
    auVar35._8_4_ =
         auVar55._8_4_ +
         fVar48 * (fVar21 + fVar48 * (fVar44 + fVar48 * (fVar31 + fVar48 * (fVar32 - fVar48 * fVar26
                                                                           ))));
    auVar35._12_4_ =
         auVar55._12_4_ +
         fVar49 * (fVar21 + fVar49 * (fVar44 + fVar49 * (fVar31 + fVar49 * (fVar32 - fVar49 * fVar26
                                                                           ))));
    fVar26 = -auVar35._4_4_;
    fVar31 = -auVar35._8_4_;
    fVar21 = -auVar35._12_4_;
    auVar56[4] = SUB41(fVar26,0);
    auVar56._0_4_ = -auVar35._0_4_;
    auVar56[5] = (char)((uint)fVar26 >> 8);
    auVar56[6] = (char)((uint)fVar26 >> 0x10);
    auVar56[7] = (char)((uint)fVar26 >> 0x18);
    auVar56[8] = SUB41(fVar31,0);
    auVar56[9] = (char)((uint)fVar31 >> 8);
    auVar56[10] = (char)((uint)fVar31 >> 0x10);
    auVar56[0xb] = (char)((uint)fVar31 >> 0x18);
    auVar56[0xc] = SUB41(fVar21,0);
    auVar56[0xd] = (char)((uint)fVar21 >> 8);
    auVar56[0xe] = (char)((uint)fVar21 >> 0x10);
    auVar56[0xf] = (char)((uint)fVar21 >> 0x18);
    auVar35 = auVar35 ^ (auVar35 ^ auVar56) & auVar34;
    auVar56 = NEON_ext(auVar28,auVar28,8,1);
    fVar29 = auVar35._4_4_;
    auVar55 = NEON_ext(auVar35,auVar35,8,1);
    fVar31 = auVar55._0_4_;
    fVar21 = auVar56._0_4_;
    fVar30 = auVar35._0_4_;
    fVar49 = (float)*(undefined8 *)(lVar12 + 0xd10);
    fVar26 = *(float *)(lVar12 + 0xd18);
    fVar53 = fVar21 * fVar30 * -1.0 + fVar31 * auVar28._4_4_ * auVar28._0_4_;
    fVar46 = fVar31 * fVar30 * 1.0 + fVar21 * auVar28._4_4_ * auVar28._0_4_;
    fVar47 = fVar30 * 0.0 * 0.0 + fVar29 * 1.0 * auVar28._0_4_;
    fVar48 = fVar30 * 0.0 * 0.0 + auVar28._0_4_ * 0.0;
    fVar32 = fVar21 * auVar28._0_4_ * 1.0 + fVar31 * auVar28._4_4_ * fVar30;
    fVar44 = fVar31 * auVar28._0_4_ * -1.0 + fVar21 * auVar28._4_4_ * fVar30;
    fVar45 = auVar28._0_4_ * 0.0 * 0.0 + fVar29 * 1.0 * fVar30;
    fVar30 = auVar28._0_4_ * 0.0 * 0.0 + fVar30 * 0.0;
    fVar50 = (float)((ulong)*(undefined8 *)(lVar12 + 0xd10) >> 0x20);
    param_1[0x41] = CONCAT44(fVar49 * 0.0,auVar28._4_4_ * -1.0 * fVar49);
    param_1[0x40] = CONCAT44(fVar21 * fVar29 * fVar49,fVar31 * fVar29 * fVar49);
    *(float *)(param_1 + 0x44) = fVar47 * fVar50;
    *(float *)((long)param_1 + 0x224) = fVar48 * fVar50;
    *(float *)(param_1 + 0x42) = fVar53 * fVar50;
    *(float *)((long)param_1 + 0x214) = fVar46 * fVar50;
    *(float *)(param_1 + 0x46) = fVar45 * fVar26;
    *(float *)((long)param_1 + 0x234) = fVar30 * fVar26;
    *(float *)(param_1 + 0x44) = fVar32 * fVar26;
    *(float *)((long)param_1 + 0x224) = fVar44 * fVar26;
    param_1[0x47] = (ulong)uVar13;
    param_1[0x46] = lVar11;
    param_1[0x49] = (ulong)(uint)(auVar28._4_4_ * -1.0);
    param_1[0x48] = CONCAT44(fVar21 * fVar29,fVar31 * fVar29);
    *(float *)(param_1 + 0x4c) = fVar47;
    *(float *)((long)param_1 + 0x264) = fVar48;
    *(float *)(param_1 + 0x4a) = fVar53;
    *(float *)((long)param_1 + 0x254) = fVar46;
    *(float *)(param_1 + 0x4e) = fVar45;
    *(float *)((long)param_1 + 0x274) = fVar30;
    *(float *)(param_1 + 0x4c) = fVar32;
    *(float *)((long)param_1 + 0x264) = fVar44;
    param_1[0x4f] = (ulong)uVar13;
    param_1[0x4e] = lVar11;
    lVar11 = *(long *)(lVar12 + 0xc30);
    param_1[0x51] = (ulong)*(uint *)(lVar12 + 0xc38);
    param_1[0x50] = lVar11;
    if ((*(char *)(lVar12 + 0xe18) == '\0') || (*(char *)(lVar12 + 0xd68) != '\0')) {
      lVar12 = param_1[0x8b];
    }
    else {
      *(undefined1 *)(lVar12 + 0xe18) = 0;
      lVar12 = param_1[0x8b];
    }
    if (lVar12 == 0) {
      *(undefined4 *)(param_1 + 0x1e) = *(undefined4 *)(*param_1 + 0xe28);
      lVar12 = param_1[0x8a];
    }
    else {
      uVar13 = *(uint *)(lVar12 + 4);
      if ((int)uVar13 < 1) {
        *(undefined4 *)(param_1 + 0x1e) = 0;
        lVar12 = param_1[0x8a];
      }
      else {
        if (uVar13 == 1) {
          uVar14 = 0;
          fVar26 = 0.0;
        }
        else {
          fVar26 = 0.0;
          uVar14 = 0;
          pfVar20 = (float *)(lVar12 + 0x1c);
          do {
            uVar14 = uVar14 + 2;
            fVar31 = pfVar20[-4];
            if (pfVar20[-4] <= fVar26) {
              fVar31 = fVar26;
            }
            fVar26 = *pfVar20;
            if (*pfVar20 <= fVar31) {
              fVar26 = fVar31;
            }
            pfVar20 = pfVar20 + 8;
          } while (((ulong)uVar13 & 0xfffffffe) != uVar14);
        }
        fVar31 = fVar26;
        if (((uVar13 & 1) != 0) &&
           (fVar31 = *(float *)(lVar12 + uVar14 * 0x10 + 0xc), fVar31 <= fVar26)) {
          fVar31 = fVar26;
        }
        *(int *)(param_1 + 0x1e) = (int)fVar31;
        lVar12 = param_1[0x8a];
      }
    }
    if (lVar12 == 0) {
      fVar26 = *(float *)(*param_1 + 0xd78);
    }
    else {
      uVar13 = *(uint *)(lVar12 + 4);
      if ((int)uVar13 < 1) {
        fVar26 = 0.0;
      }
      else {
        if (uVar13 == 1) {
          uVar14 = 0;
          fVar31 = 0.0;
        }
        else {
          fVar31 = 0.0;
          uVar14 = 0;
          pfVar20 = (float *)(lVar12 + 0x1c);
          do {
            uVar14 = uVar14 + 2;
            fVar26 = pfVar20[-4];
            if (pfVar20[-4] <= fVar31) {
              fVar26 = fVar31;
            }
            fVar31 = *pfVar20;
            if (*pfVar20 <= fVar26) {
              fVar31 = fVar26;
            }
            pfVar20 = pfVar20 + 8;
          } while (((ulong)uVar13 & 0xfffffffe) != uVar14);
        }
        fVar26 = fVar31;
        if (((uVar13 & 1) != 0) &&
           (fVar26 = *(float *)(lVar12 + uVar14 * 0x10 + 0xc), fVar26 <= fVar31)) {
          fVar26 = fVar31;
        }
      }
    }
    *(float *)((long)param_1 + 0xf4) = fVar26;
    uVar13 = *(uint *)(param_1 + 0x9e);
    lVar12 = FUN_71005fc254(param_1[0xe]);
    if (lVar12 != 0) {
      thunk_EXT_FUN_02e95df0(lVar12 + (ulong)uVar13,*param_1,0xcc0);
      FUN_71005fc26c(param_1[0xe]);
      ret_71005FC268();
    }
    if (param_1[0x3f] != 0) {
      uVar13 = *(uint *)((long)param_1 + 0x4f4);
      lVar12 = FUN_71005fc254(param_1[0xe]);
      if (lVar12 != 0) {
        puVar15 = (undefined8 *)param_1[0x3f];
        puVar1 = (undefined8 *)(lVar12 + (ulong)uVar13);
        uVar19 = *puVar15;
        uVar3 = puVar15[1];
        uVar4 = puVar15[3];
        puVar1[2] = puVar15[2];
        puVar1[3] = uVar4;
        *puVar1 = uVar19;
        puVar1[1] = uVar3;
        uVar19 = puVar15[4];
        uVar3 = puVar15[5];
        uVar4 = puVar15[7];
        puVar1[6] = puVar15[6];
        puVar1[7] = uVar4;
        puVar1[4] = uVar19;
        puVar1[5] = uVar3;
        uVar19 = puVar15[8];
        uVar3 = puVar15[9];
        uVar4 = puVar15[0xb];
        puVar1[10] = puVar15[10];
        puVar1[0xb] = uVar4;
        puVar1[8] = uVar19;
        puVar1[9] = uVar3;
        uVar19 = puVar15[0xc];
        uVar3 = puVar15[0xd];
        uVar4 = puVar15[0xf];
        puVar1[0xe] = puVar15[0xe];
        puVar1[0xf] = uVar4;
        puVar1[0xc] = uVar19;
        puVar1[0xd] = uVar3;
        FUN_71005fc26c(param_1[0xe]);
        ret_71005FC268();
      }
    }
    if (param_1[0x93] != 0) {
      uVar13 = *(uint *)(param_1 + 0x9f);
      lVar12 = FUN_71005fc254(param_1[0xe]);
      if (lVar12 != 0) {
        thunk_EXT_FUN_02e95df0(lVar12 + (ulong)uVar13,param_1[0x93],(int)param_1[0xa0]);
        FUN_71005fc26c(param_1[0xe]);
        ret_71005FC268();
      }
    }
    if (*(char *)((long)param_1 + 0xee) != '\0') {
      uVar13 = *(uint *)((long)param_1 + 0x4fc);
      lVar12 = FUN_71005fc254(param_1[0xe]);
      if (lVar12 != 0) {
        lVar11 = param_1[0x7b];
        puVar2 = (undefined4 *)(lVar12 + (ulong)uVar13);
        if (lVar11 != 0) {
          *puVar2 = *(undefined4 *)(lVar11 + 4);
          puVar2[1] = *(undefined4 *)(lVar11 + 8);
          puVar2[2] = *(undefined4 *)(lVar11 + 0xc);
          puVar2[3] = (float)*(int *)(param_1[0x7b] + 0x10);
          puVar2[4] = *(undefined4 *)(param_1[0x7b] + 0x2c);
          puVar2[5] = *(undefined4 *)(param_1[0x7b] + 0x30);
          puVar2[6] = *(undefined4 *)(param_1[0x7b] + 0x34);
          puVar2[7] = *(undefined4 *)(param_1[0x7b] + 0x38);
          puVar2[8] = *(undefined4 *)(param_1[0x7b] + 0x1c);
          puVar2[9] = *(undefined4 *)(param_1[0x7b] + 0x20);
          puVar2[10] = *(undefined4 *)(param_1[0x7b] + 0x24);
          puVar2[0xb] = *(undefined4 *)(param_1[0x7b] + 0x28);
          uVar23 = NEON_ucvtf((uint)*(byte *)param_1[0x7b]);
          puVar2[0xc] = uVar23;
          uVar23 = NEON_ucvtf((uint)*(byte *)(param_1[0x7b] + 1));
          puVar2[0xd] = uVar23;
          bVar22 = *(byte *)(param_1[0x7b] + 2);
          puVar2[0xf] = 0;
          uVar23 = NEON_ucvtf((uint)bVar22);
          puVar2[0xe] = uVar23;
          puVar2[0x10] = *(undefined4 *)(param_1[0x7b] + 0x14);
          puVar2[0x11] = *(undefined4 *)(param_1[0x7b] + 0x18);
        }
        puVar16 = (undefined4 *)param_1[0x7c];
        if (puVar16 != (undefined4 *)0x0) {
          puVar2[0x14] = *puVar16;
          puVar2[0x15] = puVar16[1];
          puVar2[0x16] = puVar16[2];
          puVar2[0x17] = (float)*(int *)(param_1[0x7c] + 0xc);
        }
        lVar12 = param_1[0x81];
        if (lVar12 != 0) {
          puVar2[0x18] = *(undefined4 *)(lVar12 + 4);
          puVar2[0x19] = *(undefined4 *)(lVar12 + 8);
          puVar2[0x1a] = *(undefined4 *)(lVar12 + 0xc);
          uVar23 = NEON_ucvtf((uint)*(byte *)param_1[0x81]);
          puVar2[0x1b] = uVar23;
        }
        lVar12 = param_1[0x7d];
        if (lVar12 != 0) {
          puVar2[0x1c] = *(undefined4 *)(lVar12 + 8);
          puVar2[0x1d] = *(undefined4 *)(lVar12 + 0xc);
          puVar2[0x1e] = *(undefined4 *)(lVar12 + 0x10);
          puVar2[0x1f] = *(undefined4 *)(param_1[0x7d] + 4);
          uVar23 = NEON_ucvtf((uint)*(byte *)param_1[0x7d]);
          puVar2[0x20] = uVar23;
          uVar23 = NEON_ucvtf((uint)*(byte *)(param_1[0x7d] + 1));
          puVar2[0x21] = uVar23;
          uVar23 = NEON_ucvtf((uint)*(byte *)(param_1[0x7d] + 2));
          puVar2[0x22] = uVar23;
          uVar23 = NEON_ucvtf((uint)*(byte *)(param_1[0x7d] + 3));
          puVar2[0x23] = uVar23;
          uVar23 = NEON_ucvtf((uint)*(byte *)(param_1[0x7d] + 0xac));
          puVar2[0x24] = uVar23;
        }
        lVar12 = param_1[0x80];
        if (lVar12 != 0) {
          puVar2[0x28] = *(undefined4 *)(lVar12 + 4);
          puVar2[0x29] = *(undefined4 *)(lVar12 + 8);
          puVar2[0x2a] = *(undefined4 *)(lVar12 + 0xc);
          puVar2[0x2b] = *(undefined4 *)(param_1[0x80] + 0x10);
          uVar23 = NEON_ucvtf((uint)*(byte *)param_1[0x80]);
          puVar2[0x2c] = uVar23;
          uVar23 = NEON_ucvtf((uint)*(byte *)(param_1[0x80] + 1));
          puVar2[0x2d] = uVar23;
        }
        if ((undefined4 *)param_1[0x7e] != (undefined4 *)0x0) {
          puVar2[0x30] = *(undefined4 *)param_1[0x7e];
          puVar2[0x31] = *(undefined4 *)(param_1[0x7e] + 8);
          uVar23 = NEON_ucvtf(*(undefined4 *)(param_1[0x7e] + 4));
          puVar2[0x32] = uVar23;
        }
        pbVar17 = (byte *)param_1[0x7f];
        if (pbVar17 != (byte *)0x0) {
          fVar26 = (float)NEON_ucvtf((uint)pbVar17[1]);
          puVar2[0x34] = fVar26 + (float)((uint)*pbVar17 << 1);
          puVar2[0x35] = *(undefined4 *)(param_1[0x7f] + 8);
          puVar2[0x36] = *(undefined4 *)(param_1[0x7f] + 0x10);
          puVar2[0x37] = *(undefined4 *)(param_1[0x7f] + 4);
        }
        lVar12 = param_1[0x82];
        if (lVar12 != 0) {
          puVar2[0x38] = *(undefined4 *)(lVar12 + 0x10);
          puVar2[0x39] = *(undefined4 *)(lVar12 + 0x14);
          puVar2[0x3a] = *(undefined4 *)(lVar12 + 0x18);
          puVar2[0x3b] = *(undefined4 *)(param_1[0x82] + 0x1c);
          lVar12 = param_1[0x82];
          puVar2[0x3c] = *(undefined4 *)(lVar12 + 4);
          puVar2[0x3d] = *(undefined4 *)(lVar12 + 8);
          puVar2[0x3e] = *(undefined4 *)(lVar12 + 0xc);
          puVar2[0x3f] = *(undefined4 *)(param_1[0x82] + 0x20);
          uVar23 = NEON_ucvtf((uint)*(byte *)(param_1[0x82] + 1));
          puVar2[0x40] = uVar23;
          uVar23 = NEON_ucvtf((uint)*(byte *)(param_1[0x82] + 2));
          puVar2[0x41] = uVar23;
        }
        if ((undefined4 *)param_1[0x83] != (undefined4 *)0x0) {
          puVar2[0x54] = *(undefined4 *)param_1[0x83];
          puVar2[0x55] = *(undefined4 *)(param_1[0x83] + 4);
          iVar24 = *(int *)(param_1[0x83] + 8);
          puVar2[0x57] = 0;
          puVar2[0x56] = (float)iVar24;
        }
        if (param_1[0x84] != 0) {
          puVar2[0x44] = *(undefined4 *)(param_1[0x84] + 4);
          puVar2[0x45] = *(undefined4 *)(param_1[0x84] + 8);
          puVar2[0x46] = *(undefined4 *)(param_1[0x84] + 0xc);
          puVar2[0x47] = *(undefined4 *)(param_1[0x84] + 0x10);
          puVar2[0x48] = *(undefined4 *)(param_1[0x84] + 0x14);
          puVar2[0x49] = *(undefined4 *)(param_1[0x84] + 0x18);
          puVar2[0x4a] = *(undefined4 *)(param_1[0x84] + 0x1c);
          puVar2[0x4b] = *(undefined4 *)(param_1[0x84] + 0x20);
          puVar2[0x4c] = *(undefined4 *)(param_1[0x84] + 0x24);
          puVar2[0x4d] = *(undefined4 *)(param_1[0x84] + 0x28);
          puVar2[0x4e] = *(undefined4 *)(param_1[0x84] + 0x2c);
          puVar2[0x4f] = *(undefined4 *)(param_1[0x84] + 0x30);
          puVar2[0x50] = *(undefined4 *)(param_1[0x84] + 0x34);
          puVar2[0x51] = *(undefined4 *)(param_1[0x84] + 0x38);
          puVar2[0x52] = *(undefined4 *)(param_1[0x84] + 0x3c);
          puVar2[0x53] = *(undefined4 *)(param_1[0x84] + 0x40);
        }
        FUN_71005fc26c(param_1[0xe]);
        ret_71005FC268();
      }
    }
    lVar12 = *param_1;
    if (((*(char *)(lVar12 + 0xd68) != '\0') && (*(char *)(lVar12 + 0xd6a) == '\0')) &&
       (*(uint *)(lVar12 + 0xd74) < *(uint *)(lVar12 + 0xd80))) {
      *(uint *)(lVar12 + 0xd80) = *(uint *)(lVar12 + 0xd74);
      lVar12 = *param_1;
    }
    if (*(char *)(lVar12 + 0xe18) == '\0') {
      if (*(char *)((long)param_1 + 0xe6) == '\x03') {
        if ((float)(int)param_1[0x1e] < *(float *)(param_1[0x3f] + 0xc)) {
          *(float *)(param_1[0x3f] + 0xc) = (float)(int)param_1[0x1e];
          return;
        }
      }
      else if (*(char *)((long)param_1 + 0xe6) == '\x02') {
        if ((float)(int)param_1[0x1e] < *(float *)(param_1[0x3f] + 8)) {
          *(float *)(param_1[0x3f] + 8) = (float)(int)param_1[0x1e];
          return;
        }
      }
    }
    return;
  }
                    // WARNING: Could not recover jumptable at 0x0071005d6350. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)(&UNK_71005d6354 + (ulong)*(ushort *)(&DAT_7103295074 + (ulong)(uVar13 - 2) * 2) * 4))()
  ;
  return;
}



// WARNING: Type propagation algorithm not settling

void FUN_71005d7160(uint *param_1,long *param_2)

{
  char cVar1;
  byte bVar2;
  long lVar3;
  uint uVar4;
  long lVar5;
  float fVar6;
  
  lVar3 = *param_2;
  if (*(char *)(lVar3 + 0xd69) != '\0') {
    *param_1 = *param_1 | 8;
  }
  bVar2 = *(byte *)(lVar3 + 0x102f) >> 4;
  if (*(byte *)(lVar3 + 0x102f) < 0x10) {
    *param_1 = *param_1 | 1;
  }
  if (bVar2 == 1) {
    uVar4 = 2;
LAB_71005d71b8:
    *param_1 = *param_1 | uVar4;
  }
  else if (bVar2 == 2) {
    uVar4 = 4;
    goto LAB_71005d71b8;
  }
  bVar2 = *(byte *)(lVar3 + 0xe81) >> 4;
  if (*(byte *)(lVar3 + 0xe81) < 0x10) {
    param_1[2] = param_1[2] | 0x1000;
  }
  if (bVar2 == 2) {
    uVar4 = 0x2000;
LAB_71005d71fc:
    param_1[2] = param_1[2] | uVar4;
  }
  else if (bVar2 == 4) {
    uVar4 = 0x4000;
    goto LAB_71005d71fc;
  }
  bVar2 = *(byte *)(lVar3 + 0xe82) >> 4;
  if (*(byte *)(lVar3 + 0xe82) < 0x10) {
    param_1[2] = param_1[2] | 0x8000;
  }
  if (bVar2 == 2) {
    uVar4 = 0x10000;
LAB_71005d7240:
    param_1[2] = param_1[2] | uVar4;
  }
  else if (bVar2 == 4) {
    uVar4 = 0x20000;
    goto LAB_71005d7240;
  }
  bVar2 = *(byte *)(lVar3 + 0xe83) >> 4;
  if (*(byte *)(lVar3 + 0xe83) < 0x10) {
    param_1[2] = param_1[2] | 0x40000;
  }
  if (bVar2 == 2) {
    uVar4 = 0x80000;
  }
  else {
    if (bVar2 != 4) goto LAB_71005d7290;
    uVar4 = 0x100000;
  }
  param_1[2] = param_1[2] | uVar4;
LAB_71005d7290:
  cVar1 = *(char *)(lVar3 + 0x10c8);
  if (cVar1 == '\x01') {
    *param_1 = *param_1 | 0x10;
    cVar1 = *(char *)(lVar3 + 0x10c8);
  }
  if (cVar1 == '\x02') {
    *param_1 = *param_1 | 0x20;
    cVar1 = *(char *)(lVar3 + 0x10c8);
  }
  if (cVar1 == '\x03') {
    *param_1 = *param_1 | 0x40;
    cVar1 = *(char *)(lVar3 + 0x10c8);
  }
  if (cVar1 == '\x06') {
    param_1[1] = param_1[1] | 0x200000;
    cVar1 = *(char *)(lVar3 + 0x10c8);
  }
  if (cVar1 == '\x04') {
    fVar6 = *(float *)(lVar3 + 0x168);
    if (0.0 < fVar6) {
      lVar5 = 0;
      do {
        *(int *)(lVar3 + 0x170 + lVar5 * 4) = (int)lVar5;
        lVar5 = lVar5 + 1;
        fVar6 = *(float *)(lVar3 + 0x168);
      } while ((float)(int)lVar5 < fVar6);
    }
    *(float *)(lVar3 + 0x160) = fVar6;
    *param_1 = *param_1 | 0x80;
    cVar1 = *(char *)(lVar3 + 0x10d8);
  }
  else {
    cVar1 = *(char *)(lVar3 + 0x10d8);
  }
  if (cVar1 == '\x01') {
    *param_1 = *param_1 | 0x100;
    cVar1 = *(char *)(lVar3 + 0x10d8);
  }
  if (cVar1 == '\x02') {
    *param_1 = *param_1 | 0x200;
    cVar1 = *(char *)(lVar3 + 0x10d8);
  }
  if (cVar1 == '\x03') {
    *param_1 = *param_1 | 0x400;
    cVar1 = *(char *)(lVar3 + 0x10d8);
  }
  if (cVar1 == '\x06') {
    param_1[1] = param_1[1] | 0x400000;
    cVar1 = *(char *)(lVar3 + 0x10d8);
  }
  if (cVar1 == '\x04') {
    fVar6 = *(float *)(lVar3 + 0x1f8);
    if (0.0 < fVar6) {
      lVar5 = 0;
      do {
        *(int *)(lVar3 + 0x200 + lVar5 * 4) = (int)lVar5;
        lVar5 = lVar5 + 1;
        fVar6 = *(float *)(lVar3 + 0x1f8);
      } while ((float)(int)lVar5 < fVar6);
    }
    *(float *)(lVar3 + 0x1f0) = fVar6;
    *param_1 = *param_1 | 0x800;
    cVar1 = *(char *)(lVar3 + 0x10e8);
  }
  else {
    cVar1 = *(char *)(lVar3 + 0x10e8);
  }
  if (cVar1 == '\x01') {
    *param_1 = *param_1 | 0x1000;
    cVar1 = *(char *)(lVar3 + 0x10e8);
  }
  if (cVar1 == '\x02') {
    *param_1 = *param_1 | 0x2000;
    cVar1 = *(char *)(lVar3 + 0x10e8);
  }
  if (cVar1 == '\x03') {
    *param_1 = *param_1 | 0x4000;
    cVar1 = *(char *)(lVar3 + 0x10e8);
  }
  if (cVar1 == '\x06') {
    param_1[1] = param_1[1] | 0x800000;
    cVar1 = *(char *)(lVar3 + 0x10e8);
  }
  if (cVar1 == '\x04') {
    fVar6 = *(float *)(lVar3 + 0x288);
    if (0.0 < fVar6) {
      lVar5 = 0;
      do {
        *(int *)(lVar3 + 0x290 + lVar5 * 4) = (int)lVar5;
        lVar5 = lVar5 + 1;
        fVar6 = *(float *)(lVar3 + 0x288);
      } while ((float)(int)lVar5 < fVar6);
    }
    *(float *)(lVar3 + 0x280) = fVar6;
    *param_1 = *param_1 | 0x8000;
    cVar1 = *(char *)(lVar3 + 0x10f8);
  }
  else {
    cVar1 = *(char *)(lVar3 + 0x10f8);
  }
  if (cVar1 == '\x01') {
    *param_1 = *param_1 | 0x10000;
    cVar1 = *(char *)(lVar3 + 0x10f8);
  }
  if (cVar1 == '\x02') {
    *param_1 = *param_1 | 0x20000;
    cVar1 = *(char *)(lVar3 + 0x10f8);
  }
  if (cVar1 == '\x03') {
    *param_1 = *param_1 | 0x40000;
    cVar1 = *(char *)(lVar3 + 0x10f8);
  }
  if (cVar1 == '\x06') {
    param_1[1] = param_1[1] | 0x1000000;
    cVar1 = *(char *)(lVar3 + 0x10f8);
  }
  if (cVar1 == '\x04') {
    fVar6 = *(float *)(lVar3 + 0x318);
    if (0.0 < fVar6) {
      lVar5 = 0;
      do {
        *(int *)(lVar3 + 800 + lVar5 * 4) = (int)lVar5;
        lVar5 = lVar5 + 1;
        fVar6 = *(float *)(lVar3 + 0x318);
      } while ((float)(int)lVar5 < fVar6);
    }
    *(float *)(lVar3 + 0x310) = fVar6;
    *param_1 = *param_1 | 0x80000;
    cVar1 = *(char *)(lVar3 + 0x1108);
  }
  else {
    cVar1 = *(char *)(lVar3 + 0x1108);
  }
  if (cVar1 == '\x01') {
    *param_1 = *param_1 | 0x100000;
    cVar1 = *(char *)(lVar3 + 0x1108);
  }
  if (cVar1 == '\x02') {
    *param_1 = *param_1 | 0x200000;
    cVar1 = *(char *)(lVar3 + 0x1108);
  }
  if (cVar1 == '\x03') {
    *param_1 = *param_1 | 0x400000;
    cVar1 = *(char *)(lVar3 + 0x1108);
  }
  if (cVar1 == '\x06') {
    param_1[1] = param_1[1] | 0x2000000;
    cVar1 = *(char *)(lVar3 + 0x1108);
  }
  if (cVar1 == '\x04') {
    fVar6 = *(float *)(lVar3 + 0x3a8);
    if (0.0 < fVar6) {
      lVar5 = 0;
      do {
        *(int *)(lVar3 + 0x3b0 + lVar5 * 4) = (int)lVar5;
        lVar5 = lVar5 + 1;
        fVar6 = *(float *)(lVar3 + 0x3a8);
      } while ((float)(int)lVar5 < fVar6);
    }
    *(float *)(lVar3 + 0x3a0) = fVar6;
    *param_1 = *param_1 | 0x800000;
    cVar1 = *(char *)(lVar3 + 0x1118);
  }
  else {
    cVar1 = *(char *)(lVar3 + 0x1118);
  }
  if (cVar1 == '\x01') {
    *param_1 = *param_1 | 0x1000000;
    cVar1 = *(char *)(lVar3 + 0x1118);
  }
  if (cVar1 == '\x02') {
    *param_1 = *param_1 | 0x2000000;
    cVar1 = *(char *)(lVar3 + 0x1118);
  }
  if (cVar1 == '\x03') {
    *param_1 = *param_1 | 0x4000000;
    cVar1 = *(char *)(lVar3 + 0x1118);
  }
  if (cVar1 == '\x06') {
    param_1[1] = param_1[1] | 0x4000000;
    cVar1 = *(char *)(lVar3 + 0x1118);
  }
  if (cVar1 == '\x04') {
    fVar6 = *(float *)(lVar3 + 0x438);
    if (0.0 < fVar6) {
      lVar5 = 0;
      do {
        *(int *)(lVar3 + 0x440 + lVar5 * 4) = (int)lVar5;
        lVar5 = lVar5 + 1;
        fVar6 = *(float *)(lVar3 + 0x438);
      } while ((float)(int)lVar5 < fVar6);
    }
    *(float *)(lVar3 + 0x430) = fVar6;
    *param_1 = *param_1 | 0x8000000;
    cVar1 = *(char *)(lVar3 + 0xe1d);
  }
  else {
    cVar1 = *(char *)(lVar3 + 0xe1d);
  }
  if (cVar1 != '\0') {
    *param_1 = *param_1 | 0x10000000;
  }
  if (*(char *)(lVar3 + 0xe1e) != '\0') {
    *param_1 = *param_1 | 0x20000000;
  }
  if (*(char *)(lVar3 + 0xe1f) != '\0') {
    *param_1 = *param_1 | 0x40000000;
  }
  if (*(char *)(lVar3 + 0x10cd) != '\0') {
    param_1[1] = param_1[1] | 1;
  }
  if (*(char *)(lVar3 + 0x10ce) != '\0') {
    param_1[1] = param_1[1] | 2;
  }
  if (*(char *)(lVar3 + 0x10dd) != '\0') {
    param_1[1] = param_1[1] | 4;
  }
  if (*(char *)(lVar3 + 0x10de) != '\0') {
    param_1[1] = param_1[1] | 8;
  }
  if (*(char *)(lVar3 + 0x10ed) != '\0') {
    param_1[1] = param_1[1] | 0x10;
  }
  if (*(char *)(lVar3 + 0x10ee) != '\0') {
    param_1[1] = param_1[1] | 0x20;
  }
  if (*(char *)(lVar3 + 0x10fd) != '\0') {
    param_1[1] = param_1[1] | 0x40;
  }
  if (*(char *)(lVar3 + 0x10fe) != '\0') {
    param_1[1] = param_1[1] | 0x80;
  }
  if (*(char *)(lVar3 + 0x110d) != '\0') {
    param_1[1] = param_1[1] | 0x100;
  }
  if (*(char *)(lVar3 + 0x110e) != '\0') {
    param_1[1] = param_1[1] | 0x200;
  }
  if (*(char *)(lVar3 + 0x111d) != '\0') {
    param_1[1] = param_1[1] | 0x400;
  }
  if (*(char *)(lVar3 + 0x111e) != '\0') {
    param_1[1] = param_1[1] | 0x800;
  }
  if (*(char *)(lVar3 + 0x10cf) != '\0') {
    param_1[1] = param_1[1] | 0x1000;
  }
  if (*(char *)(lVar3 + 0x10df) != '\0') {
    param_1[1] = param_1[1] | 0x2000;
  }
  if (*(char *)(lVar3 + 0x10ef) != '\0') {
    param_1[1] = param_1[1] | 0x4000;
  }
  if (*(char *)(lVar3 + 0x10ff) != '\0') {
    param_1[1] = param_1[1] | 0x8000;
  }
  if (*(char *)(lVar3 + 0x110f) != '\0') {
    param_1[1] = param_1[1] | 0x10000;
  }
  if (*(char *)(lVar3 + 0x111f) != '\0') {
    param_1[1] = param_1[1] | 0x20000;
  }
  if (*(char *)(lVar3 + 0xe23) != '\0') {
    param_1[1] = param_1[1] | 0x40000;
  }
  cVar1 = *(char *)(lVar3 + 0xe1c);
  if (cVar1 == '\x01') {
    param_1[1] = param_1[1] | 0x100000;
    cVar1 = *(char *)(lVar3 + 0xe1c);
  }
  if (cVar1 == '\0') {
    param_1[1] = param_1[1] | 0x80000;
    cVar1 = *(char *)(lVar3 + 0xe24);
  }
  else {
    cVar1 = *(char *)(lVar3 + 0xe24);
  }
  if (cVar1 != '\0') {
    param_1[2] = param_1[2] | 1;
  }
  if (param_2[0x7b] != 0) {
    param_1[2] = param_1[2] | 2;
  }
  if (param_2[0x7c] != 0) {
    param_1[2] = param_1[2] | 0x100;
  }
  if (param_2[0x81] != 0) {
    param_1[2] = param_1[2] | 4;
  }
  if (param_2[0x7d] != 0) {
    param_1[2] = param_1[2] | 8;
  }
  if (param_2[0x80] != 0) {
    param_1[2] = param_1[2] | 0x10;
  }
  if (param_2[0x7e] != 0) {
    param_1[2] = param_1[2] | 0x20;
  }
  if (param_2[0x7f] != 0) {
    param_1[2] = param_1[2] | 0x40;
  }
  if (param_2[0x82] != 0) {
    param_1[2] = param_1[2] | 0x80;
  }
  if ((ulong)(long)*(char *)(lVar3 + 0xcc3) < 3) {
    param_1[2] = param_1[2] | *(uint *)(&DAT_7103295090 + (long)*(char *)(lVar3 + 0xcc3) * 4);
  }
  return;
}



void FUN_71005d7a80(long param_1,long param_2)

{
  uint *puVar1;
  int iVar2;
  uint uVar3;
  int *piVar4;
  
  if ((param_2 != 0) && (*(uint *)(param_2 + 0x10) != 0xffffffff)) {
    piVar4 = (int *)(param_2 + (ulong)*(uint *)(param_2 + 0x10));
    do {
      iVar2 = *piVar4;
      if (iVar2 < 0x4c504145) {
        if (iVar2 < 0x33305045) {
          if (iVar2 < 0x31414145) {
            if (iVar2 == 0x30414145) {
              *(ulong *)(param_1 + 0x460) = (long)piVar4 + (ulong)(uint)piVar4[5];
            }
            else {
              if (iVar2 != 0x30434145) {
                if (iVar2 == 0x31305045) {
                  uVar3 = piVar4[5];
                  *(undefined1 *)(param_1 + 0xe6) = 1;
                  *(ulong *)(param_1 + 0x1f8) = (long)piVar4 + (ulong)uVar3;
                }
                goto LAB_71005d7b94;
              }
              *(ulong *)(param_1 + 0x440) = (long)piVar4 + (ulong)(uint)piVar4[5];
            }
          }
          else {
            if (0x314e5245 < iVar2) {
              if (iVar2 == 0x314e5246) {
                uVar3 = piVar4[5];
                *(undefined1 *)(param_1 + 0xee) = 1;
                *(ulong *)(param_1 + 0x3e0) = (long)piVar4 + (ulong)uVar3;
              }
              else if (iVar2 == 0x32305045) {
                *(ulong *)(param_1 + 0x1f8) = (long)piVar4 + (ulong)(uint)piVar4[5];
                *(undefined1 *)(param_1 + 0xe6) = 2;
              }
              goto LAB_71005d7b94;
            }
            if (iVar2 == 0x31414145) {
              *(ulong *)(param_1 + 0x468) = (long)piVar4 + (ulong)(uint)piVar4[5];
            }
            else {
              if (iVar2 != 0x31434145) goto LAB_71005d7b94;
              *(ulong *)(param_1 + 0x448) = (long)piVar4 + (ulong)(uint)piVar4[5];
            }
          }
LAB_71005d7b90:
          *(undefined1 *)(param_1 + 0xe8) = 1;
        }
        else if (iVar2 < 0x44574746) {
          if (iVar2 < 0x44415046) {
            if (iVar2 == 0x33305045) {
              *(ulong *)(param_1 + 0x1f8) = (long)piVar4 + (ulong)(uint)piVar4[5];
              *(undefined1 *)(param_1 + 0xe6) = 3;
            }
            else if (iVar2 == 0x34305045) {
              *(ulong *)(param_1 + 0x1f8) = (long)piVar4 + (ulong)(uint)piVar4[5];
              *(undefined1 *)(param_1 + 0xe6) = 4;
            }
          }
          else if (iVar2 == 0x44415046) {
            uVar3 = piVar4[5];
            *(undefined1 *)(param_1 + 0xee) = 1;
            *(ulong *)(param_1 + 0x408) = (long)piVar4 + (ulong)uVar3;
          }
          else if (iVar2 == 0x444e5246) {
            uVar3 = piVar4[5];
            *(undefined1 *)(param_1 + 0xee) = 1;
            *(ulong *)(param_1 + 0x3d8) = (long)piVar4 + (ulong)uVar3;
          }
        }
        else if (iVar2 < 0x47414d46) {
          if (iVar2 == 0x44574746) {
            uVar3 = piVar4[5];
            *(undefined1 *)(param_1 + 0xee) = 1;
            *(ulong *)(param_1 + 0x418) = (long)piVar4 + (ulong)uVar3;
          }
          else if (iVar2 == 0x46534346) {
            uVar3 = piVar4[5];
            *(undefined1 *)(param_1 + 0xee) = 1;
            *(ulong *)(param_1 + 0x420) = (long)piVar4 + (ulong)uVar3;
          }
        }
        else if (iVar2 == 0x47414d46) {
          uVar3 = piVar4[5];
          *(undefined1 *)(param_1 + 0xee) = 1;
          *(ulong *)(param_1 + 1000) = (long)piVar4 + (ulong)uVar3;
        }
        else if (iVar2 == 0x4c4f4346) {
          uVar3 = piVar4[5];
          *(undefined1 *)(param_1 + 0xee) = 1;
          *(ulong *)(param_1 + 0x3f8) = (long)piVar4 + (ulong)uVar3;
        }
      }
      else if (iVar2 < 0x52544145) {
        if (iVar2 < 0x50444143) {
          if (iVar2 < 0x4e4c4346) {
            if (iVar2 == 0x4c504145) {
              *(ulong *)(param_1 + 0x458) = (long)piVar4 + (ulong)(uint)piVar4[5];
            }
            else {
              if (iVar2 != 0x4c534145) goto LAB_71005d7b94;
              *(ulong *)(param_1 + 0x480) = (long)piVar4 + (ulong)(uint)piVar4[5];
            }
            goto LAB_71005d7b90;
          }
          if (iVar2 == 0x4e4c4346) {
            uVar3 = piVar4[5];
            *(undefined1 *)(param_1 + 0xee) = 1;
            *(ulong *)(param_1 + 0x410) = (long)piVar4 + (ulong)uVar3;
          }
          else if (iVar2 == 0x4e505346) {
            uVar3 = piVar4[5];
            *(undefined1 *)(param_1 + 0xee) = 1;
            *(ulong *)(param_1 + 0x3f0) = (long)piVar4 + (ulong)uVar3;
          }
        }
        else if (iVar2 < 0x50445543) {
          if (iVar2 == 0x50444143) {
            *(ulong *)(param_1 + 0x4a0) = (long)piVar4 + (ulong)(uint)piVar4[5];
          }
          else if (iVar2 == 0x50445343) {
            *(ulong *)(param_1 + 0x498) = (long)piVar4 + (ulong)(uint)piVar4[5];
            *(int *)(param_1 + 0x500) = piVar4[1] + -0x20;
          }
        }
        else if (iVar2 == 0x50445543) {
          *(ulong *)(param_1 + 0x4a8) = (long)piVar4 + (ulong)(uint)piVar4[5];
        }
        else if (iVar2 == 0x52454145) {
          uVar3 = piVar4[5];
          *(undefined2 *)(param_1 + 0xe7) = 0x101;
          *(ulong *)(param_1 + 0x430) = (long)piVar4 + (ulong)uVar3;
        }
      }
      else {
        if (0x56444144 < iVar2) {
          if (iVar2 < 0x564f4145) {
            if (iVar2 == 0x56444145) {
              *(ulong *)(param_1 + 0x478) = (long)piVar4 + (ulong)(uint)piVar4[5];
            }
            else {
              if (iVar2 != 0x56474145) goto LAB_71005d7b94;
              *(ulong *)(param_1 + 0x490) = (long)piVar4 + (ulong)(uint)piVar4[5];
            }
          }
          else {
            if (iVar2 != 0x564f4145) {
              if (iVar2 == 0x564f4346) {
                uVar3 = piVar4[5];
                *(undefined1 *)(param_1 + 0xee) = 1;
                *(ulong *)(param_1 + 0x400) = (long)piVar4 + (ulong)uVar3;
              }
              goto LAB_71005d7b94;
            }
            *(ulong *)(param_1 + 0x470) = (long)piVar4 + (ulong)(uint)piVar4[5];
          }
          goto LAB_71005d7b90;
        }
        if (iVar2 < 0x53534145) {
          if (iVar2 == 0x52544145) {
            *(ulong *)(param_1 + 0x450) = (long)piVar4 + (ulong)(uint)piVar4[5];
            goto LAB_71005d7b90;
          }
          if (iVar2 == 0x53454145) {
            uVar3 = piVar4[5];
            *(undefined2 *)(param_1 + 0xe7) = 0x101;
            *(ulong *)(param_1 + 0x428) = (long)piVar4 + (ulong)uVar3;
          }
        }
        else {
          if (iVar2 == 0x53534145) {
            *(ulong *)(param_1 + 0x488) = (long)piVar4 + (ulong)(uint)piVar4[5];
            goto LAB_71005d7b90;
          }
          if (iVar2 == 0x54454145) {
            uVar3 = piVar4[5];
            *(undefined2 *)(param_1 + 0xe7) = 0x101;
            *(ulong *)(param_1 + 0x438) = (long)piVar4 + (ulong)uVar3;
          }
        }
      }
LAB_71005d7b94:
      puVar1 = (uint *)(piVar4 + 3);
      piVar4 = (int *)((long)piVar4 + (ulong)*puVar1);
    } while (*puVar1 != 0xffffffff);
  }
  return;
}



void FUN_71005d8014(undefined8 *param_1,long *param_2)

{
  undefined8 uVar1;
  
  *(undefined1 *)((long)param_1 + 0x1c) = 0;
  *(undefined4 *)(param_1 + 3) = 0x101;
  uVar1 = (**(code **)(*param_2 + 0x20))(param_2,param_1 + 2);
  *param_1 = uVar1;
  *(undefined4 *)(param_1 + 6) = 0x202;
  *(undefined1 *)((long)param_1 + 0x34) = 0;
  uVar1 = (**(code **)(*param_2 + 0x20))(param_2,param_1 + 5);
  param_1[1] = uVar1;
  return;
}
