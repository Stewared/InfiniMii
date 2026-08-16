


long FUN_71005e7d14(long param_1,long param_2)

{
  uint *puVar1;
  long lVar2;
  long *plVar3;
  
  do {
    param_1 = *(long *)(param_1 + 0x488);
    if (param_1 == 0) {
      return 0;
    }
    lVar2 = *(long *)(param_1 + 0x468);
    plVar3 = *(long **)(param_1 + 0x480);
  } while (lVar2 == 0 || plVar3 == (long *)0x0);
  do {
    if (*plVar3 == param_2) {
      return lVar2;
    }
    puVar1 = (uint *)(plVar3 + 1);
    lVar2 = lVar2 + 0x90;
    plVar3 = (long *)((long)plVar3 + (ulong)*puVar1);
  } while (*puVar1 != 0);
  lVar2 = FUN_71005e7d14(param_1,param_2);
  return lVar2;
}



long FUN_71005e7d1c(long param_1,long param_2)

{
  uint *puVar1;
  long lVar2;
  long *plVar3;
  
  do {
    lVar2 = *(long *)(param_1 + 0x468);
    plVar3 = *(long **)(param_1 + 0x480);
    if (lVar2 != 0 && plVar3 != (long *)0x0) {
      do {
        if (*plVar3 == param_2) {
          return lVar2;
        }
        puVar1 = (uint *)(plVar3 + 1);
        lVar2 = lVar2 + 0x90;
        plVar3 = (long *)((long)plVar3 + (ulong)*puVar1);
      } while (*puVar1 != 0);
      lVar2 = FUN_71005e7d14(param_1,param_2);
      return lVar2;
    }
    param_1 = *(long *)(param_1 + 0x488);
  } while (param_1 != 0);
  return 0;
}



ulong FUN_71005e7d60(long param_1,undefined8 param_2)

{
  uint uVar1;
  int iVar2;
  ulong uVar3;
  long *plVar4;
  
  uVar1 = *(uint *)(param_1 + 0x550);
  if ((int)uVar1 < 1) {
    return 0xffffffff;
  }
  plVar4 = *(long **)(param_1 + 0x430);
  uVar3 = 0;
  do {
    iVar2 = thunk_EXT_FUN_02e95df0(param_2,*plVar4 + 0x10);
    if (iVar2 == 0) {
      return uVar3 & 0xffffffff;
    }
    uVar3 = uVar3 + 1;
    plVar4 = plVar4 + 5;
  } while (uVar1 != uVar3);
  return 0xffffffff;
}



byte FUN_71005e7e10(long param_1,int param_2)

{
  long *plVar1;
  long *plVar2;
  byte bVar3;
  byte bVar4;
  long lVar5;
  ulong uVar6;
  long lVar7;
  
  lVar5 = *(long *)(param_1 + 0x430);
  if (param_2 < *(int *)(param_1 + 0x550) && lVar5 != 0) {
    bVar3 = *(byte *)(lVar5 + (long)param_2 * 0x28 + 0x22);
    if (bVar3 != 0) {
      lVar5 = *(long *)(lVar5 + (long)param_2 * 0x28 + 8);
      if (bVar3 == 1) {
        uVar6 = 0;
        bVar4 = 0;
      }
      else {
        uVar6 = 0;
        bVar4 = 0;
        lVar7 = lVar5;
        do {
          plVar1 = (long *)(lVar7 + 0x350);
          uVar6 = uVar6 + 2;
          plVar2 = (long *)(lVar7 + 0x890);
          lVar7 = lVar7 + 0xa80;
          bVar4 = (*plVar2 != 0 || *plVar1 != 0) | bVar4;
        } while (((ulong)bVar3 & 0xfe) != uVar6);
      }
      if ((bVar3 & 1) == 0) {
        return bVar4;
      }
      return *(long *)(lVar5 + uVar6 * 0x540 + 0x350) != 0 | bVar4;
    }
  }
  return 0;
}



bool FUN_71005e7ec0(long param_1,int param_2)

{
  long lVar1;
  
  lVar1 = *(long *)(param_1 + 0x430);
  if (*(int *)(param_1 + 0x550) <= param_2 || lVar1 == 0) {
    return false;
  }
  if (*(char *)(lVar1 + (long)param_2 * 0x28 + 0x25) != '\0') {
    return true;
  }
  return *(char *)(lVar1 + (long)param_2 * 0x28 + 0x26) != '\0';
}



void FUN_71005e7f10(long *param_1)

{
  long lVar1;
  
  lVar1 = DAT_7103a6fa38 + 0x10;
  *param_1 = DAT_7103a6fa30 + 0x10;
  param_1[1] = lVar1;
  thunk_EXT_FUN_02e95df0(param_1 + 2);
  FUN_71024d49c0((long)param_1);
  return;
}



void FUN_71005e7f50(long param_1,undefined8 param_2,long param_3)

{
  thunk_EXT_FUN_02e95df0(param_1 + 0x10);
  *(long *)(param_1 + 0x38) = *(long *)(param_1 + 0x38) - param_3;
  *(long *)(param_1 + 0x40) = *(long *)(param_1 + 0x40) + -1;
  (**(code **)(**(long **)(param_1 + 0x30) + 0x18))(*(long **)(param_1 + 0x30),param_2);
  thunk_EXT_FUN_02e95df0(param_1 + 0x10);
  return;
}



undefined8
FUN_71005e81c0(long param_1,undefined8 *param_2,long *param_3,undefined8 *param_4,long param_5,
              undefined8 param_6,long param_7,uint param_8,undefined *param_9)

{
  long lVar1;
  long lVar2;
  undefined8 uVar3;
  int iVar4;
  long lVar5;
  long lVar6;
  long lVar7;
  
  if (*(char *)(param_1 + 0x39) == '\0') {
    *(undefined8 **)(param_1 + 8) = param_2;
    lVar1 = thunk_EXT_FUN_02e95df0(param_7);
    *(long *)(param_1 + 0x10) = lVar1;
    if (param_4 == (undefined8 *)0x0) {
      param_4 = (undefined8 *)0x0;
      lVar6 = 0;
    }
    else {
      lVar6 = (param_5 - param_7) + lVar1;
    }
    FUN_7100601fe0(lVar1,param_2,param_4,lVar6);
    iVar4 = *(int *)(*(long *)(param_1 + 0x10) + 0x1c);
    *(int *)(param_1 + 0x34) = iVar4;
    lVar1 = (**(code **)(*param_3 + 0x10))(param_3,(long)iVar4 * 0x58,0x80);
    uVar3 = 0;
    if (lVar1 != 0) {
      iVar4 = *(int *)(param_1 + 0x34);
      if (iVar4 == 0) {
        *(long *)(param_1 + 0x18) = lVar1;
      }
      else {
        lVar6 = 0;
        do {
          lVar5 = lVar1 + lVar6;
          FUN_71005e9484((undefined1 *)(lVar5 + 8));
          FUN_71005e9484((undefined1 *)(lVar5 + 9));
          FUN_71005e9484((undefined1 *)(lVar5 + 10));
          FUN_71005e9484((undefined1 *)(lVar5 + 0xb));
          FUN_71005e9484((undefined1 *)(lVar5 + 0xc));
          FUN_71005e9484((undefined1 *)(lVar5 + 0xd));
          FUN_71005e9484((undefined1 *)(lVar5 + 0xe));
          FUN_71005e9484((undefined1 *)(lVar5 + 0xf));
          FUN_71005e9484((undefined1 *)(lVar5 + 0x10));
          FUN_71005e8404((undefined1 *)(lVar5 + 0x11));
          lVar6 = lVar6 + 0x58;
        } while ((long)iVar4 * 0x58 - lVar6 != 0);
        *(long *)(param_1 + 0x18) = lVar1;
        lVar1 = DAT_7103a64d30;
        if (0 < *(int *)(param_1 + 0x34)) {
          lVar5 = 0;
          lVar6 = 0;
          if (param_9 == (undefined *)0x0) {
            do {
              FUN_71005e9dc8(*(long *)(param_1 + 0x18) + lVar5);
              iVar4 = *(int *)(param_1 + 0x34);
              lVar6 = lVar6 + 1;
              lVar5 = lVar5 + 0x58;
            } while (lVar6 < iVar4);
          }
          else {
            lVar7 = 0;
            do {
              FUN_71005e9dc8(*(long *)(param_1 + 0x18) + lVar6);
              lVar2 = *(long *)(*(long *)(*(long *)(param_1 + 0x10) + 0x20) + *(long *)(lVar1 + 8) +
                               lVar5);
              if ((lVar2 != 0) && (*(long *)(lVar2 + 0x30) == 0)) {
                (*(code *)param_9)();
              }
              iVar4 = *(int *)(param_1 + 0x34);
              lVar7 = lVar7 + 1;
              lVar6 = lVar6 + 0x58;
              lVar5 = lVar5 + 0x40;
            } while (lVar7 < iVar4);
          }
          if ((0 < iVar4) && ((param_8 & 1) == 0)) {
            lVar5 = 0;
            lVar6 = 0;
            lVar1 = 0;
            do {
              FUN_71017ca764(param_1,(long *)(*(long *)(param_1 + 0x18) + lVar6),
                             *(long *)(*(long *)(param_1 + 0x10) + 0x20) + lVar5);
              lVar1 = lVar1 + 1;
              lVar6 = lVar6 + 0x58;
              lVar5 = lVar5 + 0x40;
            } while (lVar1 < *(int *)(param_1 + 0x34));
          }
        }
      }
      uVar3 = 1;
      *(undefined1 *)(param_1 + 0x39) = 1;
    }
    return uVar3;
  }
  return 0;
}



void FUN_71005e8404(undefined1 *param_1)

{
  FUN_71005e9484(param_1);
  FUN_71005e9484(param_1 + 1);
  FUN_71005e9484(param_1 + 2);
  FUN_71005e9484(param_1 + 3);
  FUN_71005e9484(param_1 + 4);
  FUN_71005e9484(param_1 + 5);
  FUN_71005e9484(param_1 + 6);
  FUN_71005e9484(param_1 + 7);
  FUN_71005e9484(param_1 + 8);
  FUN_71005e9484(param_1 + 9);
  FUN_71005e9484(param_1 + 10);
  FUN_71005e9484(param_1 + 0xb);
  FUN_71005e9484(param_1 + 0xc);
  FUN_71005e9484(param_1 + 0xd);
  FUN_71005e9484(param_1 + 0xe);
  FUN_71005e9484(param_1 + 0xf);
  FUN_71005e9484(param_1 + 0x10);
  FUN_71005e9484(param_1 + 0x11);
  FUN_71005e9484(param_1 + 0x12);
  FUN_71005e9484(param_1 + 0x13);
  FUN_71005e9484(param_1 + 0x14);
  FUN_71005e9484(param_1 + 0x15);
  FUN_71005e9484(param_1 + 0x16);
  FUN_71005e9484(param_1 + 0x17);
  FUN_71005e9484(param_1 + 0x18);
  FUN_71005e9484(param_1 + 0x19);
  FUN_71005e9484(param_1 + 0x1a);
  FUN_71005e9484(param_1 + 0x1b);
  FUN_71005e9484(param_1 + 0x1c);
  FUN_71005e9484(param_1 + 0x1d);
  FUN_71005e9484(param_1 + 0x1e);
  FUN_71005e9484(param_1 + 0x1f);
  FUN_71005e9484(param_1 + 0x20);
  FUN_71005e9484(param_1 + 0x21);
  FUN_71005e9484(param_1 + 0x22);
  FUN_71005e9484(param_1 + 0x23);
  FUN_71005e9484(param_1 + 0x24);
  FUN_71005e9484(param_1 + 0x25);
  FUN_71005e9484(param_1 + 0x26);
  FUN_71005e9484(param_1 + 0x27);
  FUN_71005e9484(param_1 + 0x28);
  FUN_71005e9484(param_1 + 0x29);
  FUN_71005e9484(param_1 + 0x2a);
  FUN_71005e9484(param_1 + 0x2b);
  FUN_71005e9484(param_1 + 0x2c);
  FUN_71005e9484(param_1 + 0x2d);
  FUN_71005e9484(param_1 + 0x2e);
  FUN_71005e9484(param_1 + 0x2f);
  FUN_71005e9484(param_1 + 0x30);
  FUN_71005e9484(param_1 + 0x31);
  FUN_71005e9484(param_1 + 0x32);
  FUN_71005e9484(param_1 + 0x33);
  FUN_71005e9484(param_1 + 0x34);
  FUN_71005e9484(param_1 + 0x35);
  FUN_71005e9484(param_1 + 0x36);
  FUN_71005e9484(param_1 + 0x37);
  FUN_71005e9484(param_1 + 0x38);
  FUN_71005e9484(param_1 + 0x39);
  FUN_71005e9484(param_1 + 0x3a);
  FUN_71005e9484(param_1 + 0x3b);
  FUN_71005e9484(param_1 + 0x3c);
  FUN_71005e9484(param_1 + 0x3d);
  FUN_71005e9484(param_1 + 0x3e);
  FUN_71005e9484(param_1 + 0x3f);
  FUN_71005e9484(param_1 + 0x40);
  FUN_71005e9484(param_1 + 0x41);
  return;
}



void FUN_71005e863c(undefined8 *param_1)

{
  FUN_71005fc110(param_1);
  FUN_71005fd8a4(param_1 + 9);
  param_1[0x2f] = 0;
  param_1[0x30] = 0;
  param_1[0x2d] = 0;
  param_1[0x2e] = 0;
  return;
}



void FUN_71005e866c(void)

{
  ret_71005FD8B0();
  ret_71005FC128();
  return;
}



bool FUN_71005e8694(char *param_1,undefined8 *param_2,long *param_3,undefined4 param_4,
                   undefined4 param_5,long param_6)

{
  long *plVar1;
  bool bVar2;
  uint uVar3;
  undefined8 uVar4;
  long lVar5;
  ulong uVar6;
  undefined8 local_70;
  long local_68;
  undefined8 local_60;
  undefined8 uStack_58;
  undefined8 local_50;
  undefined8 uStack_48;
  
  if (*param_1 == '\0' || param_1[0x158] == '\0') {
    param_1[0x178] = '\0';
    param_1[0x179] = '\0';
    param_1[0x17a] = '\0';
    param_1[0x17b] = '\0';
    param_1[0x17c] = '\0';
    param_1[0x17d] = '\0';
    param_1[0x17e] = '\0';
    param_1[0x17f] = '\0';
    param_1[0x180] = '\0';
    param_1[0x181] = '\0';
    param_1[0x182] = '\0';
    param_1[0x183] = '\0';
    param_1[0x184] = '\0';
    param_1[0x185] = '\0';
    param_1[0x186] = '\0';
    param_1[0x187] = '\0';
    *(long *)(param_1 + 0x170) = param_6;
    local_50 = 0;
    uStack_48 = 0;
    FUN_71005fbcfc(&local_50);
    local_60 = 0;
    uStack_58 = 0;
    local_70 = 0;
    local_68 = 0;
    local_50._4_4_ = param_4;
    FUN_71005fbd04((undefined4 *)&local_70);
    local_70 = CONCAT44(local_70._4_4_,param_5);
    uVar3 = FUN_71005fbfe4(param_2,(long)&local_50);
    *(ulong *)(param_1 + 0x168) = (ulong)uVar3;
    uVar4 = FUN_71005fd894();
    lVar5 = FUN_71005fd89c();
    uVar6 = (param_6 + lVar5) - 1U & -lVar5;
    *(ulong *)(param_1 + 0x178) = uVar6;
    local_68 = (**(code **)(*param_3 + 0x10))(param_3,uVar6,uVar4);
    bVar2 = local_68 != 0;
    *(long *)(param_1 + 0x180) = local_68;
    if (local_68 != 0) {
      local_60 = *(undefined8 *)(param_1 + 0x178);
      plVar1 = (long *)(param_1 + 0x48);
      local_70 = CONCAT44((int)local_60,(undefined4)local_70);
      FUN_71005fd8b4(plVar1,param_2,(undefined4 *)&local_70);
      FUN_71005fd99c(plVar1,param_2,"NnVfx2GfxMemoryPool");
      local_50 = CONCAT44(local_50._4_4_,(int)*(undefined8 *)(param_1 + 0x170));
      FUN_71005fc12c(param_1,param_2,(undefined4 *)&local_50,plVar1,0);
      FUN_71005fc2e0((long)param_1,param_2,"NnVfx2GfxBuffer");
    }
  }
  else {
    bVar2 = true;
  }
  return bVar2;
}



bool FUN_71005e87f4(char *param_1)

{
  return *param_1 != '\0' && param_1[0x158] != '\0';
}



void FUN_71005e880c(char *param_1,undefined8 param_2,long *param_3)

{
  if (*param_1 != '\0' && param_1[0x158] != '\0') {
    FUN_71005fc21c(param_1);
    FUN_71005fd94c((undefined8 *)(param_1 + 0x48));
    (**(code **)(*param_3 + 0x18))(param_3,*(undefined8 *)(param_1 + 0x180));
    param_1[0x180] = '\0';
    param_1[0x181] = '\0';
    param_1[0x182] = '\0';
    param_1[0x183] = '\0';
    param_1[0x184] = '\0';
    param_1[0x185] = '\0';
    param_1[0x186] = '\0';
    param_1[0x187] = '\0';
  }
  return;
}



long FUN_71005e8874(long param_1)

{
  long lVar1;
  uint uVar2;
  ulong uVar3;
  uint uVar4;
  uint uVar5;
  ulong uVar6;
  bool bVar7;
  
  lVar1 = param_1 + (ulong)*(uint *)(param_1 + 0x14);
  bVar7 = param_1 != 0;
  uVar2 = (uint)(bVar7 && *(int *)(lVar1 + 0x3c) != 0);
  uVar3 = 1;
  if (uVar2 != 0) {
    uVar3 = 2;
  }
  uVar6 = (ulong)uVar2;
  if (*(int *)(lVar1 + 0x40) != 0 && param_1 != 0) {
    uVar6 = uVar3;
  }
  uVar2 = 0;
  if (*(int *)(lVar1 + 0x44) != 0) {
    uVar2 = (uint)bVar7;
  }
  uVar4 = 0;
  if (*(int *)(lVar1 + 0x48) != 0) {
    uVar4 = (uint)bVar7;
  }
  uVar5 = 0;
  if (*(int *)(lVar1 + 0x4c) != 0) {
    uVar5 = (uint)bVar7;
  }
  return (long)*(int *)(lVar1 + 8) * (uVar6 + (ulong)uVar2 + (ulong)uVar4 + (ulong)uVar5) * 0x10 +
         (long)*(int *)(lVar1 + 0x38) * 4;
}



uint FUN_71005e88ec(long param_1,long param_2,long param_3)

{
  undefined8 *puVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  undefined4 *puVar5;
  undefined4 *puVar6;
  long lVar7;
  undefined8 uVar8;
  
  puVar1 = (undefined8 *)(param_3 + (ulong)*(uint *)(param_3 + 0x14));
  puVar2 = (undefined4 *)0x0;
  if (*(uint *)((long)puVar1 + 0x3c) != 0) {
    puVar2 = (undefined4 *)((long)puVar1 + (ulong)*(uint *)((long)puVar1 + 0x3c));
  }
  puVar3 = (undefined4 *)0x0;
  if (*(uint *)(puVar1 + 8) != 0) {
    puVar3 = (undefined4 *)((long)puVar1 + (ulong)*(uint *)(puVar1 + 8));
  }
  puVar4 = (undefined4 *)0x0;
  if (*(uint *)((long)puVar1 + 0x44) != 0) {
    puVar4 = (undefined4 *)((long)puVar1 + (ulong)*(uint *)((long)puVar1 + 0x44));
  }
  puVar5 = (undefined4 *)0x0;
  if (*(uint *)(puVar1 + 9) != 0) {
    puVar5 = (undefined4 *)((long)puVar1 + (ulong)*(uint *)(puVar1 + 9));
  }
  puVar6 = (undefined4 *)0x0;
  if (*(uint *)((long)puVar1 + 0x4c) != 0) {
    puVar6 = (undefined4 *)((long)puVar1 + (ulong)*(uint *)((long)puVar1 + 0x4c));
  }
  lVar7 = 0;
  if (*(uint *)(puVar1 + 10) != 0) {
    lVar7 = (long)puVar1 + (ulong)*(uint *)(puVar1 + 10);
  }
  uVar8 = FUN_71005e8980(param_1,param_2,*puVar1,*(uint *)(puVar1 + 7),*(int *)(puVar1 + 1),puVar2,
                         puVar3,puVar4,puVar5,puVar6,lVar7);
  return (uint)uVar8 & 1;
}



undefined8
FUN_71005e8980(long param_1,long param_2,undefined8 param_3,uint param_4,int param_5,
              undefined4 *param_6,undefined4 *param_7,undefined4 *param_8,undefined4 *param_9,
              undefined4 *param_10,undefined8 param_11)

{
  undefined4 *puVar1;
  uint uVar2;
  undefined4 *puVar3;
  undefined8 uVar4;
  int iVar5;
  ulong uVar6;
  long lVar7;
  undefined4 *puVar8;
  undefined4 *puVar9;
  undefined4 *puVar10;
  ulong uVar11;
  undefined4 *puVar12;
  undefined4 *puVar13;
  long lVar14;
  
  *(int *)(param_1 + 0x94) = param_5;
  *(uint *)(param_1 + 0x98) = param_4;
  *(undefined8 *)(param_1 + 0x88) = param_3;
  *(undefined1 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0x90) = 0;
  if (param_6 == (undefined4 *)0x0) {
    uVar6 = 0;
    *(undefined8 *)(param_1 + 0x50) = 0;
    if (param_7 == (undefined4 *)0x0) goto LAB_71005e8a30;
LAB_71005e89c0:
    iVar5 = (int)uVar6;
    uVar2 = iVar5 + 1;
    uVar6 = (ulong)uVar2;
    *(uint *)(param_1 + 0x90) = uVar2;
    *(ulong *)(param_1 + 0x58) = (ulong)(uint)(iVar5 << 4);
    if (param_8 != (undefined4 *)0x0) goto LAB_71005e89d8;
LAB_71005e8a40:
    *(undefined8 *)(param_1 + 0x60) = 0;
    if (param_9 == (undefined4 *)0x0) goto LAB_71005e8a50;
LAB_71005e89f4:
    uVar2 = (int)uVar6 + 1;
    *(uint *)(param_1 + 0x90) = uVar2;
    *(ulong *)(param_1 + 0x68) = uVar6 << 4;
    uVar6 = (ulong)uVar2;
    if (param_10 != (undefined4 *)0x0) goto LAB_71005e8a10;
LAB_71005e8a60:
    lVar7 = 0;
  }
  else {
    uVar6 = 1;
    *(undefined4 *)(param_1 + 0x90) = 1;
    *(undefined8 *)(param_1 + 0x50) = 0;
    if (param_7 != (undefined4 *)0x0) goto LAB_71005e89c0;
LAB_71005e8a30:
    *(undefined8 *)(param_1 + 0x58) = 0;
    if (param_8 == (undefined4 *)0x0) goto LAB_71005e8a40;
LAB_71005e89d8:
    uVar2 = (int)uVar6 + 1;
    *(uint *)(param_1 + 0x90) = uVar2;
    *(ulong *)(param_1 + 0x60) = uVar6 << 4;
    uVar6 = (ulong)uVar2;
    if (param_9 != (undefined4 *)0x0) goto LAB_71005e89f4;
LAB_71005e8a50:
    *(undefined8 *)(param_1 + 0x68) = 0;
    if (param_10 == (undefined4 *)0x0) goto LAB_71005e8a60;
LAB_71005e8a10:
    uVar2 = (int)uVar6 + 1;
    *(uint *)(param_1 + 0x90) = uVar2;
    lVar7 = uVar6 << 4;
    uVar6 = (ulong)uVar2;
  }
  uVar11 = -(ulong)(param_4 >> 0x1f) & 0xfffffffc00000000 | (ulong)param_4 << 2;
  *(long *)(param_1 + 0x70) = lVar7;
  lVar7 = (long)(int)uVar6 * (long)param_5 * 0x10;
  *(undefined4 **)(param_1 + 0x30) = param_6;
  *(undefined4 **)(param_1 + 0x38) = param_7;
  *(undefined8 *)(param_1 + 0x40) = param_11;
  *(ulong *)(param_1 + 0x48) = uVar6 << 4;
  *(long *)(param_1 + 0x78) = lVar7;
  *(ulong *)(param_1 + 0x80) = uVar11;
  if (param_2 != 0) {
    lVar14 = *(long *)(param_2 + 0x198);
    uVar6 = ((uVar11 + lVar7 + *(long *)(param_2 + 0x168)) - 1 & -*(long *)(param_2 + 0x168)) +
            lVar14;
    if (uVar6 <= *(ulong *)(param_2 + 0x170)) {
      *(ulong *)(param_2 + 0x198) = uVar6;
      if (*(long *)(param_2 + 0x1a0) != 0) {
        puVar3 = (undefined4 *)(*(long *)(param_2 + 0x1a0) + lVar14);
        puVar13 = puVar3;
        if (0 < param_5) {
          puVar9 = param_8;
          puVar8 = param_7;
          puVar12 = param_10;
          puVar10 = param_9;
          if (param_6 == (undefined4 *)0x0) {
            do {
              if (param_7 != (undefined4 *)0x0) {
                *puVar13 = *puVar8;
                puVar13[1] = puVar8[1];
                puVar13[2] = puVar8[2];
                puVar1 = puVar8 + 3;
                puVar8 = puVar8 + 4;
                puVar13[3] = *puVar1;
                puVar13 = puVar13 + 4;
              }
              if (param_8 != (undefined4 *)0x0) {
                *puVar13 = *puVar9;
                puVar13[1] = puVar9[1];
                puVar13[2] = puVar9[2];
                puVar1 = puVar9 + 3;
                puVar9 = puVar9 + 4;
                puVar13[3] = *puVar1;
                puVar13 = puVar13 + 4;
              }
              if (param_9 != (undefined4 *)0x0) {
                *puVar13 = *puVar10;
                puVar13[1] = puVar10[1];
                puVar13[2] = puVar10[2];
                puVar1 = puVar10 + 3;
                puVar10 = puVar10 + 4;
                puVar13[3] = *puVar1;
                puVar13 = puVar13 + 4;
              }
              if (param_10 != (undefined4 *)0x0) {
                *puVar13 = *puVar12;
                puVar13[1] = puVar12[1];
                puVar13[2] = puVar12[2];
                puVar1 = puVar12 + 3;
                puVar12 = puVar12 + 4;
                puVar13[3] = *puVar1;
                puVar13 = puVar13 + 4;
              }
              param_5 = param_5 + -1;
            } while (param_5 != 0);
          }
          else {
            puVar8 = param_8;
            puVar10 = param_10;
            puVar9 = param_9;
            if (param_7 == (undefined4 *)0x0) {
              do {
                *puVar13 = *param_6;
                puVar13[1] = param_6[1];
                puVar13[2] = param_6[2];
                puVar13[3] = param_6[3];
                if (param_8 == (undefined4 *)0x0) {
                  puVar13 = puVar13 + 4;
                }
                else {
                  puVar13[4] = *puVar8;
                  puVar13[5] = puVar8[1];
                  puVar13[6] = puVar8[2];
                  puVar12 = puVar8 + 3;
                  puVar8 = puVar8 + 4;
                  puVar13[7] = *puVar12;
                  puVar13 = puVar13 + 8;
                }
                if (param_9 != (undefined4 *)0x0) {
                  *puVar13 = *puVar9;
                  puVar13[1] = puVar9[1];
                  puVar13[2] = puVar9[2];
                  puVar12 = puVar9 + 3;
                  puVar9 = puVar9 + 4;
                  puVar13[3] = *puVar12;
                  puVar13 = puVar13 + 4;
                }
                if (param_10 != (undefined4 *)0x0) {
                  *puVar13 = *puVar10;
                  puVar13[1] = puVar10[1];
                  puVar13[2] = puVar10[2];
                  puVar12 = puVar10 + 3;
                  puVar10 = puVar10 + 4;
                  puVar13[3] = *puVar12;
                  puVar13 = puVar13 + 4;
                }
                param_5 = param_5 + -1;
                param_6 = param_6 + 4;
              } while (param_5 != 0);
            }
            else {
              puVar8 = param_10;
              if (param_8 == (undefined4 *)0x0) {
                do {
                  *puVar13 = *param_6;
                  puVar13[1] = param_6[1];
                  puVar13[2] = param_6[2];
                  puVar13[3] = param_6[3];
                  puVar13[4] = *param_7;
                  puVar13[5] = param_7[1];
                  puVar13[6] = param_7[2];
                  puVar13[7] = param_7[3];
                  if (param_9 == (undefined4 *)0x0) {
                    puVar13 = puVar13 + 8;
                  }
                  else {
                    puVar13[8] = *puVar9;
                    puVar13[9] = puVar9[1];
                    puVar13[10] = puVar9[2];
                    puVar10 = puVar9 + 3;
                    puVar9 = puVar9 + 4;
                    puVar13[0xb] = *puVar10;
                    puVar13 = puVar13 + 0xc;
                  }
                  if (param_10 != (undefined4 *)0x0) {
                    *puVar13 = *puVar8;
                    puVar13[1] = puVar8[1];
                    puVar13[2] = puVar8[2];
                    puVar10 = puVar8 + 3;
                    puVar8 = puVar8 + 4;
                    puVar13[3] = *puVar10;
                    puVar13 = puVar13 + 4;
                  }
                  param_5 = param_5 + -1;
                  param_6 = param_6 + 4;
                  param_7 = param_7 + 4;
                } while (param_5 != 0);
              }
              else {
                do {
                  *puVar13 = *param_6;
                  puVar13[1] = param_6[1];
                  puVar13[2] = param_6[2];
                  puVar13[3] = param_6[3];
                  puVar13[4] = *param_7;
                  puVar13[5] = param_7[1];
                  puVar13[6] = param_7[2];
                  puVar13[7] = param_7[3];
                  puVar13[8] = *param_8;
                  puVar13[9] = param_8[1];
                  puVar13[10] = param_8[2];
                  puVar13[0xb] = param_8[3];
                  if (param_9 == (undefined4 *)0x0) {
                    puVar13 = puVar13 + 0xc;
                  }
                  else {
                    puVar13[0xc] = *puVar9;
                    puVar13[0xd] = puVar9[1];
                    puVar13[0xe] = puVar9[2];
                    puVar10 = puVar9 + 3;
                    puVar9 = puVar9 + 4;
                    puVar13[0xf] = *puVar10;
                    puVar13 = puVar13 + 0x10;
                  }
                  if (param_10 != (undefined4 *)0x0) {
                    *puVar13 = *puVar8;
                    puVar13[1] = puVar8[1];
                    puVar13[2] = puVar8[2];
                    puVar10 = puVar8 + 3;
                    puVar8 = puVar8 + 4;
                    puVar13[3] = *puVar10;
                    puVar13 = puVar13 + 4;
                  }
                  param_5 = param_5 + -1;
                  param_6 = param_6 + 4;
                  param_7 = param_7 + 4;
                  param_8 = param_8 + 4;
                } while (param_5 != 0);
              }
            }
          }
        }
        thunk_EXT_FUN_02e95df0(puVar13,param_11,*(undefined8 *)(param_1 + 0x80));
        uVar4 = *(undefined8 *)(param_2 + 400);
        *(undefined8 *)(param_1 + 0x10) = *(undefined8 *)(param_2 + 0x188);
        *(undefined8 *)(param_1 + 0x18) = uVar4;
        lVar7 = *(long *)(param_2 + 0x188);
        uVar4 = *(undefined8 *)(param_2 + 400);
        *(long *)(param_1 + 0x20) = lVar7;
        *(undefined8 *)(param_1 + 0x28) = uVar4;
        *(long *)(param_1 + 0x10) = *(long *)(param_1 + 0x10) + lVar14;
        *(long *)(param_1 + 0x20) = (long)puVar13 + lVar7 + (lVar14 - (long)puVar3);
        goto LAB_71005e8e7c;
      }
    }
    return 0;
  }
LAB_71005e8e7c:
  *(undefined1 *)(param_1 + 8) = 1;
  return 1;
}



undefined8 FUN_71005e8ea0(long param_1,long param_2,long param_3)

{
  bool bVar1;
  long lVar2;
  uint uVar3;
  byte bVar4;
  int iVar5;
  int iVar6;
  long lVar7;
  long lVar8;
  long lVar9;
  ulong uVar10;
  short *psVar11;
  uint *puVar12;
  ulong uVar13;
  ulong uVar14;
  long lVar15;
  long lVar16;
  long lVar17;
  
  *(long *)(param_1 + 0x10) = param_2;
  lVar7 = *(long *)(param_2 + 0x20);
  *(long *)(param_1 + 0x18) = lVar7;
  lVar8 = *(long *)(param_2 + 0x28);
  *(long *)(param_1 + 0x20) = lVar8;
  *(undefined8 *)(param_1 + 0x28) = *(undefined8 *)(lVar8 + 0x18);
  lVar8 = *(long *)(lVar7 + 0x10);
  if (lVar8 != 0) {
    uVar10 = (ulong)*(ushort *)(lVar8 + 0xc);
    puVar12 = (uint *)((int *)(lVar8 + 8) + uVar10 * 4);
    uVar3 = *puVar12;
    if (*(int *)(lVar8 + 8) < (int)uVar3) {
      do {
        if (uVar3 < 0x18) {
          uVar14 = (ulong)((byte)(&UNK_7103169547)[-(ulong)(uVar3 >> 3)] >> ((ulong)uVar3 & 7)) & 1;
        }
        else {
          uVar14 = 0;
        }
        uVar10 = (ulong)*(ushort *)(lVar8 + 8 + uVar10 * 0x10 + uVar14 * 2 + 4);
        puVar12 = (uint *)(lVar8 + 8 + uVar10 * 0x10);
        bVar1 = (int)uVar3 < (int)*puVar12;
        uVar3 = *puVar12;
      } while (bVar1);
    }
    psVar11 = *(short **)(puVar12 + 2);
    if (((*psVar11 == 3) && (psVar11[1] == 0x705f && (char)psVar11[2] == '0')) &&
       (uVar10 = (long)puVar12 + (-0x18 - lVar8), ((uVar10 ^ 0xffffffffffffffff) & 0xffffffff0) != 0
       )) {
      lVar7 = *(long *)(lVar7 + 8) + (long)(int)(uVar10 >> 4) * 0x10;
      goto LAB_71005e8fa4;
    }
  }
  lVar7 = 0;
LAB_71005e8fa4:
  lVar8 = 0;
  do {
    while( true ) {
      lVar15 = (&DAT_71038006d8)[lVar8];
      lVar16 = *(long *)(param_1 + 0x18);
      uVar10 = thunk_EXT_FUN_02e95df0(lVar15);
      lVar17 = *(long *)(lVar16 + 0x10);
      if (lVar17 != 0) break;
LAB_71005e9060:
      lVar15 = 0;
      if (lVar8 != 4) goto LAB_71005e91c0;
LAB_71005e906c:
      if (lVar15 != 0) goto LAB_71005e91c0;
      if ((lVar17 != 0) && (*(byte *)(param_3 + 0x14) != 0xff)) {
        lVar15 = *(long *)(lVar17 + 8 + (ulong)*(byte *)(param_3 + 0x14) * 0x10 + 0x18) + 2;
        uVar10 = thunk_EXT_FUN_02e95df0(lVar15);
        uVar14 = (ulong)*(ushort *)(lVar17 + 0xc);
        puVar12 = (uint *)(lVar17 + 8 + uVar14 * 0x10);
        uVar3 = *puVar12;
        if (*(int *)(lVar17 + 8) < (int)*puVar12) {
          do {
            uVar13 = (long)((ulong)uVar3 << 0x20) >> 0x23;
            if (uVar13 < uVar10) {
              uVar13 = (ulong)(*(byte *)(lVar15 + uVar10 + ~uVar13) >> ((ulong)uVar3 & 7)) & 1;
            }
            else {
              uVar13 = 0;
            }
            uVar14 = (ulong)*(ushort *)(lVar17 + 8 + uVar14 * 0x10 + uVar13 * 2 + 4);
            puVar12 = (uint *)(lVar17 + 8 + uVar14 * 0x10);
            bVar1 = (int)uVar3 < (int)*puVar12;
            uVar3 = *puVar12;
          } while (bVar1);
        }
        if (((uVar10 == **(ushort **)(puVar12 + 2)) &&
            (iVar5 = thunk_EXT_FUN_02e95df0(*(ushort **)(puVar12 + 2) + 1,lVar15), iVar5 == 0)) &&
           (uVar10 = (long)puVar12 + (-0x18 - lVar17),
           ((uVar10 ^ 0xffffffffffffffff) & 0xffffffff0) != 0)) {
          lVar15 = *(long *)(lVar16 + 8) + (long)(int)(uVar10 >> 4) * 0x10;
          goto LAB_71005e91c0;
        }
      }
LAB_71005e8fc0:
      lVar15 = param_1 + lVar8 * 4;
      *(uint *)(lVar15 + 0x7c) = (uint)*(byte *)(lVar7 + 0xe);
      *(undefined4 *)(lVar15 + 0x68) = *(undefined4 *)(lVar7 + 8);
      lVar15 = lVar8 * 8;
      lVar8 = lVar8 + 1;
      *(ulong *)(param_1 + lVar15 + 0x40) = (ulong)*(ushort *)(lVar7 + 0xc);
      if (lVar8 == 5) goto LAB_71005e9440;
    }
    uVar14 = (ulong)*(ushort *)(lVar17 + 0xc);
    puVar12 = (uint *)((int *)(lVar17 + 8) + uVar14 * 4);
    uVar3 = *puVar12;
    if (*(int *)(lVar17 + 8) < (int)*puVar12) {
      do {
        uVar13 = (long)((ulong)uVar3 << 0x20) >> 0x23;
        if (uVar13 < uVar10) {
          uVar13 = (ulong)(*(byte *)(lVar15 + uVar10 + ~uVar13) >> ((ulong)uVar3 & 7)) & 1;
        }
        else {
          uVar13 = 0;
        }
        uVar14 = (ulong)*(ushort *)(lVar17 + 8 + uVar14 * 0x10 + uVar13 * 2 + 4);
        puVar12 = (uint *)(lVar17 + 8 + uVar14 * 0x10);
        bVar1 = (int)uVar3 < (int)*puVar12;
        uVar3 = *puVar12;
      } while (bVar1);
    }
    if (((uVar10 != **(ushort **)(puVar12 + 2)) ||
        (iVar5 = thunk_EXT_FUN_02e95df0(*(ushort **)(puVar12 + 2) + 1,lVar15), iVar5 != 0)) ||
       (uVar10 = (long)puVar12 + (-0x18 - lVar17),
       ((uVar10 ^ 0xffffffffffffffff) & 0xffffffff0) == 0)) goto LAB_71005e9060;
    lVar15 = *(long *)(lVar16 + 8) + (long)(int)(uVar10 >> 4) * 0x10;
    if (lVar8 == 4) goto LAB_71005e906c;
LAB_71005e91c0:
    if (lVar15 == 0) goto LAB_71005e8fc0;
    iVar5 = *(int *)(lVar15 + 8);
    lVar2 = param_1 + lVar8 * 4;
    if (lVar8 == 4) {
      if (lVar17 == 0) {
LAB_71005e923c:
        bVar4 = *(byte *)(param_3 + 0x15);
        if (((bVar4 != 0xff) && (lVar17 != 0)) && (bVar4 < *(byte *)(lVar16 + 0x4c))) {
          lVar9 = *(long *)(lVar17 + 8 + (ulong)bVar4 * 0x10 + 0x18) + 2;
          uVar10 = thunk_EXT_FUN_02e95df0(lVar9);
          uVar14 = (ulong)*(ushort *)(lVar17 + 0xc);
          puVar12 = (uint *)(lVar17 + 8 + uVar14 * 0x10);
          uVar3 = *puVar12;
          if (*(int *)(lVar17 + 8) < (int)*puVar12) {
            do {
              uVar13 = (long)((ulong)uVar3 << 0x20) >> 0x23;
              if (uVar13 < uVar10) {
                uVar13 = (ulong)(*(byte *)(lVar9 + uVar10 + ~uVar13) >> ((ulong)uVar3 & 7)) & 1;
              }
              else {
                uVar13 = 0;
              }
              uVar14 = (ulong)*(ushort *)(lVar17 + 8 + uVar14 * 0x10 + uVar13 * 2 + 4);
              puVar12 = (uint *)(lVar17 + 8 + uVar14 * 0x10);
              bVar1 = (int)uVar3 < (int)*puVar12;
              uVar3 = *puVar12;
            } while (bVar1);
          }
          if ((((uVar10 == **(ushort **)(puVar12 + 2)) &&
               (iVar6 = thunk_EXT_FUN_02e95df0(*(ushort **)(puVar12 + 2) + 1,lVar9), iVar6 == 0)) &&
              (uVar10 = (long)puVar12 + (-0x18 - lVar17),
              ((uVar10 ^ 0xffffffffffffffff) & 0xffffffff0) != 0)) &&
             (lVar9 = *(long *)(lVar16 + 8), lVar9 != 0)) goto LAB_71005e93b4;
        }
      }
      else {
        uVar10 = (ulong)*(ushort *)(lVar17 + 0xc);
        puVar12 = (uint *)((int *)(lVar17 + 8) + uVar10 * 4);
        uVar3 = *puVar12;
        if (*(int *)(lVar17 + 8) < (int)*puVar12) {
          do {
            if (uVar3 < 0x18) {
              uVar14 = (ulong)((byte)(&UNK_71030fb0de)[-(ulong)(uVar3 >> 3)] >> ((ulong)uVar3 & 7))
                       & 1;
            }
            else {
              uVar14 = 0;
            }
            uVar10 = (ulong)*(ushort *)(lVar17 + 8 + uVar10 * 0x10 + uVar14 * 2 + 4);
            puVar12 = (uint *)(lVar17 + 8 + uVar10 * 0x10);
            bVar1 = (int)uVar3 < (int)*puVar12;
            uVar3 = *puVar12;
          } while (bVar1);
        }
        psVar11 = *(short **)(puVar12 + 2);
        if (((*psVar11 != 3) || (psVar11[1] != 0x755f || (char)psVar11[2] != '1')) ||
           ((uVar10 = (long)puVar12 + (-0x18 - lVar17),
            ((uVar10 ^ 0xffffffffffffffff) & 0xffffffff0) == 0 ||
            (lVar9 = *(long *)(lVar16 + 8), lVar9 == 0)))) goto LAB_71005e923c;
LAB_71005e93b4:
        if (iVar5 == *(int *)(lVar9 + (long)(int)(uVar10 >> 4) * 0x10 + 8)) {
          iVar6 = 0xb01;
          if (iVar5 != 0x901) {
            iVar6 = iVar5;
          }
          iVar5 = 0x1501;
          if (iVar6 != 0x1201) {
            iVar5 = iVar6;
          }
          iVar6 = 0x1505;
          if (iVar5 != 0x1205) {
            iVar6 = iVar5;
          }
          iVar5 = 0x1905;
          if (iVar6 != 0x1705) {
            iVar5 = iVar6;
          }
          iVar6 = 0xb02;
          if (iVar5 != 0x902) {
            iVar6 = iVar5;
          }
          iVar5 = 0x1502;
          if (iVar6 != 0x1202) {
            iVar5 = iVar6;
          }
        }
        else {
          FUN_71005dee10();
        }
      }
      *(int *)(param_1 + 0x78) = iVar5;
    }
    else {
      *(int *)(lVar2 + 0x68) = iVar5;
    }
    *(uint *)(lVar2 + 0x7c) = (uint)*(byte *)(lVar15 + 0xe);
    lVar16 = lVar8 * 8;
    lVar8 = lVar8 + 1;
    *(ulong *)(param_1 + lVar16 + 0x40) = (ulong)*(ushort *)(lVar15 + 0xc);
  } while (lVar8 != 5);
LAB_71005e9440:
  FUN_71005fc2ac(*(long *)(*(long *)(param_1 + 0x28) + 0x10),(undefined8 *)(param_1 + 0x30));
  return 1;
}



void FUN_71005e9484(undefined1 *param_1)

{
  *param_1 = 0xff;
  return;
}



bool FUN_71005e9490(undefined1 *param_1,long param_2,ulong param_3,uint param_4,long param_5)

{
  uint uVar1;
  
  uVar1 = FUN_7100602fd0(param_2,param_3 & 0xffffffff,param_4,param_5);
  *param_1 = (char)uVar1;
  return ((uVar1 ^ 0xffffffff) & 0xff) != 0;
}



void FUN_71005e94d0(undefined1 *param_1)

{
  *param_1 = 0xff;
  return;
}



void FUN_71005e94dc(long param_1)

{
  FUN_71005e94d0((undefined1 *)(param_1 + 0x39));
  FUN_71005e94d0((undefined1 *)(param_1 + 0x7b));
  FUN_71005e94d0((undefined1 *)(param_1 + 0x3a));
  FUN_71005e94d0((undefined1 *)(param_1 + 0x7c));
  FUN_71005e94d0((undefined1 *)(param_1 + 0x3b));
  FUN_71005e94d0((undefined1 *)(param_1 + 0x7d));
  FUN_71005e94d0((undefined1 *)(param_1 + 0x3c));
  FUN_71005e94d0((undefined1 *)(param_1 + 0x7e));
  FUN_71005e94d0((undefined1 *)(param_1 + 0x3d));
  FUN_71005e94d0((undefined1 *)(param_1 + 0x7f));
  FUN_71005e94d0((undefined1 *)(param_1 + 0x3e));
  FUN_71005e94d0((undefined1 *)(param_1 + 0x80));
  FUN_71005e94d0((undefined1 *)(param_1 + 0x3f));
  FUN_71005e94d0((undefined1 *)(param_1 + 0x81));
  FUN_71005e94d0((undefined1 *)(param_1 + 0x40));
  FUN_71005e94d0((undefined1 *)(param_1 + 0x82));
  FUN_71005e94d0((undefined1 *)(param_1 + 0x41));
  FUN_71005e94d0((undefined1 *)(param_1 + 0x83));
  FUN_71005e94d0((undefined1 *)(param_1 + 0x42));
  FUN_71005e94d0((undefined1 *)(param_1 + 0x84));
  FUN_71005e94d0((undefined1 *)(param_1 + 0x43));
  FUN_71005e94d0((undefined1 *)(param_1 + 0x85));
  FUN_71005e94d0((undefined1 *)(param_1 + 0x44));
  FUN_71005e94d0((undefined1 *)(param_1 + 0x86));
  FUN_71005e94d0((undefined1 *)(param_1 + 0x45));
  FUN_71005e94d0((undefined1 *)(param_1 + 0x87));
  return;
}



void FUN_71005e95c4(long param_1)

{
  *(undefined1 *)(param_1 + 0x8c) = 0;
  return;
}



bool FUN_71005e95cc(long *param_1,long param_2)

{
  bool bVar1;
  
  *param_1 = param_2;
  bVar1 = FUN_71005e9600(param_1);
  *(undefined1 *)((long)param_1 + 0x8c) = 1;
  return bVar1;
}



bool FUN_71005e9600(long *param_1)

{
  long *plVar1;
  long *plVar2;
  long *plVar3;
  long *plVar4;
  long *plVar5;
  long lVar6;
  bool bVar7;
  long lVar8;
  
  FUN_71005e94d0((undefined1 *)((long)param_1 + 0x39));
  FUN_71005e94d0((undefined1 *)((long)param_1 + 0x3a));
  FUN_71005e94d0((undefined1 *)((long)param_1 + 0x3b));
  FUN_71005e94d0((undefined1 *)((long)param_1 + 0x3c));
  FUN_71005e94d0((undefined1 *)((long)param_1 + 0x3d));
  FUN_71005e94d0((undefined1 *)((long)param_1 + 0x3e));
  FUN_71005e94d0((undefined1 *)((long)param_1 + 0x7b));
  FUN_71005e94d0((undefined1 *)((long)param_1 + 0x7c));
  FUN_71005e94d0((undefined1 *)((long)param_1 + 0x7d));
  FUN_71005e94d0((undefined1 *)((long)param_1 + 0x7e));
  FUN_71005e94d0((undefined1 *)((long)param_1 + 0x7f));
  FUN_71005e94d0((undefined1 *)(param_1 + 0x10));
  FUN_71005e94d0((undefined1 *)((long)param_1 + 0x3f));
  FUN_71005e94d0((undefined1 *)(param_1 + 8));
  FUN_71005e94d0((undefined1 *)((long)param_1 + 0x41));
  FUN_71005e94d0((undefined1 *)((long)param_1 + 0x42));
  FUN_71005e94d0((undefined1 *)((long)param_1 + 0x43));
  FUN_71005e94d0((undefined1 *)((long)param_1 + 0x44));
  FUN_71005e94d0((undefined1 *)((long)param_1 + 0x81));
  FUN_71005e94d0((undefined1 *)((long)param_1 + 0x82));
  FUN_71005e94d0((undefined1 *)((long)param_1 + 0x83));
  FUN_71005e94d0((undefined1 *)((long)param_1 + 0x84));
  FUN_71005e94d0((undefined1 *)((long)param_1 + 0x85));
  FUN_71005e94d0((undefined1 *)((long)param_1 + 0x86));
  FUN_71005e94d0((undefined1 *)((long)param_1 + 0x45));
  FUN_71005e94d0((undefined1 *)((long)param_1 + 0x87));
  plVar1 = DAT_7103a6fb10;
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x39),*param_1,0,3,*DAT_7103a6fb10);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x3a),*param_1,0,3,plVar1[1]);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x3b),*param_1,0,3,plVar1[2]);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x3c),*param_1,0,3,plVar1[3]);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x3d),*param_1,0,3,plVar1[4]);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x3e),*param_1,0,3,plVar1[5]);
  plVar2 = DAT_7103a6fb18;
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x3f),*param_1,0,3,*DAT_7103a6fb18);
  FUN_71005e9490((undefined1 *)(param_1 + 8),*param_1,0,3,plVar2[1]);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x41),*param_1,0,3,plVar2[2]);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x42),*param_1,0,3,plVar2[3]);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x43),*param_1,0,3,plVar2[4]);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x44),*param_1,0,3,plVar2[5]);
  plVar3 = DAT_7103a6fb20;
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x45),*param_1,0,4,*DAT_7103a6fb20);
  plVar4 = DAT_7103a6fb28;
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x46),*param_1,0,4,*DAT_7103a6fb28);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x47),*param_1,0,4,plVar4[1]);
  FUN_71005e9490((undefined1 *)(param_1 + 9),*param_1,0,4,plVar4[2]);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x49),*param_1,0,4,plVar4[3]);
  plVar5 = DAT_7103a6fb30;
  FUN_71005e9490((undefined1 *)(param_1 + 1),*param_1,0,2,*DAT_7103a6fb30);
  FUN_71005e9490((undefined1 *)((long)param_1 + 9),*param_1,0,2,plVar5[1]);
  FUN_71005e9490((undefined1 *)((long)param_1 + 10),*param_1,0,2,plVar5[2]);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0xb),*param_1,0,2,plVar5[3]);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0xc),*param_1,0,2,plVar5[4]);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0xd),*param_1,0,2,plVar5[5]);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0xe),*param_1,0,2,plVar5[6]);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0xf),*param_1,0,2,plVar5[7]);
  FUN_71005e9490((undefined1 *)(param_1 + 2),*param_1,0,2,plVar5[8]);
  lVar6 = DAT_7103a6fb38;
  lVar8 = 0;
  do {
    FUN_71005e9490((undefined1 *)((long)param_1 + lVar8 + 0x11),*param_1,0,2,
                   *(long *)(lVar6 + lVar8 * 8));
    lVar8 = lVar8 + 1;
  } while (lVar8 != 0x28);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x7b),*param_1,4,3,*plVar1);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x7c),*param_1,4,3,plVar1[1]);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x7d),*param_1,4,3,plVar1[2]);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x7e),*param_1,4,3,plVar1[3]);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x7f),*param_1,4,3,plVar1[4]);
  FUN_71005e9490((undefined1 *)(param_1 + 0x10),*param_1,4,3,plVar1[5]);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x81),*param_1,4,3,*plVar2);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x82),*param_1,4,3,plVar2[1]);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x83),*param_1,4,3,plVar2[2]);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x84),*param_1,4,3,plVar2[3]);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x85),*param_1,4,3,plVar2[4]);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x86),*param_1,4,3,plVar2[5]);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x87),*param_1,4,4,*plVar3);
  FUN_71005e9490((undefined1 *)(param_1 + 0x11),*param_1,4,4,*plVar4);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x89),*param_1,4,4,plVar4[1]);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x8a),*param_1,4,4,plVar4[2]);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x8b),*param_1,4,4,plVar4[3]);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x4a),*param_1,4,2,*plVar5);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x4b),*param_1,4,2,plVar5[1]);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x4c),*param_1,4,2,plVar5[2]);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x4d),*param_1,4,2,plVar5[3]);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x4e),*param_1,4,2,plVar5[4]);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x4f),*param_1,4,2,plVar5[5]);
  FUN_71005e9490((undefined1 *)(param_1 + 10),*param_1,4,2,plVar5[6]);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x51),*param_1,4,2,plVar5[7]);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x52),*param_1,4,2,plVar5[8]);
  lVar8 = 0;
  do {
    bVar7 = FUN_71005e9490((undefined1 *)((long)param_1 + lVar8 + 0x53),*param_1,4,2,
                           *(long *)(lVar6 + lVar8 * 8));
    lVar8 = lVar8 + 1;
  } while (lVar8 != 0x28);
  return bVar7;
}



void FUN_71005e9cc8(long param_1,long param_2,byte param_3,undefined8 param_4,undefined8 param_5)

{
  char cVar1;
  int iVar2;
  
  cVar1 = *(char *)(param_1 + (ulong)param_3 + 0x81);
  iVar2 = (int)*(char *)(param_1 + (ulong)param_3 + 0x3f);
  if (iVar2 != -1) {
    FUN_71005fd4d4(param_2,iVar2,0,param_4,param_5);
  }
  iVar2 = (int)cVar1;
  if (iVar2 != -1) {
    FUN_71005fd4d4(param_2,iVar2,4,param_4,param_5);
    return;
  }
  return;
}



void FUN_71005e9d48(long param_1)

{
  FUN_71005e94d0((undefined1 *)(param_1 + 0x42));
  FUN_71005e94d0((undefined1 *)(param_1 + 0x43));
  FUN_71005e94d0((undefined1 *)(param_1 + 0x44));
  FUN_71005e94d0((undefined1 *)(param_1 + 0x45));
  FUN_71005e94d0((undefined1 *)(param_1 + 0x46));
  FUN_71005e94d0((undefined1 *)(param_1 + 0x47));
  FUN_71005e94d0((undefined1 *)(param_1 + 0x48));
  FUN_71005e94d0((undefined1 *)(param_1 + 0x49));
  FUN_71005e94d0((undefined1 *)(param_1 + 0x4a));
  FUN_71005e94d0((undefined1 *)(param_1 + 0x4b));
  FUN_71005e94d0((undefined1 *)(param_1 + 0x4c));
  FUN_71005e94d0((undefined1 *)(param_1 + 0x4d));
  FUN_71005e94d0((undefined1 *)(param_1 + 0x4e));
  return;
}



void FUN_71005e9dc8(long param_1)

{
  *(undefined1 *)(param_1 + 0x53) = 0;
  return;
}



bool FUN_71005e9dd0(long *param_1,long param_2)

{
  bool bVar1;
  
  *param_1 = param_2;
  bVar1 = FUN_71005e9e00(param_1);
  *(undefined1 *)((long)param_1 + 0x53) = 1;
  return bVar1;
}



bool FUN_71005e9e00(long *param_1)

{
  long *plVar1;
  long lVar2;
  bool bVar3;
  long lVar4;
  
  plVar1 = DAT_7103a6fb10;
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x42),*param_1,5,3,*DAT_7103a6fb10);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x43),*param_1,5,3,plVar1[1]);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x44),*param_1,5,3,plVar1[2]);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x45),*param_1,5,3,plVar1[3]);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x46),*param_1,5,3,plVar1[4]);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x47),*param_1,5,3,plVar1[5]);
  plVar1 = DAT_7103a6fb18;
  FUN_71005e9490((undefined1 *)(param_1 + 9),*param_1,5,3,*DAT_7103a6fb18);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x49),*param_1,5,3,plVar1[1]);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x4a),*param_1,5,3,plVar1[2]);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x4b),*param_1,5,3,plVar1[3]);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x4c),*param_1,5,3,plVar1[4]);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x4d),*param_1,5,3,plVar1[5]);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x4e),*param_1,5,4,*DAT_7103a6fb20);
  plVar1 = DAT_7103a6fb28;
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x4f),*param_1,5,4,*DAT_7103a6fb28);
  FUN_71005e9490((undefined1 *)(param_1 + 10),*param_1,5,4,plVar1[1]);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x51),*param_1,5,4,plVar1[2]);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x52),*param_1,5,4,plVar1[3]);
  plVar1 = DAT_7103a6fb30;
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x11),*param_1,5,2,*DAT_7103a6fb30);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x12),*param_1,5,2,plVar1[1]);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x13),*param_1,5,2,plVar1[2]);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x14),*param_1,5,2,plVar1[3]);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x15),*param_1,5,2,plVar1[4]);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x16),*param_1,5,2,plVar1[5]);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x17),*param_1,5,2,plVar1[6]);
  FUN_71005e9490((undefined1 *)(param_1 + 3),*param_1,5,2,plVar1[7]);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0x19),*param_1,5,2,plVar1[8]);
  lVar2 = DAT_7103a6fb38;
  lVar4 = 0;
  do {
    FUN_71005e9490((undefined1 *)((long)param_1 + lVar4 + 0x1a),*param_1,5,2,
                   *(long *)(lVar2 + lVar4 * 8));
    plVar1 = DAT_7103a6fb40;
    lVar4 = lVar4 + 1;
  } while (lVar4 != 0x28);
  FUN_71005e9490((undefined1 *)(param_1 + 1),*param_1,5,4,*DAT_7103a6fb40);
  FUN_71005e9490((undefined1 *)((long)param_1 + 9),*param_1,5,4,plVar1[1]);
  FUN_71005e9490((undefined1 *)((long)param_1 + 10),*param_1,5,4,plVar1[2]);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0xb),*param_1,5,4,plVar1[3]);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0xc),*param_1,5,4,plVar1[4]);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0xd),*param_1,5,4,plVar1[5]);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0xe),*param_1,5,4,plVar1[6]);
  FUN_71005e9490((undefined1 *)((long)param_1 + 0xf),*param_1,5,4,plVar1[7]);
  bVar3 = FUN_71005e9490((undefined1 *)(param_1 + 2),*param_1,5,4,plVar1[8]);
  return bVar3;
}



void FUN_71005ea1d8(undefined8 *param_1)

{
  *(undefined4 *)(param_1 + 10) = 0;
  param_1[8] = 0;
  param_1[9] = 0;
  param_1[6] = 0;
  param_1[7] = 0;
  param_1[4] = 0;
  param_1[5] = 0;
  param_1[2] = 0;
  param_1[3] = 0;
  *param_1 = 0;
  param_1[1] = 0;
  return;
}



void FUN_71005ea2f8(undefined8 *param_1,long *param_2,long *param_3)

{
  (**(code **)(*param_3 + 0x18))(param_3,*param_1);
  *param_1 = 0;
                    // WARNING: Could not recover jumptable at 0x0071005ea33c. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_2 + 0x18))(param_2,param_1[1]);
  return;
}



void FUN_71005ea5e0(long param_1,long param_2,char *param_3)

{
  uint uVar1;
  undefined1 auVar2 [16];
  undefined2 uVar3;
  float fVar4;
  int iVar5;
  long lVar6;
  int iVar7;
  undefined4 *puVar8;
  int iVar9;
  long lVar10;
  undefined8 *puVar11;
  int iVar12;
  ulong uVar13;
  int iVar14;
  undefined8 *puVar15;
  float fVar16;
  float fVar17;
  undefined1 uVar18;
  undefined1 uVar19;
  undefined1 uVar20;
  undefined1 uVar21;
  undefined1 uVar22;
  undefined1 uVar23;
  undefined1 uVar24;
  undefined1 uVar25;
  undefined1 uVar26;
  undefined4 uVar27;
  undefined1 auVar28 [16];
  undefined1 auVar29 [16];
  float fVar30;
  float fVar31;
  float fVar32;
  float fVar33;
  undefined1 auVar34 [16];
  undefined1 auVar35 [16];
  undefined1 auVar36 [16];
  float fVar37;
  undefined8 local_90 [2];
  undefined8 local_80 [2];
  
  iVar7 = *(int *)(param_2 + 0x80);
  if (iVar7 < 3) goto LAB_71005ea720;
  if (*(float *)(param_2 + 0x90) <= *(float *)(param_2 + 0x8c)) {
LAB_71005ea640:
    fVar37 = (float)iVar7;
    uVar18 = SUB41(fVar37,0);
    uVar19 = (undefined1)((uint)fVar37 >> 8);
    uVar20 = (undefined1)((uint)fVar37 >> 0x10);
    uVar21 = (undefined1)((uint)fVar37 >> 0x18);
  }
  else if (param_3[3] == '\x01') {
    uVar27 = *(undefined4 *)(param_3 + 8);
    uVar18 = (undefined1)uVar27;
    uVar19 = (undefined1)((uint)uVar27 >> 8);
    uVar20 = (undefined1)((uint)uVar27 >> 0x10);
    uVar21 = (undefined1)((uint)uVar27 >> 0x18);
  }
  else {
    uVar18 = 0;
    uVar19 = 0;
    uVar20 = 0;
    uVar21 = 0;
    if (param_3[3] == '\0') goto LAB_71005ea640;
  }
  iVar9 = (iVar7 + -1) * (int)*(float *)(param_3 + 4);
  uVar1 = iVar9 + iVar7;
  if (0 < (int)uVar1) {
    uVar13 = 0;
    iVar14 = 0;
    puVar15 = (undefined8 *)(param_1 + 0x10);
    puVar11 = *(undefined8 **)(*(long *)(param_2 + 0x68) + 0x30);
    fVar37 = 1.0 / (float)((int)*(float *)(param_3 + 4) + 1);
    do {
      iVar12 = (int)uVar13;
      fVar17 = fVar37 * (float)iVar12;
      iVar5 = (int)fVar17;
      if (iVar14 < iVar5) {
        puVar11 = (undefined8 *)puVar11[6];
        iVar14 = iVar5;
      }
      FUN_71005eb8bc(fVar17 - (float)iVar5,(float *)local_80,local_90,puVar11,iVar5,iVar7);
      uVar13 = uVar13 + 1;
      puVar15[-2] = local_80[0];
      *(int *)(puVar15 + -1) = (int)local_80[1];
      uVar27 = *(undefined4 *)((long)puVar11 + 0xc);
      *(float *)((long)puVar15 + 0xc) =
           (1.0 / ((float)CONCAT13(uVar21,CONCAT12(uVar20,CONCAT11(uVar19,uVar18))) + -1.0 +
                  (float)iVar9)) * (float)iVar12;
      *puVar15 = local_90[0];
      *(int *)(puVar15 + 1) = (int)local_90[1];
      *(undefined4 *)((long)puVar15 + -4) = uVar27;
      puVar15 = puVar15 + 6;
    } while (uVar1 != uVar13);
    *(uint *)(param_2 + 0x88) = uVar1 * 2;
    if (*param_3 == '\0') {
      return;
    }
    if ((int)uVar1 < 1) {
      return;
    }
    uVar13 = 0;
    iVar7 = 0;
    puVar8 = (undefined4 *)(param_1 + 0x28);
    lVar6 = *(long *)(*(long *)(param_2 + 0x68) + 0x30);
    do {
      fVar17 = fVar37 * (float)(int)uVar13;
      iVar9 = (int)fVar17;
      if (iVar7 < iVar9) {
        lVar6 = *(long *)(lVar6 + 0x30);
        iVar7 = iVar9;
      }
      uVar13 = uVar13 + 1;
      lVar10 = *(long *)(lVar6 + 0x30);
      fVar17 = fVar17 - (float)iVar9;
      fVar30 = (float)*(undefined8 *)(lVar6 + 0x20);
      fVar31 = (float)((ulong)*(undefined8 *)(lVar6 + 0x20) >> 0x20);
      fVar32 = (float)*(undefined8 *)(lVar6 + 0x28);
      fVar33 = (float)((ulong)*(undefined8 *)(lVar6 + 0x28) >> 0x20);
      fVar30 = fVar30 + (*(float *)(lVar10 + 0x20) - fVar30) * fVar17;
      fVar31 = fVar31 + (*(float *)(lVar10 + 0x24) - fVar31) * fVar17;
      fVar32 = fVar32 + (*(float *)(lVar10 + 0x28) - fVar32) * fVar17;
      fVar33 = fVar33 + (*(float *)(lVar10 + 0x2c) - fVar33) * fVar17;
      fVar17 = fVar30 * fVar30;
      fVar4 = fVar31 * fVar31;
      uVar18 = (undefined1)((uint)fVar4 >> 8);
      uVar19 = (undefined1)((uint)fVar4 >> 0x10);
      uVar20 = (undefined1)((uint)fVar4 >> 0x18);
      fVar16 = fVar32 * fVar32;
      uVar21 = (undefined1)((uint)fVar16 >> 8);
      uVar22 = (undefined1)((uint)fVar16 >> 0x10);
      uVar23 = (undefined1)((uint)fVar16 >> 0x18);
      fVar33 = fVar33 * fVar33;
      uVar24 = (undefined1)((uint)fVar33 >> 8);
      uVar25 = (undefined1)((uint)fVar33 >> 0x10);
      uVar26 = (undefined1)((uint)fVar33 >> 0x18);
      auVar28[4] = SUB41(fVar4,0);
      auVar28._0_4_ = fVar17;
      auVar28[5] = uVar18;
      auVar28[6] = uVar19;
      auVar28[7] = uVar20;
      auVar28[8] = SUB41(fVar16,0);
      auVar28[9] = uVar21;
      auVar28[10] = uVar22;
      auVar28[0xb] = uVar23;
      auVar28[0xc] = SUB41(fVar33,0);
      auVar28[0xd] = uVar24;
      auVar28[0xe] = uVar25;
      auVar28[0xf] = uVar26;
      auVar35[4] = SUB41(fVar4,0);
      auVar35._0_4_ = fVar17;
      auVar35[5] = uVar18;
      auVar35[6] = uVar19;
      auVar35[7] = uVar20;
      auVar35[8] = SUB41(fVar16,0);
      auVar35[9] = uVar21;
      auVar35[10] = uVar22;
      auVar35[0xb] = uVar23;
      auVar35[0xc] = SUB41(fVar33,0);
      auVar35[0xd] = uVar24;
      auVar35[0xe] = uVar25;
      auVar35[0xf] = uVar26;
      auVar28 = NEON_ext(auVar28,auVar35,8,1);
      fVar17 = auVar28._0_4_ + fVar17;
      fVar4 = auVar28._4_4_ + fVar4;
      fVar16 = fVar17 + fVar4;
      fVar17 = fVar17 + fVar4;
      uVar18 = SUB41(fVar17,0);
      uVar19 = (undefined1)((uint)fVar17 >> 8);
      uVar20 = (undefined1)((uint)fVar17 >> 0x10);
      uVar21 = (undefined1)((uint)fVar17 >> 0x18);
      auVar2[4] = uVar18;
      auVar2._0_4_ = fVar16;
      auVar2[5] = uVar19;
      auVar2[6] = uVar20;
      auVar2[7] = uVar21;
      auVar2[8] = SUB41(fVar16,0);
      auVar2[9] = (char)((uint)fVar16 >> 8);
      auVar2[10] = (char)((uint)fVar16 >> 0x10);
      auVar2[0xb] = (char)((uint)fVar16 >> 0x18);
      auVar2[0xc] = uVar18;
      auVar2[0xd] = uVar19;
      auVar2[0xe] = uVar20;
      auVar2[0xf] = uVar21;
      auVar28 = NEON_frsqrte(auVar2,4);
      auVar34._0_4_ = auVar28._0_4_ * fVar16;
      auVar34._4_4_ = auVar28._4_4_ * fVar17;
      auVar34._8_4_ = auVar28._8_4_ * fVar16;
      uVar3 = (undefined2)(CONCAT15(uVar19,CONCAT14(uVar18,fVar16)) >> 0x20);
      auVar34._12_4_ = auVar28._12_4_ * (float)CONCAT13(uVar21,CONCAT12(uVar20,uVar3));
      auVar35 = NEON_frsqrts(auVar28,auVar34,4);
      auVar29._0_4_ = auVar28._0_4_ * auVar35._0_4_;
      auVar29._4_4_ = auVar28._4_4_ * auVar35._4_4_;
      auVar29._8_4_ = auVar28._8_4_ * auVar35._8_4_;
      auVar29._12_4_ = auVar28._12_4_ * auVar35._12_4_;
      auVar36._0_4_ = fVar16 * auVar29._0_4_;
      auVar36._4_4_ = fVar17 * auVar29._4_4_;
      auVar36._8_4_ = fVar16 * auVar29._8_4_;
      auVar36._12_4_ = (float)CONCAT13(uVar21,CONCAT12(uVar20,uVar3)) * auVar29._12_4_;
      iVar9 = -(uint)(fVar16 == 0.0);
      iVar14 = -(uint)(fVar17 == 0.0);
      iVar5 = -(uint)(fVar16 == 0.0);
      auVar28 = NEON_frsqrts(auVar29,auVar36,4);
      fVar30 = fVar30 * auVar29._0_4_ * auVar28._0_4_;
      fVar31 = fVar31 * auVar29._4_4_ * auVar28._4_4_;
      fVar32 = fVar32 * auVar29._8_4_ * auVar28._8_4_;
      *(ulong *)(puVar8 + -2) =
           CONCAT17((byte)((uint)fVar31 >> 0x18) & ~(byte)((uint)iVar14 >> 0x18),
                    CONCAT16((byte)((uint)fVar31 >> 0x10) & ~(byte)((uint)iVar14 >> 0x10),
                             CONCAT15((byte)((uint)fVar31 >> 8) & ~(byte)((uint)iVar14 >> 8),
                                      CONCAT14(SUB41(fVar31,0) & ~(byte)iVar14,
                                               CONCAT13((byte)((uint)fVar30 >> 0x18) &
                                                        ~(byte)((uint)iVar9 >> 0x18),
                                                        CONCAT12((byte)((uint)fVar30 >> 0x10) &
                                                                 ~(byte)((uint)iVar9 >> 0x10),
                                                                 CONCAT11((byte)((uint)fVar30 >> 8)
                                                                          & ~(byte)((uint)iVar9 >> 8
                                                                                   ),
                                                                          SUB41(fVar30,0) &
                                                                          ~(byte)iVar9)))))));
      *puVar8 = CONCAT13((byte)((uint)fVar32 >> 0x18) & ~(byte)((uint)iVar5 >> 0x18),
                         CONCAT12((byte)((uint)fVar32 >> 0x10) & ~(byte)((uint)iVar5 >> 0x10),
                                  CONCAT11((byte)((uint)fVar32 >> 8) & ~(byte)((uint)iVar5 >> 8),
                                           SUB41(fVar32,0) & ~(byte)iVar5)));
      puVar8 = puVar8 + 0xc;
    } while (uVar1 != uVar13);
    return;
  }
LAB_71005ea720:
  *(undefined4 *)(param_2 + 0x88) = 0;
  return;
}



void FUN_71005ea8d0(long *param_1)

{
  long lVar1;
  long lVar2;
  long lVar3;
  long lVar4;
  long lVar5;
  float fVar6;
  
  lVar3 = *param_1;
  if (((*(byte *)(lVar3 + 0x31) >> 6 & 1) != 0) && (lVar1 = *(long *)(lVar3 + 0x3a8), lVar1 != 0)) {
    lVar4 = *(long *)(lVar1 + 0x40);
    if (lVar4 != 0) {
      lVar5 = param_1[1];
      do {
        (**(code **)**(undefined8 **)(lVar5 + 8))();
        lVar2 = *(long *)(lVar4 + 0x60);
        if (lVar2 != 0) {
          fVar6 = *(float *)(*(long *)(*(long *)(lVar3 + 0x40) + 0x1f8) + 8);
          thunk_EXT_FUN_02e95df0(lVar3 + 0x6d0);
          *(long *)(lVar3 + 0x700) = *(long *)(lVar3 + 0x700) + -1;
          *(ulong *)(lVar3 + 0x6f8) = *(long *)(lVar3 + 0x6f8) + (ulong)(uint)(int)fVar6 * -0x40;
          (**(code **)(**(long **)(lVar3 + 0x6f0) + 0x18))(*(long **)(lVar3 + 0x6f0),lVar2);
          thunk_EXT_FUN_02e95df0(lVar3 + 0x6d0);
        }
        *(undefined8 *)(lVar4 + 0x60) = 0;
        *(undefined1 *)(lVar4 + 0x98) = 0;
        *(int *)(lVar5 + 0x50) = *(int *)(lVar5 + 0x50) + -1;
        (**(code **)(**(long **)(lVar5 + 8) + 8))();
        lVar4 = *(long *)(lVar4 + 0x78);
      } while (lVar4 != 0);
      *(undefined8 *)(lVar1 + 0x40) = 0;
      lVar3 = *param_1;
    }
    if (*(long *)(lVar1 + 0x20) != 0) {
      FUN_71005cefc0(*(long *)(lVar3 + 0x658),*(long *)(lVar1 + 0x20),0);
      *(undefined8 *)(lVar1 + 0x20) = 0;
      lVar3 = *param_1;
    }
    thunk_EXT_FUN_02e95df0(lVar3 + 0x6d0);
    *(long *)(lVar3 + 0x700) = *(long *)(lVar3 + 0x700) + -1;
    *(long *)(lVar3 + 0x6f8) = *(long *)(lVar3 + 0x6f8) + -0x80;
    (**(code **)(**(long **)(lVar3 + 0x6f0) + 0x18))(*(long **)(lVar3 + 0x6f0),lVar1);
    thunk_EXT_FUN_02e95df0(lVar3 + 0x6d0);
    *(undefined8 *)(*param_1 + 0x3a8) = 0;
  }
  return;
}



undefined8 FUN_71005eaa2c(long param_1)

{
  int iVar1;
  int iVar2;
  long lVar3;
  long lVar4;
  float fVar5;
  
  if (((*(byte *)(*(long *)(param_1 + 0x10) + 0x31) >> 6 & 1) != 0) &&
     (lVar3 = FUN_71005eaad0(*(long **)(param_1 + 0x18),*(long *)(param_1 + 0x10)), lVar3 != 0)) {
    fVar5 = *(float *)(*(long *)(param_1 + 0x10) + 0x28);
    *(float *)(lVar3 + 0x94) = fVar5 - (float)(int)fVar5;
    *(long *)(param_1 + 8) = lVar3;
    lVar4 = *(long *)(*(long *)(param_1 + 0x10) + 0x3a8);
    iVar1 = *(int *)(lVar4 + 0x68);
    iVar2 = 0;
    if (iVar1 != 0) {
      iVar2 = *(int *)(lVar4 + 0x6c) / iVar1;
    }
    *(int *)(lVar3 + 0x84) = *(int *)(lVar4 + 0x6c) - iVar2 * iVar1;
    iVar1 = 0;
    if (*(int *)(lVar4 + 0x6c) + 1 < *(int *)(lVar4 + 0x68)) {
      iVar1 = *(int *)(lVar4 + 0x6c) + 1;
    }
    *(int *)(lVar4 + 0x6c) = iVar1;
    FUN_71005e4220(param_1,(undefined8 *)(lVar3 + 0x20));
    return 1;
  }
  return 0;
}



long FUN_71005eaad0(long *param_1,long param_2)

{
  ulong uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  long lVar6;
  long lVar7;
  long *plVar8;
  ulong uVar9;
  int iVar10;
  long lVar11;
  ulong uVar12;
  long lVar13;
  long lVar14;
  char *pcVar15;
  uint uVar16;
  
  (*(code *)**(undefined8 **)param_1[1])();
  iVar3 = (int)param_1[9];
  if (0 < iVar3) {
    lVar14 = *param_1;
    iVar10 = *(int *)((long)param_1 + 0x4c);
    iVar4 = iVar3;
    do {
      pcVar15 = (char *)(lVar14 + (long)iVar10 * 0xa0 + 0x98);
      if (*pcVar15 == '\0') {
        lVar11 = param_2 + 0x6d0;
        uVar16 = (uint)*(float *)(*(long *)(*(long *)(param_2 + 0x40) + 0x1f8) + 8);
        lVar6 = (ulong)uVar16 * 0x40;
        thunk_EXT_FUN_02e95df0(lVar11);
        lVar7 = (**(code **)(**(long **)(param_2 + 0x6f0) + 0x10))
                          (*(long **)(param_2 + 0x6f0),lVar6,0x80);
        if (lVar7 == 0) {
          thunk_EXT_FUN_02e95df0(lVar11);
          lVar13 = 0;
          *(undefined8 *)(lVar14 + (long)iVar10 * 0xa0 + 0x60) = 0;
        }
        else {
          lVar13 = lVar14 + (long)iVar10 * 0xa0;
          *(long *)(param_2 + 0x6f8) = *(long *)(param_2 + 0x6f8) + lVar6;
          *(long *)(param_2 + 0x700) = *(long *)(param_2 + 0x700) + 1;
          thunk_EXT_FUN_02e95df0(lVar11);
          uVar5 = uVar16 - 1;
          plVar8 = (long *)(lVar14 + (long)iVar10 * 0xa0 + 0x60);
          *plVar8 = lVar7;
          if (uVar5 != 0) {
            if (uVar5 == 1) {
              uVar9 = 0;
            }
            else {
              lVar11 = 0;
              uVar9 = 0;
              do {
                uVar9 = uVar9 + 2;
                *(long *)(*plVar8 + lVar11 + 0x30) = *plVar8 + lVar11 + 0x40;
                lVar6 = *plVar8 + lVar11;
                lVar11 = lVar11 + 0x80;
                *(long *)(lVar6 + 0x70) = lVar6 + 0x80;
              } while (((ulong)uVar5 & 0xfffffffe) != uVar9);
            }
            if ((uVar5 & 1) != 0) {
              lVar11 = *plVar8 + uVar9 * 0x40;
              *(long *)(lVar11 + 0x30) = lVar11 + 0x40;
            }
            if (1 < uVar16) {
              uVar9 = (ulong)uVar16 - 1;
              if (uVar16 == 2) {
                lVar11 = 1;
              }
              else {
                lVar11 = 0;
                uVar1 = 0;
                do {
                  uVar12 = uVar1;
                  uVar1 = uVar12 + 2;
                  *(long *)(*plVar8 + lVar11 + 0x78) = *plVar8 + lVar11;
                  lVar6 = *plVar8 + lVar11;
                  lVar11 = lVar11 + 0x80;
                  *(long *)(lVar6 + 0xb8) = lVar6 + 0x40;
                } while ((uVar9 & 0xfffffffffffffffe) != uVar1);
                lVar11 = uVar12 + 3;
              }
              if ((uVar9 & 1) != 0) {
                lVar11 = *plVar8 + lVar11 * 0x40;
                *(long *)(lVar11 + 0x38) = lVar11 + -0x40;
              }
            }
          }
          lVar11 = (ulong)uVar5 * 0x40;
          *(long *)(*plVar8 + lVar11 + 0x30) = *plVar8;
          *(long *)(*plVar8 + 0x38) = *plVar8 + lVar11;
          lVar11 = *plVar8;
          lVar14 = lVar14 + (long)iVar10 * 0xa0;
          *(undefined4 *)(lVar14 + 0x80) = 0;
          *(undefined8 *)(lVar14 + 0x88) = 0;
          *(undefined8 *)(lVar14 + 0x78) = 0;
          *(long *)(lVar14 + 0x68) = lVar11;
          *(long *)(lVar14 + 0x70) = lVar11;
          *pcVar15 = '\x01';
          *(int *)(param_1 + 10) = (int)param_1[10] + 1;
        }
        goto LAB_71005ead00;
      }
      iVar2 = 0;
      if (iVar10 + 1 < iVar3) {
        iVar2 = iVar10 + 1;
      }
      iVar4 = iVar4 + -1;
      *(int *)((long)param_1 + 0x4c) = iVar2;
      iVar10 = iVar2;
    } while (iVar4 != 0);
  }
  lVar13 = 0;
LAB_71005ead00:
  (**(code **)(*(long *)param_1[1] + 8))();
  return lVar13;
}



uint FUN_71005ead30(long param_1)

{
  uint uVar1;
  long lVar2;
  long lVar3;
  float *pfVar4;
  long *plVar5;
  float fVar6;
  float fVar7;
  undefined8 uVar8;
  undefined8 uVar9;
  float afStack_50 [4];
  
  uVar1 = *(uint *)(*(long *)(param_1 + 0x10) + 0x30);
  if (((uVar1 >> 0xe & 1) != 0) && (pfVar4 = *(float **)(param_1 + 8), pfVar4 != (float *)0x0)) {
    FUN_71005e4220(param_1,(undefined8 *)afStack_50);
    plVar5 = *(long **)(*(long *)(param_1 + 0x10) + 0x40);
    fVar6 = (float)FUN_71005e3d44(param_1);
    fVar7 = (float)FUN_71005e3d3c(param_1);
    FUN_71005e1b1c(fVar6,fVar7,(undefined8 *)pfVar4,plVar5,afStack_50);
    plVar5 = *(long **)(*(long *)(param_1 + 0x10) + 0x40);
    fVar6 = (float)FUN_71005e3d44(param_1);
    fVar7 = (float)FUN_71005e3d3c(param_1);
    FUN_71005e2368(fVar6,fVar7,(undefined8 *)(pfVar4 + 4),plVar5,afStack_50);
    uVar8 = *(undefined8 *)pfVar4;
    uVar9 = *(undefined8 *)(pfVar4 + 4);
    fVar6 = *(float *)(*(long *)(*(long *)(*(long *)(param_1 + 0x10) + 0x40) + 0x340) + 0x630);
    *pfVar4 = fVar6 * (float)uVar8;
    pfVar4[1] = fVar6 * (float)((ulong)uVar8 >> 0x20);
    pfVar4[2] = fVar6 * (float)*(undefined8 *)(pfVar4 + 2);
    pfVar4[4] = fVar6 * (float)uVar9;
    pfVar4[5] = fVar6 * (float)((ulong)uVar9 >> 0x20);
    pfVar4[6] = fVar6 * (float)*(undefined8 *)(pfVar4 + 6);
    lVar3 = *(long *)(*(long *)(param_1 + 0x10) + 0x3a8);
    lVar2 = *(long *)(lVar3 + 0x40);
    if (lVar2 == 0) {
      *(float **)(lVar3 + 0x40) = pfVar4;
    }
    else {
      do {
        lVar3 = lVar2;
        lVar2 = *(long *)(lVar3 + 0x78);
      } while (lVar2 != 0);
      *(float **)(lVar3 + 0x78) = pfVar4;
    }
  }
  return uVar1 >> 0xe & 1;
}



void FUN_71005eae68(undefined8 *param_1,int param_2,long param_3)

{
  undefined8 *puVar1;
  undefined2 uVar2;
  undefined1 auVar3 [16];
  undefined1 auVar4 [16];
  undefined1 auVar5 [16];
  undefined1 auVar6 [16];
  undefined1 auVar7 [16];
  undefined1 auVar8 [16];
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  undefined2 uVar13;
  long lVar14;
  float fVar15;
  float fVar16;
  float fVar17;
  undefined8 uVar18;
  float fVar19;
  float fVar20;
  float fVar21;
  undefined8 uVar22;
  float fVar23;
  float fVar24;
  undefined1 uVar25;
  undefined1 uVar26;
  undefined1 uVar27;
  undefined1 uVar28;
  undefined1 uVar29;
  undefined1 uVar30;
  undefined1 uVar31;
  undefined1 uVar32;
  undefined1 uVar33;
  undefined1 auVar34 [16];
  undefined1 auVar35 [16];
  undefined1 auVar36 [16];
  undefined1 auVar37 [16];
  undefined1 auVar38 [16];
  undefined1 auVar39 [16];
  undefined1 auVar40 [16];
  undefined1 auVar41 [16];
  float afStack_50 [2];
  float local_48;
  undefined8 local_40;
  undefined8 uStack_38;
  
  if (param_2 < 1) {
    uVar18 = param_1[2];
    uVar22 = param_1[3];
  }
  else {
    uVar18 = *(undefined8 *)param_1[6];
    fVar16 = 1.0 / *(float *)(*(long *)(param_3 + 0x10) + 0x2c);
    uVar18 = CONCAT44(((float)((ulong)*param_1 >> 0x20) - (float)((ulong)uVar18 >> 0x20)) * fVar16 +
                      0.0,((float)*param_1 - (float)uVar18) * fVar16 + 0.0);
    uVar22 = CONCAT44(fVar16 * 0.0 + 0.0,
                      ((float)param_1[1] - (float)((undefined8 *)param_1[6])[1]) * fVar16 + 0.0);
  }
  fVar16 = (float)uVar18 * (float)uVar18;
  fVar19 = (float)((ulong)uVar18 >> 0x20);
  fVar19 = fVar19 * fVar19;
  uVar25 = (undefined1)((uint)fVar19 >> 8);
  uVar26 = (undefined1)((uint)fVar19 >> 0x10);
  uVar27 = (undefined1)((uint)fVar19 >> 0x18);
  fVar15 = (float)uVar22 * (float)uVar22;
  uVar28 = (undefined1)((uint)fVar15 >> 8);
  uVar29 = (undefined1)((uint)fVar15 >> 0x10);
  uVar30 = (undefined1)((uint)fVar15 >> 0x18);
  fVar23 = (float)((ulong)uVar22 >> 0x20);
  fVar23 = fVar23 * fVar23;
  uVar31 = (undefined1)((uint)fVar23 >> 8);
  uVar32 = (undefined1)((uint)fVar23 >> 0x10);
  uVar33 = (undefined1)((uint)fVar23 >> 0x18);
  auVar34[4] = SUB41(fVar19,0);
  auVar34._0_4_ = fVar16;
  auVar34[5] = uVar25;
  auVar34[6] = uVar26;
  auVar34[7] = uVar27;
  auVar34[8] = SUB41(fVar15,0);
  auVar34[9] = uVar28;
  auVar34[10] = uVar29;
  auVar34[0xb] = uVar30;
  auVar34[0xc] = SUB41(fVar23,0);
  auVar34[0xd] = uVar31;
  auVar34[0xe] = uVar32;
  auVar34[0xf] = uVar33;
  auVar38[4] = SUB41(fVar19,0);
  auVar38._0_4_ = fVar16;
  auVar38[5] = uVar25;
  auVar38[6] = uVar26;
  auVar38[7] = uVar27;
  auVar38[8] = SUB41(fVar15,0);
  auVar38[9] = uVar28;
  auVar38[10] = uVar29;
  auVar38[0xb] = uVar30;
  auVar38[0xc] = SUB41(fVar23,0);
  auVar38[0xd] = uVar31;
  auVar38[0xe] = uVar32;
  auVar38[0xf] = uVar33;
  auVar34 = NEON_ext(auVar34,auVar38,8,1);
  fVar16 = auVar34._0_4_ + fVar16;
  fVar19 = auVar34._4_4_ + fVar19;
  fVar15 = fVar16 + fVar19;
  fVar16 = fVar16 + fVar19;
  uVar25 = SUB41(fVar15,0);
  uVar26 = (undefined1)((uint)fVar15 >> 8);
  uVar27 = (undefined1)((uint)fVar15 >> 0x10);
  uVar28 = (undefined1)((uint)fVar15 >> 0x18);
  uVar29 = SUB41(fVar16,0);
  uVar30 = (undefined1)((uint)fVar16 >> 8);
  uVar31 = (undefined1)((uint)fVar16 >> 0x10);
  uVar32 = (undefined1)((uint)fVar16 >> 0x18);
  if (fVar15 < 1e-05) {
    uVar22 = *(undefined8 *)(*(long *)(param_3 + 0x10) + 0x128);
    uVar18 = *(undefined8 *)(*(long *)(param_3 + 0x10) + 0x120);
    fVar16 = (float)uVar18 * (float)uVar18;
    fVar19 = (float)((ulong)uVar18 >> 0x20);
    fVar19 = fVar19 * fVar19;
    uVar25 = (undefined1)((uint)fVar19 >> 8);
    uVar26 = (undefined1)((uint)fVar19 >> 0x10);
    uVar27 = (undefined1)((uint)fVar19 >> 0x18);
    fVar15 = (float)uVar22 * (float)uVar22;
    uVar28 = (undefined1)((uint)fVar15 >> 8);
    uVar29 = (undefined1)((uint)fVar15 >> 0x10);
    uVar30 = (undefined1)((uint)fVar15 >> 0x18);
    fVar23 = (float)((ulong)uVar22 >> 0x20);
    fVar23 = fVar23 * fVar23;
    uVar31 = (undefined1)((uint)fVar23 >> 8);
    uVar32 = (undefined1)((uint)fVar23 >> 0x10);
    uVar33 = (undefined1)((uint)fVar23 >> 0x18);
    auVar3[4] = SUB41(fVar19,0);
    auVar3._0_4_ = fVar16;
    auVar3[5] = uVar25;
    auVar3[6] = uVar26;
    auVar3[7] = uVar27;
    auVar3[8] = SUB41(fVar15,0);
    auVar3[9] = uVar28;
    auVar3[10] = uVar29;
    auVar3[0xb] = uVar30;
    auVar3[0xc] = SUB41(fVar23,0);
    auVar3[0xd] = uVar31;
    auVar3[0xe] = uVar32;
    auVar3[0xf] = uVar33;
    auVar4[4] = SUB41(fVar19,0);
    auVar4._0_4_ = fVar16;
    auVar4[5] = uVar25;
    auVar4[6] = uVar26;
    auVar4[7] = uVar27;
    auVar4[8] = SUB41(fVar15,0);
    auVar4[9] = uVar28;
    auVar4[10] = uVar29;
    auVar4[0xb] = uVar30;
    auVar4[0xc] = SUB41(fVar23,0);
    auVar4[0xd] = uVar31;
    auVar4[0xe] = uVar32;
    auVar4[0xf] = uVar33;
    auVar34 = NEON_ext(auVar3,auVar4,8,1);
    fVar16 = auVar34._0_4_ + fVar16;
    fVar19 = auVar34._4_4_ + fVar19;
    fVar15 = fVar16 + fVar19;
    fVar16 = fVar16 + fVar19;
    uVar25 = SUB41(fVar15,0);
    uVar26 = (undefined1)((uint)fVar15 >> 8);
    uVar27 = (undefined1)((uint)fVar15 >> 0x10);
    uVar28 = (undefined1)((uint)fVar15 >> 0x18);
    uVar29 = SUB41(fVar16,0);
    uVar30 = (undefined1)((uint)fVar16 >> 8);
    uVar31 = (undefined1)((uint)fVar16 >> 0x10);
    uVar32 = (undefined1)((uint)fVar16 >> 0x18);
  }
  uVar2 = CONCAT11(uVar26,uVar25);
  uVar13 = CONCAT11(uVar30,uVar29);
  auVar5[1] = uVar26;
  auVar5[0] = uVar25;
  auVar5[2] = uVar27;
  auVar5[3] = uVar28;
  auVar5[4] = uVar29;
  auVar5[5] = uVar30;
  auVar5[6] = uVar31;
  auVar5[7] = uVar32;
  auVar5[8] = uVar25;
  auVar5[9] = uVar26;
  auVar5[10] = uVar27;
  auVar5[0xb] = uVar28;
  auVar5[0xc] = uVar29;
  auVar5[0xd] = uVar30;
  auVar5[0xe] = uVar31;
  auVar5[0xf] = uVar32;
  auVar34 = NEON_frsqrte(auVar5,4);
  auVar37._0_4_ = auVar34._0_4_ * (float)CONCAT13(uVar28,CONCAT12(uVar27,CONCAT11(uVar26,uVar25)));
  auVar37._4_4_ = auVar34._4_4_ * (float)CONCAT13(uVar32,CONCAT12(uVar31,CONCAT11(uVar30,uVar29)));
  auVar37._8_4_ = auVar34._8_4_ * (float)CONCAT13(uVar28,CONCAT12(uVar27,uVar2));
  auVar37._12_4_ = auVar34._12_4_ * (float)CONCAT13(uVar32,CONCAT12(uVar31,uVar13));
  auVar38 = NEON_frsqrts(auVar34,auVar37,4);
  auVar35._0_4_ = auVar34._0_4_ * auVar38._0_4_;
  auVar35._4_4_ = auVar34._4_4_ * auVar38._4_4_;
  auVar35._8_4_ = auVar34._8_4_ * auVar38._8_4_;
  auVar35._12_4_ = auVar34._12_4_ * auVar38._12_4_;
  auVar39._0_4_ = (float)CONCAT13(uVar28,CONCAT12(uVar27,CONCAT11(uVar26,uVar25))) * auVar35._0_4_;
  auVar39._4_4_ = (float)CONCAT13(uVar32,CONCAT12(uVar31,CONCAT11(uVar30,uVar29))) * auVar35._4_4_;
  auVar39._8_4_ = (float)CONCAT13(uVar28,CONCAT12(uVar27,uVar2)) * auVar35._8_4_;
  auVar39._12_4_ = (float)CONCAT13(uVar32,CONCAT12(uVar31,uVar13)) * auVar35._12_4_;
  iVar9 = -(uint)((float)CONCAT13(uVar28,CONCAT12(uVar27,CONCAT11(uVar26,uVar25))) == 0.0);
  iVar10 = -(uint)((float)CONCAT13(uVar32,CONCAT12(uVar31,CONCAT11(uVar30,uVar29))) == 0.0);
  iVar11 = -(uint)((float)CONCAT13(uVar28,CONCAT12(uVar27,uVar2)) == 0.0);
  iVar12 = -(uint)((float)CONCAT13(uVar32,CONCAT12(uVar31,uVar13)) == 0.0);
  auVar34 = NEON_frsqrts(auVar35,auVar39,4);
  fVar16 = (float)uVar18 * auVar35._0_4_ * auVar34._0_4_;
  fVar19 = (float)((ulong)uVar18 >> 0x20) * auVar35._4_4_ * auVar34._4_4_;
  fVar15 = (float)uVar22 * auVar35._8_4_ * auVar34._8_4_;
  fVar23 = (float)((ulong)uVar22 >> 0x20) * auVar35._12_4_ * auVar34._12_4_;
  local_40 = CONCAT17((byte)((uint)fVar19 >> 0x18) & ~(byte)((uint)iVar10 >> 0x18),
                      CONCAT16((byte)((uint)fVar19 >> 0x10) & ~(byte)((uint)iVar10 >> 0x10),
                               CONCAT15((byte)((uint)fVar19 >> 8) & ~(byte)((uint)iVar10 >> 8),
                                        CONCAT14(SUB41(fVar19,0) & ~(byte)iVar10,
                                                 CONCAT13((byte)((uint)fVar16 >> 0x18) &
                                                          ~(byte)((uint)iVar9 >> 0x18),
                                                          CONCAT12((byte)((uint)fVar16 >> 0x10) &
                                                                   ~(byte)((uint)iVar9 >> 0x10),
                                                                   CONCAT11((byte)((uint)fVar16 >> 8
                                                                                  ) & ~(byte)((uint)
                                                  iVar9 >> 8),SUB41(fVar16,0) & ~(byte)iVar9)))))));
  uStack_38 = CONCAT17((byte)((uint)fVar23 >> 0x18) & ~(byte)((uint)iVar12 >> 0x18),
                       CONCAT16((byte)((uint)fVar23 >> 0x10) & ~(byte)((uint)iVar12 >> 0x10),
                                CONCAT15((byte)((uint)fVar23 >> 8) & ~(byte)((uint)iVar12 >> 8),
                                         CONCAT14(SUB41(fVar23,0) & ~(byte)iVar12,
                                                  CONCAT13((byte)((uint)fVar15 >> 0x18) &
                                                           ~(byte)((uint)iVar11 >> 0x18),
                                                           CONCAT12((byte)((uint)fVar15 >> 0x10) &
                                                                    ~(byte)((uint)iVar11 >> 0x10),
                                                                    CONCAT11((byte)((uint)fVar15 >>
                                                                                   8) &
                                                                             ~(byte)((uint)iVar11 >>
                                                                                    8),
                                                                             SUB41(fVar15,0) &
                                                                             ~(byte)iVar11)))))));
  FUN_71005e3ff8(param_3,afStack_50);
  puVar1 = param_1 + 4;
  FUN_71005def50(local_48,puVar1,puVar1,&local_40);
  fVar17 = (float)param_1[4];
  fVar16 = fVar17 * fVar17;
  fVar20 = (float)((ulong)param_1[4] >> 0x20);
  fVar19 = fVar20 * fVar20;
  uVar25 = (undefined1)((uint)fVar19 >> 8);
  uVar26 = (undefined1)((uint)fVar19 >> 0x10);
  uVar27 = (undefined1)((uint)fVar19 >> 0x18);
  fVar21 = (float)param_1[5];
  fVar15 = fVar21 * fVar21;
  uVar28 = (undefined1)((uint)fVar15 >> 8);
  uVar29 = (undefined1)((uint)fVar15 >> 0x10);
  uVar30 = (undefined1)((uint)fVar15 >> 0x18);
  fVar24 = (float)((ulong)param_1[5] >> 0x20);
  fVar23 = fVar24 * fVar24;
  uVar31 = (undefined1)((uint)fVar23 >> 8);
  uVar32 = (undefined1)((uint)fVar23 >> 0x10);
  uVar33 = (undefined1)((uint)fVar23 >> 0x18);
  auVar6[4] = SUB41(fVar19,0);
  auVar6._0_4_ = fVar16;
  auVar6[5] = uVar25;
  auVar6[6] = uVar26;
  auVar6[7] = uVar27;
  auVar6[8] = SUB41(fVar15,0);
  auVar6[9] = uVar28;
  auVar6[10] = uVar29;
  auVar6[0xb] = uVar30;
  auVar6[0xc] = SUB41(fVar23,0);
  auVar6[0xd] = uVar31;
  auVar6[0xe] = uVar32;
  auVar6[0xf] = uVar33;
  auVar7[4] = SUB41(fVar19,0);
  auVar7._0_4_ = fVar16;
  auVar7[5] = uVar25;
  auVar7[6] = uVar26;
  auVar7[7] = uVar27;
  auVar7[8] = SUB41(fVar15,0);
  auVar7[9] = uVar28;
  auVar7[10] = uVar29;
  auVar7[0xb] = uVar30;
  auVar7[0xc] = SUB41(fVar23,0);
  auVar7[0xd] = uVar31;
  auVar7[0xe] = uVar32;
  auVar7[0xf] = uVar33;
  auVar34 = NEON_ext(auVar6,auVar7,8,1);
  fVar16 = auVar34._0_4_ + fVar16;
  fVar19 = auVar34._4_4_ + fVar19;
  fVar15 = fVar16 + fVar19;
  fVar16 = fVar16 + fVar19;
  uVar25 = SUB41(fVar16,0);
  uVar26 = (undefined1)((uint)fVar16 >> 8);
  uVar27 = (undefined1)((uint)fVar16 >> 0x10);
  uVar28 = (undefined1)((uint)fVar16 >> 0x18);
  auVar8[4] = uVar25;
  auVar8._0_4_ = fVar15;
  auVar8[5] = uVar26;
  auVar8[6] = uVar27;
  auVar8[7] = uVar28;
  auVar8[8] = SUB41(fVar15,0);
  auVar8[9] = (char)((uint)fVar15 >> 8);
  auVar8[10] = (char)((uint)fVar15 >> 0x10);
  auVar8[0xb] = (char)((uint)fVar15 >> 0x18);
  auVar8[0xc] = uVar25;
  auVar8[0xd] = uVar26;
  auVar8[0xe] = uVar27;
  auVar8[0xf] = uVar28;
  auVar34 = NEON_frsqrte(auVar8,4);
  auVar40._0_4_ = auVar34._0_4_ * fVar15;
  auVar40._4_4_ = auVar34._4_4_ * fVar16;
  auVar40._8_4_ = auVar34._8_4_ * fVar15;
  uVar2 = (undefined2)(CONCAT15(uVar26,CONCAT14(uVar25,fVar15)) >> 0x20);
  auVar40._12_4_ = auVar34._12_4_ * (float)CONCAT13(uVar28,CONCAT12(uVar27,uVar2));
  auVar38 = NEON_frsqrts(auVar34,auVar40,4);
  auVar36._0_4_ = auVar34._0_4_ * auVar38._0_4_;
  auVar36._4_4_ = auVar34._4_4_ * auVar38._4_4_;
  auVar36._8_4_ = auVar34._8_4_ * auVar38._8_4_;
  auVar36._12_4_ = auVar34._12_4_ * auVar38._12_4_;
  auVar41._0_4_ = fVar15 * auVar36._0_4_;
  auVar41._4_4_ = fVar16 * auVar36._4_4_;
  auVar41._8_4_ = fVar15 * auVar36._8_4_;
  auVar41._12_4_ = (float)CONCAT13(uVar28,CONCAT12(uVar27,uVar2)) * auVar36._12_4_;
  iVar9 = -(uint)(fVar15 == 0.0);
  iVar10 = -(uint)(fVar16 == 0.0);
  iVar11 = -(uint)(fVar15 == 0.0);
  iVar12 = -(uint)((float)CONCAT13(uVar28,CONCAT12(uVar27,uVar2)) == 0.0);
  auVar34 = NEON_frsqrts(auVar36,auVar41,4);
  fVar17 = fVar17 * auVar36._0_4_ * auVar34._0_4_;
  fVar20 = fVar20 * auVar36._4_4_ * auVar34._4_4_;
  fVar21 = fVar21 * auVar36._8_4_ * auVar34._8_4_;
  fVar24 = fVar24 * auVar36._12_4_ * auVar34._12_4_;
  param_1[5] = CONCAT17((byte)((uint)fVar24 >> 0x18) & ~(byte)((uint)iVar12 >> 0x18),
                        CONCAT16((byte)((uint)fVar24 >> 0x10) & ~(byte)((uint)iVar12 >> 0x10),
                                 CONCAT15((byte)((uint)fVar24 >> 8) & ~(byte)((uint)iVar12 >> 8),
                                          CONCAT14(SUB41(fVar24,0) & ~(byte)iVar12,
                                                   CONCAT13((byte)((uint)fVar21 >> 0x18) &
                                                            ~(byte)((uint)iVar11 >> 0x18),
                                                            CONCAT12((byte)((uint)fVar21 >> 0x10) &
                                                                     ~(byte)((uint)iVar11 >> 0x10),
                                                                     CONCAT11((byte)((uint)fVar21 >>
                                                                                    8) &
                                                                              ~(byte)((uint)iVar11
                                                                                     >> 8),
                                                                              SUB41(fVar21,0) &
                                                                              ~(byte)iVar11)))))));
  param_1[4] = CONCAT17((byte)((uint)fVar20 >> 0x18) & ~(byte)((uint)iVar10 >> 0x18),
                        CONCAT16((byte)((uint)fVar20 >> 0x10) & ~(byte)((uint)iVar10 >> 0x10),
                                 CONCAT15((byte)((uint)fVar20 >> 8) & ~(byte)((uint)iVar10 >> 8),
                                          CONCAT14(SUB41(fVar20,0) & ~(byte)iVar10,
                                                   CONCAT13((byte)((uint)fVar17 >> 0x18) &
                                                            ~(byte)((uint)iVar9 >> 0x18),
                                                            CONCAT12((byte)((uint)fVar17 >> 0x10) &
                                                                     ~(byte)((uint)iVar9 >> 0x10),
                                                                     CONCAT11((byte)((uint)fVar17 >>
                                                                                    8) &
                                                                              ~(byte)((uint)iVar9 >>
                                                                                     8),
                                                                              SUB41(fVar17,0) &
                                                                              ~(byte)iVar9)))))));
  if (param_2 == 1) {
    lVar14 = param_1[6];
    *(undefined8 *)(lVar14 + 0x28) = param_1[5];
    *(undefined8 *)(lVar14 + 0x20) = *puVar1;
  }
  return;
}



void FUN_71005eafd0(long param_1,float *param_2)

{
  byte bVar1;
  undefined2 uVar2;
  undefined1 auVar3 [16];
  undefined1 auVar4 [16];
  undefined1 auVar5 [16];
  undefined1 auVar6 [16];
  undefined1 auVar7 [16];
  undefined1 auVar8 [16];
  undefined1 auVar9 [16];
  undefined1 auVar10 [16];
  undefined1 auVar11 [16];
  undefined1 auVar12 [16];
  undefined1 auVar13 [16];
  undefined2 uVar14;
  bool bVar15;
  bool bVar16;
  undefined8 *puVar17;
  undefined8 *puVar18;
  byte *pbVar19;
  long *plVar20;
  float *pfVar21;
  undefined8 *puVar22;
  long lVar23;
  float fVar24;
  float fVar25;
  float fVar26;
  undefined8 uVar27;
  float fVar28;
  float fVar29;
  ulong uVar30;
  undefined8 uVar31;
  float fVar32;
  undefined1 uVar33;
  undefined1 uVar34;
  undefined1 uVar35;
  undefined1 uVar36;
  undefined1 uVar37;
  undefined1 uVar38;
  undefined1 uVar39;
  undefined1 uVar40;
  undefined1 uVar41;
  float fVar42;
  int iVar43;
  float fVar50;
  int iVar52;
  undefined1 auVar44 [16];
  undefined1 auVar45 [16];
  undefined1 auVar46 [16];
  undefined1 auVar47 [16];
  undefined1 auVar48 [16];
  int iVar51;
  int iVar53;
  undefined1 auVar49 [16];
  undefined1 auVar54 [16];
  undefined1 auVar55 [16];
  undefined1 auVar56 [16];
  undefined1 auVar57 [16];
  undefined1 auVar58 [16];
  undefined1 auVar59 [16];
  undefined1 auVar60 [16];
  undefined1 auVar61 [16];
  float fVar62;
  undefined1 auVar63 [16];
  undefined1 auVar64 [16];
  undefined8 local_a0;
  undefined8 local_98;
  undefined4 local_90;
  undefined4 uStack_8c;
  undefined4 local_88;
  undefined4 uStack_84;
  float local_80 [4];
  float local_70 [2];
  float local_68;
  undefined8 local_60;
  undefined8 uStack_58;
  
  lVar23 = *(long *)(param_1 + 0x10);
  puVar22 = *(undefined8 **)(lVar23 + 0x3a8);
  pbVar19 = *(byte **)(*(long *)(lVar23 + 0x40) + 0x1f8);
  fVar25 = (float)FUN_71005e3d3c(param_1);
  param_2[0x23] = fVar25;
  fVar25 = (float)FUN_71005e3d44(param_1);
  param_2[0x24] = fVar25;
  param_2[0x22] = 0.0;
  FUN_71005e437c(param_1,(undefined8 *)(param_2 + 0xc));
  FUN_71005e4220(param_1,&local_60);
  plVar20 = *(long **)(*(long *)(param_1 + 0x10) + 0x40);
  fVar25 = (float)FUN_71005e3d44(param_1);
  fVar26 = (float)FUN_71005e3d3c(param_1);
  FUN_71005e1b1c(fVar25,fVar26,(undefined8 *)param_2,plVar20,(float *)&local_60);
  plVar20 = *(long **)(*(long *)(param_1 + 0x10) + 0x40);
  fVar25 = (float)FUN_71005e3d44(param_1);
  fVar26 = (float)FUN_71005e3d3c(param_1);
  FUN_71005e2368(fVar25,fVar26,(undefined8 *)(param_2 + 4),plVar20,(float *)&local_60);
  uVar27 = *(undefined8 *)param_2;
  fVar25 = *(float *)(*(long *)(*(long *)(*(long *)(param_1 + 0x10) + 0x40) + 0x340) + 0x630);
  *param_2 = fVar25 * (float)uVar27;
  param_2[1] = fVar25 * (float)((ulong)uVar27 >> 0x20);
  param_2[2] = fVar25 * (float)*(undefined8 *)(param_2 + 2);
  param_2[4] = fVar25 * param_2[4];
  param_2[5] = fVar25 * param_2[5];
  param_2[6] = fVar25 * param_2[6];
  fVar25 = param_2[0x23] + 0.0005 + param_2[0x25];
  fVar26 = fVar25 + *(float *)(lVar23 + 0x2c);
  if (fVar26 - fVar25 < 0.9995) {
    fVar62 = fVar26 - (float)(int)fVar26;
    bVar15 = true;
    bVar16 = false;
    if (0.0 < (float)(int)fVar26 - (float)(int)fVar25) {
      bVar15 = false;
      bVar16 = true;
      if (!NAN(fVar62)) {
        bVar15 = fVar62 < 0.001;
        bVar16 = false;
      }
    }
    if (bVar15 != bVar16) {
      if ((param_2[0x23] != 0.0) &&
         (fVar26 - fVar25 < 0.0005 || 0.001 < fVar25 - (float)(int)fVar25)) {
        pfVar21 = *(float **)(*(long *)(param_2 + 0x1a) + 0x30);
        if (pbVar19[1] == 0) {
          FUN_71005e4078(param_1,local_70);
          FUN_71005e3d7c(param_1,&local_60);
        }
        else {
          FUN_71005e4104(param_1,local_70);
          FUN_71005e3d54(param_1,&local_60);
        }
        *(undefined8 *)(param_2 + 0x14) = local_60;
        *(undefined8 *)(param_2 + 0x16) = uStack_58;
        *pfVar21 = (float)local_60;
        pfVar21[1] = local_60._4_4_;
        pfVar21[2] = (float)uStack_58;
        pfVar21[3] = local_70[0];
        if (pbVar19[1] == 0) {
          uVar30 = *(ulong *)(lVar23 + 0x118);
          *(undefined8 *)(pfVar21 + 8) = *(undefined8 *)(lVar23 + 0x110);
          *(ulong *)(pfVar21 + 10) = uVar30 & 0xffffffff;
          *(undefined8 *)(pfVar21 + 8) = *(undefined8 *)(pfVar21 + 8);
          bVar1 = *pbVar19;
        }
        else {
          *(undefined8 *)(pfVar21 + 10) = puVar22[1];
          *(undefined8 *)(pfVar21 + 8) = *puVar22;
          bVar1 = *pbVar19;
        }
        if ((bVar1 - 1 < 2) &&
           (*(char *)(*(long *)(*(long *)(param_1 + 0x10) + 0x48) + 0xe22) != '\0')) {
          FUN_71005eae68((undefined8 *)pfVar21,(int)param_2[0x20],param_1);
        }
        fVar25 = param_2[0x20];
        goto joined_r0x0071005eb3f0;
      }
    }
  }
  puVar17 = *(undefined8 **)(param_2 + 0x1a);
  *(undefined8 *)(param_2 + 0x1a) = puVar17[7];
  if (pbVar19[1] == 0) {
    FUN_71005e4078(param_1,local_80);
    FUN_71005e3d7c(param_1,(undefined8 *)&local_90);
    FUN_71005e3efc(param_1,&local_a0);
  }
  else {
    FUN_71005e4104(param_1,local_80);
    FUN_71005e3d54(param_1,(undefined8 *)&local_90);
    FUN_71005e3ed4(param_1,&local_a0);
  }
  *(ulong *)(param_2 + 0x14) = CONCAT44(uStack_8c,local_90);
  *(ulong *)(param_2 + 0x16) = CONCAT44(uStack_84,local_88);
  *(undefined4 *)puVar17 = local_90;
  *(undefined4 *)((long)puVar17 + 4) = uStack_8c;
  puVar17[2] = local_a0;
  *(undefined4 *)(puVar17 + 1) = local_88;
  *(float *)((long)puVar17 + 0xc) = local_80[0];
  puVar17[3] = local_98;
  if (pbVar19[1] == 0) {
    uVar30 = *(ulong *)(lVar23 + 0x118);
    puVar17[4] = *(undefined8 *)(lVar23 + 0x110);
    puVar17[5] = uVar30 & 0xffffffff;
    puVar17[4] = puVar17[4];
    bVar1 = *pbVar19;
  }
  else {
    puVar17[5] = puVar22[1];
    puVar17[4] = *puVar22;
    bVar1 = *pbVar19;
  }
  if ((bVar1 - 1 < 2) &&
     (lVar23 = *(long *)(param_1 + 0x10), *(char *)(*(long *)(lVar23 + 0x48) + 0xe22) != '\0')) {
    fVar25 = param_2[0x20];
    if ((int)fVar25 < 1) {
      uVar27 = puVar17[2];
      uVar31 = puVar17[3];
    }
    else {
      uVar27 = *(undefined8 *)puVar17[6];
      fVar26 = 1.0 / *(float *)(lVar23 + 0x2c);
      uVar27 = CONCAT44(((float)((ulong)*puVar17 >> 0x20) - (float)((ulong)uVar27 >> 0x20)) * fVar26
                        + 0.0,((float)*puVar17 - (float)uVar27) * fVar26 + 0.0);
      uVar31 = CONCAT44(fVar26 * 0.0 + 0.0,
                        ((float)puVar17[1] - (float)((undefined8 *)puVar17[6])[1]) * fVar26 + 0.0);
    }
    fVar26 = (float)uVar27 * (float)uVar27;
    fVar62 = (float)((ulong)uVar27 >> 0x20);
    fVar62 = fVar62 * fVar62;
    uVar33 = (undefined1)((uint)fVar62 >> 8);
    uVar34 = (undefined1)((uint)fVar62 >> 0x10);
    uVar35 = (undefined1)((uint)fVar62 >> 0x18);
    fVar29 = (float)uVar31 * (float)uVar31;
    uVar36 = (undefined1)((uint)fVar29 >> 8);
    uVar37 = (undefined1)((uint)fVar29 >> 0x10);
    uVar38 = (undefined1)((uint)fVar29 >> 0x18);
    fVar24 = (float)((ulong)uVar31 >> 0x20);
    fVar24 = fVar24 * fVar24;
    uVar39 = (undefined1)((uint)fVar24 >> 8);
    uVar40 = (undefined1)((uint)fVar24 >> 0x10);
    uVar41 = (undefined1)((uint)fVar24 >> 0x18);
    auVar46[4] = SUB41(fVar62,0);
    auVar46._0_4_ = fVar26;
    auVar46[5] = uVar33;
    auVar46[6] = uVar34;
    auVar46[7] = uVar35;
    auVar46[8] = SUB41(fVar29,0);
    auVar46[9] = uVar36;
    auVar46[10] = uVar37;
    auVar46[0xb] = uVar38;
    auVar46[0xc] = SUB41(fVar24,0);
    auVar46[0xd] = uVar39;
    auVar46[0xe] = uVar40;
    auVar46[0xf] = uVar41;
    auVar60[4] = SUB41(fVar62,0);
    auVar60._0_4_ = fVar26;
    auVar60[5] = uVar33;
    auVar60[6] = uVar34;
    auVar60[7] = uVar35;
    auVar60[8] = SUB41(fVar29,0);
    auVar60[9] = uVar36;
    auVar60[10] = uVar37;
    auVar60[0xb] = uVar38;
    auVar60[0xc] = SUB41(fVar24,0);
    auVar60[0xd] = uVar39;
    auVar60[0xe] = uVar40;
    auVar60[0xf] = uVar41;
    auVar46 = NEON_ext(auVar46,auVar60,8,1);
    fVar26 = auVar46._0_4_ + fVar26;
    fVar62 = auVar46._4_4_ + fVar62;
    fVar29 = fVar26 + fVar62;
    fVar26 = fVar26 + fVar62;
    uVar33 = SUB41(fVar29,0);
    uVar34 = (undefined1)((uint)fVar29 >> 8);
    uVar35 = (undefined1)((uint)fVar29 >> 0x10);
    uVar36 = (undefined1)((uint)fVar29 >> 0x18);
    uVar37 = SUB41(fVar26,0);
    uVar38 = (undefined1)((uint)fVar26 >> 8);
    uVar39 = (undefined1)((uint)fVar26 >> 0x10);
    uVar40 = (undefined1)((uint)fVar26 >> 0x18);
    if (fVar29 < 1e-05) {
      uVar31 = *(undefined8 *)(lVar23 + 0x128);
      uVar27 = *(undefined8 *)(lVar23 + 0x120);
      fVar26 = (float)uVar27 * (float)uVar27;
      fVar62 = (float)((ulong)uVar27 >> 0x20);
      fVar62 = fVar62 * fVar62;
      uVar33 = (undefined1)((uint)fVar62 >> 8);
      uVar34 = (undefined1)((uint)fVar62 >> 0x10);
      uVar35 = (undefined1)((uint)fVar62 >> 0x18);
      fVar29 = (float)uVar31 * (float)uVar31;
      uVar36 = (undefined1)((uint)fVar29 >> 8);
      uVar37 = (undefined1)((uint)fVar29 >> 0x10);
      uVar38 = (undefined1)((uint)fVar29 >> 0x18);
      fVar24 = (float)((ulong)uVar31 >> 0x20);
      fVar24 = fVar24 * fVar24;
      uVar39 = (undefined1)((uint)fVar24 >> 8);
      uVar40 = (undefined1)((uint)fVar24 >> 0x10);
      uVar41 = (undefined1)((uint)fVar24 >> 0x18);
      auVar8[4] = SUB41(fVar62,0);
      auVar8._0_4_ = fVar26;
      auVar8[5] = uVar33;
      auVar8[6] = uVar34;
      auVar8[7] = uVar35;
      auVar8[8] = SUB41(fVar29,0);
      auVar8[9] = uVar36;
      auVar8[10] = uVar37;
      auVar8[0xb] = uVar38;
      auVar8[0xc] = SUB41(fVar24,0);
      auVar8[0xd] = uVar39;
      auVar8[0xe] = uVar40;
      auVar8[0xf] = uVar41;
      auVar9[4] = SUB41(fVar62,0);
      auVar9._0_4_ = fVar26;
      auVar9[5] = uVar33;
      auVar9[6] = uVar34;
      auVar9[7] = uVar35;
      auVar9[8] = SUB41(fVar29,0);
      auVar9[9] = uVar36;
      auVar9[10] = uVar37;
      auVar9[0xb] = uVar38;
      auVar9[0xc] = SUB41(fVar24,0);
      auVar9[0xd] = uVar39;
      auVar9[0xe] = uVar40;
      auVar9[0xf] = uVar41;
      auVar46 = NEON_ext(auVar8,auVar9,8,1);
      fVar26 = auVar46._0_4_ + fVar26;
      fVar62 = auVar46._4_4_ + fVar62;
      fVar29 = fVar26 + fVar62;
      fVar26 = fVar26 + fVar62;
      uVar33 = SUB41(fVar29,0);
      uVar34 = (undefined1)((uint)fVar29 >> 8);
      uVar35 = (undefined1)((uint)fVar29 >> 0x10);
      uVar36 = (undefined1)((uint)fVar29 >> 0x18);
      uVar37 = SUB41(fVar26,0);
      uVar38 = (undefined1)((uint)fVar26 >> 8);
      uVar39 = (undefined1)((uint)fVar26 >> 0x10);
      uVar40 = (undefined1)((uint)fVar26 >> 0x18);
    }
    uVar2 = CONCAT11(uVar34,uVar33);
    uVar14 = CONCAT11(uVar38,uVar37);
    auVar10[1] = uVar34;
    auVar10[0] = uVar33;
    auVar10[2] = uVar35;
    auVar10[3] = uVar36;
    auVar10[4] = uVar37;
    auVar10[5] = uVar38;
    auVar10[6] = uVar39;
    auVar10[7] = uVar40;
    auVar10[8] = uVar33;
    auVar10[9] = uVar34;
    auVar10[10] = uVar35;
    auVar10[0xb] = uVar36;
    auVar10[0xc] = uVar37;
    auVar10[0xd] = uVar38;
    auVar10[0xe] = uVar39;
    auVar10[0xf] = uVar40;
    auVar46 = NEON_frsqrte(auVar10,4);
    auVar54._0_4_ = (float)CONCAT13(uVar36,CONCAT12(uVar35,CONCAT11(uVar34,uVar33))) * auVar46._0_4_
    ;
    auVar54._4_4_ = (float)CONCAT13(uVar40,CONCAT12(uVar39,CONCAT11(uVar38,uVar37))) * auVar46._4_4_
    ;
    auVar54._8_4_ = (float)CONCAT13(uVar36,CONCAT12(uVar35,uVar2)) * auVar46._8_4_;
    auVar54._12_4_ = (float)CONCAT13(uVar40,CONCAT12(uVar39,uVar14)) * auVar46._12_4_;
    auVar60 = NEON_frsqrts(auVar46,auVar54,4);
    auVar44._0_4_ = auVar46._0_4_ * auVar60._0_4_;
    auVar44._4_4_ = auVar46._4_4_ * auVar60._4_4_;
    auVar44._8_4_ = auVar46._8_4_ * auVar60._8_4_;
    auVar44._12_4_ = auVar46._12_4_ * auVar60._12_4_;
    auVar55._0_4_ = (float)CONCAT13(uVar36,CONCAT12(uVar35,CONCAT11(uVar34,uVar33))) * auVar44._0_4_
    ;
    auVar55._4_4_ = (float)CONCAT13(uVar40,CONCAT12(uVar39,CONCAT11(uVar38,uVar37))) * auVar44._4_4_
    ;
    auVar55._8_4_ = (float)CONCAT13(uVar36,CONCAT12(uVar35,uVar2)) * auVar44._8_4_;
    auVar55._12_4_ = (float)CONCAT13(uVar40,CONCAT12(uVar39,uVar14)) * auVar44._12_4_;
    iVar43 = -(uint)((float)CONCAT13(uVar36,CONCAT12(uVar35,CONCAT11(uVar34,uVar33))) == 0.0);
    iVar51 = -(uint)((float)CONCAT13(uVar40,CONCAT12(uVar39,CONCAT11(uVar38,uVar37))) == 0.0);
    iVar52 = -(uint)((float)CONCAT13(uVar36,CONCAT12(uVar35,uVar2)) == 0.0);
    iVar53 = -(uint)((float)CONCAT13(uVar40,CONCAT12(uVar39,uVar14)) == 0.0);
    auVar46 = NEON_frsqrts(auVar44,auVar55,4);
    fVar26 = (float)uVar27 * auVar44._0_4_ * auVar46._0_4_;
    fVar62 = (float)((ulong)uVar27 >> 0x20) * auVar44._4_4_ * auVar46._4_4_;
    fVar29 = (float)uVar31 * auVar44._8_4_ * auVar46._8_4_;
    fVar24 = (float)((ulong)uVar31 >> 0x20) * auVar44._12_4_ * auVar46._12_4_;
    local_60 = CONCAT17((byte)((uint)fVar62 >> 0x18) & ~(byte)((uint)iVar51 >> 0x18),
                        CONCAT16((byte)((uint)fVar62 >> 0x10) & ~(byte)((uint)iVar51 >> 0x10),
                                 CONCAT15((byte)((uint)fVar62 >> 8) & ~(byte)((uint)iVar51 >> 8),
                                          CONCAT14(SUB41(fVar62,0) & ~(byte)iVar51,
                                                   CONCAT13((byte)((uint)fVar26 >> 0x18) &
                                                            ~(byte)((uint)iVar43 >> 0x18),
                                                            CONCAT12((byte)((uint)fVar26 >> 0x10) &
                                                                     ~(byte)((uint)iVar43 >> 0x10),
                                                                     CONCAT11((byte)((uint)fVar26 >>
                                                                                    8) &
                                                                              ~(byte)((uint)iVar43
                                                                                     >> 8),
                                                                              SUB41(fVar26,0) &
                                                                              ~(byte)iVar43)))))));
    uStack_58 = CONCAT17((byte)((uint)fVar24 >> 0x18) & ~(byte)((uint)iVar53 >> 0x18),
                         CONCAT16((byte)((uint)fVar24 >> 0x10) & ~(byte)((uint)iVar53 >> 0x10),
                                  CONCAT15((byte)((uint)fVar24 >> 8) & ~(byte)((uint)iVar53 >> 8),
                                           CONCAT14(SUB41(fVar24,0) & ~(byte)iVar53,
                                                    CONCAT13((byte)((uint)fVar29 >> 0x18) &
                                                             ~(byte)((uint)iVar52 >> 0x18),
                                                             CONCAT12((byte)((uint)fVar29 >> 0x10) &
                                                                      ~(byte)((uint)iVar52 >> 0x10),
                                                                      CONCAT11((byte)((uint)fVar29
                                                                                     >> 8) &
                                                                               ~(byte)((uint)iVar52
                                                                                      >> 8),
                                                                               SUB41(fVar29,0) &
                                                                               ~(byte)iVar52)))))));
    FUN_71005e3ff8(param_1,local_70);
    puVar18 = puVar17 + 4;
    FUN_71005def50(local_68,puVar18,puVar18,&local_60);
    fVar42 = (float)puVar17[4];
    fVar26 = fVar42 * fVar42;
    fVar50 = (float)((ulong)puVar17[4] >> 0x20);
    fVar62 = fVar50 * fVar50;
    uVar33 = (undefined1)((uint)fVar62 >> 8);
    uVar34 = (undefined1)((uint)fVar62 >> 0x10);
    uVar35 = (undefined1)((uint)fVar62 >> 0x18);
    fVar28 = (float)puVar17[5];
    fVar29 = fVar28 * fVar28;
    uVar36 = (undefined1)((uint)fVar29 >> 8);
    uVar37 = (undefined1)((uint)fVar29 >> 0x10);
    uVar38 = (undefined1)((uint)fVar29 >> 0x18);
    fVar32 = (float)((ulong)puVar17[5] >> 0x20);
    fVar24 = fVar32 * fVar32;
    uVar39 = (undefined1)((uint)fVar24 >> 8);
    uVar40 = (undefined1)((uint)fVar24 >> 0x10);
    uVar41 = (undefined1)((uint)fVar24 >> 0x18);
    auVar11[4] = SUB41(fVar62,0);
    auVar11._0_4_ = fVar26;
    auVar11[5] = uVar33;
    auVar11[6] = uVar34;
    auVar11[7] = uVar35;
    auVar11[8] = SUB41(fVar29,0);
    auVar11[9] = uVar36;
    auVar11[10] = uVar37;
    auVar11[0xb] = uVar38;
    auVar11[0xc] = SUB41(fVar24,0);
    auVar11[0xd] = uVar39;
    auVar11[0xe] = uVar40;
    auVar11[0xf] = uVar41;
    auVar12[4] = SUB41(fVar62,0);
    auVar12._0_4_ = fVar26;
    auVar12[5] = uVar33;
    auVar12[6] = uVar34;
    auVar12[7] = uVar35;
    auVar12[8] = SUB41(fVar29,0);
    auVar12[9] = uVar36;
    auVar12[10] = uVar37;
    auVar12[0xb] = uVar38;
    auVar12[0xc] = SUB41(fVar24,0);
    auVar12[0xd] = uVar39;
    auVar12[0xe] = uVar40;
    auVar12[0xf] = uVar41;
    auVar46 = NEON_ext(auVar11,auVar12,8,1);
    fVar26 = auVar46._0_4_ + fVar26;
    fVar62 = auVar46._4_4_ + fVar62;
    fVar29 = fVar26 + fVar62;
    fVar26 = fVar26 + fVar62;
    uVar33 = SUB41(fVar26,0);
    uVar34 = (undefined1)((uint)fVar26 >> 8);
    uVar35 = (undefined1)((uint)fVar26 >> 0x10);
    uVar36 = (undefined1)((uint)fVar26 >> 0x18);
    auVar13[4] = uVar33;
    auVar13._0_4_ = fVar29;
    auVar13[5] = uVar34;
    auVar13[6] = uVar35;
    auVar13[7] = uVar36;
    auVar13[8] = SUB41(fVar29,0);
    auVar13[9] = (char)((uint)fVar29 >> 8);
    auVar13[10] = (char)((uint)fVar29 >> 0x10);
    auVar13[0xb] = (char)((uint)fVar29 >> 0x18);
    auVar13[0xc] = uVar33;
    auVar13[0xd] = uVar34;
    auVar13[0xe] = uVar35;
    auVar13[0xf] = uVar36;
    auVar46 = NEON_frsqrte(auVar13,4);
    auVar56._0_4_ = auVar46._0_4_ * fVar29;
    auVar56._4_4_ = auVar46._4_4_ * fVar26;
    auVar56._8_4_ = auVar46._8_4_ * fVar29;
    uVar2 = (undefined2)(CONCAT15(uVar34,CONCAT14(uVar33,fVar29)) >> 0x20);
    auVar56._12_4_ = auVar46._12_4_ * (float)CONCAT13(uVar36,CONCAT12(uVar35,uVar2));
    auVar60 = NEON_frsqrts(auVar46,auVar56,4);
    auVar45._0_4_ = auVar46._0_4_ * auVar60._0_4_;
    auVar45._4_4_ = auVar46._4_4_ * auVar60._4_4_;
    auVar45._8_4_ = auVar46._8_4_ * auVar60._8_4_;
    auVar45._12_4_ = auVar46._12_4_ * auVar60._12_4_;
    auVar57._0_4_ = fVar29 * auVar45._0_4_;
    auVar57._4_4_ = fVar26 * auVar45._4_4_;
    auVar57._8_4_ = fVar29 * auVar45._8_4_;
    auVar57._12_4_ = (float)CONCAT13(uVar36,CONCAT12(uVar35,uVar2)) * auVar45._12_4_;
    iVar43 = -(uint)(fVar29 == 0.0);
    iVar51 = -(uint)(fVar26 == 0.0);
    iVar52 = -(uint)(fVar29 == 0.0);
    iVar53 = -(uint)((float)CONCAT13(uVar36,CONCAT12(uVar35,uVar2)) == 0.0);
    auVar46 = NEON_frsqrts(auVar45,auVar57,4);
    fVar42 = fVar42 * auVar45._0_4_ * auVar46._0_4_;
    fVar50 = fVar50 * auVar45._4_4_ * auVar46._4_4_;
    fVar28 = fVar28 * auVar45._8_4_ * auVar46._8_4_;
    fVar32 = fVar32 * auVar45._12_4_ * auVar46._12_4_;
    puVar17[5] = CONCAT17((byte)((uint)fVar32 >> 0x18) & ~(byte)((uint)iVar53 >> 0x18),
                          CONCAT16((byte)((uint)fVar32 >> 0x10) & ~(byte)((uint)iVar53 >> 0x10),
                                   CONCAT15((byte)((uint)fVar32 >> 8) & ~(byte)((uint)iVar53 >> 8),
                                            CONCAT14(SUB41(fVar32,0) & ~(byte)iVar53,
                                                     CONCAT13((byte)((uint)fVar28 >> 0x18) &
                                                              ~(byte)((uint)iVar52 >> 0x18),
                                                              CONCAT12((byte)((uint)fVar28 >> 0x10)
                                                                       & ~(byte)((uint)iVar52 >>
                                                                                0x10),
                                                                       CONCAT11((byte)((uint)fVar28
                                                                                      >> 8) &
                                                                                ~(byte)((uint)iVar52
                                                                                       >> 8),
                                                                                SUB41(fVar28,0) &
                                                                                ~(byte)iVar52)))))))
    ;
    puVar17[4] = CONCAT17((byte)((uint)fVar50 >> 0x18) & ~(byte)((uint)iVar51 >> 0x18),
                          CONCAT16((byte)((uint)fVar50 >> 0x10) & ~(byte)((uint)iVar51 >> 0x10),
                                   CONCAT15((byte)((uint)fVar50 >> 8) & ~(byte)((uint)iVar51 >> 8),
                                            CONCAT14(SUB41(fVar50,0) & ~(byte)iVar51,
                                                     CONCAT13((byte)((uint)fVar42 >> 0x18) &
                                                              ~(byte)((uint)iVar43 >> 0x18),
                                                              CONCAT12((byte)((uint)fVar42 >> 0x10)
                                                                       & ~(byte)((uint)iVar43 >>
                                                                                0x10),
                                                                       CONCAT11((byte)((uint)fVar42
                                                                                      >> 8) &
                                                                                ~(byte)((uint)iVar43
                                                                                       >> 8),
                                                                                SUB41(fVar42,0) &
                                                                                ~(byte)iVar43)))))))
    ;
    if (fVar25 == 1.4013e-45) {
      lVar23 = puVar17[6];
      *(undefined8 *)(lVar23 + 0x28) = puVar17[5];
      *(undefined8 *)(lVar23 + 0x20) = *puVar18;
    }
  }
  fVar25 = param_2[0x20];
  if ((float)(int)fVar25 < *(float *)(pbVar19 + 8)) {
    fVar25 = (float)((int)fVar25 + 1);
    param_2[0x20] = fVar25;
  }
joined_r0x0071005eb3f0:
  if (1 < (int)fVar25) {
    puVar17 = *(undefined8 **)(*(long *)(param_2 + 0x1a) + 0x30);
    puVar18 = (undefined8 *)puVar17[6];
    fVar26 = (float)*puVar17 - (float)*puVar18;
    fVar62 = (float)((ulong)*puVar17 >> 0x20) - (float)((ulong)*puVar18 >> 0x20);
    uVar27 = CONCAT44(fVar62,fVar26);
    fVar29 = (float)puVar17[1] - (float)puVar18[1];
    fVar25 = *(float *)(pbVar19 + 0x1c);
    uVar30 = (ulong)(uint)fVar29;
    if (fVar25 <= 0.0) {
      puVar17[3] = uVar30;
      puVar17[2] = uVar27;
      fVar25 = param_2[0x20];
    }
    else {
      if (2.0 <= param_2[0x23]) {
        auVar47._0_4_ = fVar26 * fVar26;
        auVar47._4_4_ = fVar62 * fVar62;
        auVar47._8_4_ = fVar29 * fVar29;
        auVar47._12_4_ = 0;
        auVar46 = NEON_ext(auVar47,auVar47,8,1);
        fVar42 = auVar46._0_4_ + auVar47._0_4_;
        fVar50 = auVar46._4_4_ + auVar47._4_4_;
        fVar24 = fVar42 + fVar50;
        fVar42 = fVar42 + fVar50;
        if (0.0 < fVar24) {
          auVar48._8_8_ = CONCAT44(fVar42,fVar24);
          auVar48._0_8_ = CONCAT44(fVar42,fVar24);
          auVar46 = NEON_frsqrte(auVar48,4);
          auVar63._0_4_ = fVar24 * auVar46._0_4_;
          auVar63._4_4_ = fVar42 * auVar46._4_4_;
          auVar63._8_4_ = fVar24 * auVar46._8_4_;
          auVar63._12_4_ = fVar42 * auVar46._12_4_;
          auVar60 = NEON_frsqrts(auVar46,auVar63,4);
          auVar58._0_4_ = auVar46._0_4_ * auVar60._0_4_;
          auVar58._4_4_ = auVar46._4_4_ * auVar60._4_4_;
          auVar58._8_4_ = auVar46._8_4_ * auVar60._8_4_;
          auVar58._12_4_ = auVar46._12_4_ * auVar60._12_4_;
          auVar64._0_4_ = fVar24 * auVar58._0_4_;
          auVar64._4_4_ = fVar42 * auVar58._4_4_;
          auVar64._8_4_ = fVar24 * auVar58._8_4_;
          auVar64._12_4_ = fVar42 * auVar58._12_4_;
          iVar43 = -(uint)(fVar24 == 0.0);
          iVar51 = -(uint)(fVar42 == 0.0);
          iVar52 = -(uint)(fVar24 == 0.0);
          iVar53 = -(uint)(fVar42 == 0.0);
          auVar46 = NEON_frsqrts(auVar58,auVar64,4);
          fVar26 = fVar26 * auVar58._0_4_ * auVar46._0_4_;
          fVar62 = fVar62 * auVar58._4_4_ * auVar46._4_4_;
          fVar29 = fVar29 * auVar58._8_4_ * auVar46._8_4_;
          fVar24 = auVar58._12_4_ * auVar46._12_4_ * 0.0;
          uVar27 = CONCAT17((byte)((uint)fVar62 >> 0x18) & ~(byte)((uint)iVar51 >> 0x18),
                            CONCAT16((byte)((uint)fVar62 >> 0x10) & ~(byte)((uint)iVar51 >> 0x10),
                                     CONCAT15((byte)((uint)fVar62 >> 8) & ~(byte)((uint)iVar51 >> 8)
                                              ,CONCAT14(SUB41(fVar62,0) & ~(byte)iVar51,
                                                        CONCAT13((byte)((uint)fVar26 >> 0x18) &
                                                                 ~(byte)((uint)iVar43 >> 0x18),
                                                                 CONCAT12((byte)((uint)fVar26 >>
                                                                                0x10) &
                                                                          ~(byte)((uint)iVar43 >>
                                                                                 0x10),
                                                                          CONCAT11((byte)((uint)
                                                  fVar26 >> 8) & ~(byte)((uint)iVar43 >> 8),
                                                  SUB41(fVar26,0) & ~(byte)iVar43)))))));
          uVar30 = CONCAT17((byte)((uint)fVar24 >> 0x18) & ~(byte)((uint)iVar53 >> 0x18),
                            CONCAT16((byte)((uint)fVar24 >> 0x10) & ~(byte)((uint)iVar53 >> 0x10),
                                     CONCAT15((byte)((uint)fVar24 >> 8) & ~(byte)((uint)iVar53 >> 8)
                                              ,CONCAT14(SUB41(fVar24,0) & ~(byte)iVar53,
                                                        CONCAT13((byte)((uint)fVar29 >> 0x18) &
                                                                 ~(byte)((uint)iVar52 >> 0x18),
                                                                 CONCAT12((byte)((uint)fVar29 >>
                                                                                0x10) &
                                                                          ~(byte)((uint)iVar52 >>
                                                                                 0x10),
                                                                          CONCAT11((byte)((uint)
                                                  fVar29 >> 8) & ~(byte)((uint)iVar52 >> 8),
                                                  SUB41(fVar29,0) & ~(byte)iVar52)))))));
        }
        fVar26 = param_2[0x10] + ((float)uVar27 - param_2[0x10]) * fVar25;
        fVar62 = param_2[0x11] + ((float)((ulong)uVar27 >> 0x20) - param_2[0x11]) * fVar25;
        uVar27 = CONCAT44(fVar62,fVar26);
        fVar29 = param_2[0x12] + ((float)uVar30 - param_2[0x12]) * fVar25;
        fVar25 = param_2[0x13] + ((float)(uVar30 >> 0x20) - param_2[0x13]) * fVar25;
        uVar30 = CONCAT44(fVar25,fVar29);
        fVar26 = fVar26 * fVar26;
        fVar62 = fVar62 * fVar62;
        uVar33 = (undefined1)((uint)fVar62 >> 8);
        uVar34 = (undefined1)((uint)fVar62 >> 0x10);
        uVar35 = (undefined1)((uint)fVar62 >> 0x18);
        fVar29 = fVar29 * fVar29;
        uVar36 = (undefined1)((uint)fVar29 >> 8);
        uVar37 = (undefined1)((uint)fVar29 >> 0x10);
        uVar38 = (undefined1)((uint)fVar29 >> 0x18);
        fVar25 = fVar25 * fVar25;
        uVar39 = (undefined1)((uint)fVar25 >> 8);
        uVar40 = (undefined1)((uint)fVar25 >> 0x10);
        uVar41 = (undefined1)((uint)fVar25 >> 0x18);
        auVar6[4] = SUB41(fVar62,0);
        auVar6._0_4_ = fVar26;
        auVar6[5] = uVar33;
        auVar6[6] = uVar34;
        auVar6[7] = uVar35;
        auVar6[8] = SUB41(fVar29,0);
        auVar6[9] = uVar36;
        auVar6[10] = uVar37;
        auVar6[0xb] = uVar38;
        auVar6[0xc] = SUB41(fVar25,0);
        auVar6[0xd] = uVar39;
        auVar6[0xe] = uVar40;
        auVar6[0xf] = uVar41;
        auVar7[4] = SUB41(fVar62,0);
        auVar7._0_4_ = fVar26;
        auVar7[5] = uVar33;
        auVar7[6] = uVar34;
        auVar7[7] = uVar35;
        auVar7[8] = SUB41(fVar29,0);
        auVar7[9] = uVar36;
        auVar7[10] = uVar37;
        auVar7[0xb] = uVar38;
        auVar7[0xc] = SUB41(fVar25,0);
        auVar7[0xd] = uVar39;
        auVar7[0xe] = uVar40;
        auVar7[0xf] = uVar41;
        auVar46 = NEON_ext(auVar6,auVar7,8,1);
        fVar26 = auVar46._0_4_ + fVar26;
        fVar62 = auVar46._4_4_ + fVar62;
        fVar25 = fVar26 + fVar62;
        fVar26 = fVar26 + fVar62;
        uVar33 = SUB41(fVar25,0);
        uVar34 = (undefined1)((uint)fVar25 >> 8);
        uVar35 = (undefined1)((uint)fVar25 >> 0x10);
        uVar36 = (undefined1)((uint)fVar25 >> 0x18);
        uVar37 = SUB41(fVar26,0);
        uVar38 = (undefined1)((uint)fVar26 >> 8);
        uVar39 = (undefined1)((uint)fVar26 >> 0x10);
        uVar40 = (undefined1)((uint)fVar26 >> 0x18);
      }
      else {
        fVar26 = fVar26 * fVar26;
        fVar62 = fVar62 * fVar62;
        uVar33 = (undefined1)((uint)fVar62 >> 8);
        uVar34 = (undefined1)((uint)fVar62 >> 0x10);
        uVar35 = (undefined1)((uint)fVar62 >> 0x18);
        fVar29 = fVar29 * fVar29;
        uVar36 = (undefined1)((uint)fVar29 >> 8);
        uVar37 = (undefined1)((uint)fVar29 >> 0x10);
        uVar38 = (undefined1)((uint)fVar29 >> 0x18);
        auVar3[4] = SUB41(fVar62,0);
        auVar3._0_4_ = fVar26;
        auVar3[5] = uVar33;
        auVar3[6] = uVar34;
        auVar3[7] = uVar35;
        auVar3[8] = SUB41(fVar29,0);
        auVar3[9] = uVar36;
        auVar3[10] = uVar37;
        auVar3[0xb] = uVar38;
        auVar3._12_4_ = 0;
        auVar4[4] = SUB41(fVar62,0);
        auVar4._0_4_ = fVar26;
        auVar4[5] = uVar33;
        auVar4[6] = uVar34;
        auVar4[7] = uVar35;
        auVar4[8] = SUB41(fVar29,0);
        auVar4[9] = uVar36;
        auVar4[10] = uVar37;
        auVar4[0xb] = uVar38;
        auVar4._12_4_ = 0;
        auVar46 = NEON_ext(auVar3,auVar4,8,1);
        fVar26 = auVar46._0_4_ + fVar26;
        fVar62 = auVar46._4_4_ + fVar62;
        fVar25 = fVar26 + fVar62;
        fVar26 = fVar26 + fVar62;
        uVar33 = SUB41(fVar25,0);
        uVar34 = (undefined1)((uint)fVar25 >> 8);
        uVar35 = (undefined1)((uint)fVar25 >> 0x10);
        uVar36 = (undefined1)((uint)fVar25 >> 0x18);
        uVar37 = SUB41(fVar26,0);
        uVar38 = (undefined1)((uint)fVar26 >> 8);
        uVar39 = (undefined1)((uint)fVar26 >> 0x10);
        uVar40 = (undefined1)((uint)fVar26 >> 0x18);
      }
      if (0.0 < fVar25) {
        uVar2 = CONCAT11(uVar34,uVar33);
        uVar14 = CONCAT11(uVar38,uVar37);
        auVar5[1] = uVar34;
        auVar5[0] = uVar33;
        auVar5[2] = uVar35;
        auVar5[3] = uVar36;
        auVar5[4] = uVar37;
        auVar5[5] = uVar38;
        auVar5[6] = uVar39;
        auVar5[7] = uVar40;
        auVar5[8] = uVar33;
        auVar5[9] = uVar34;
        auVar5[10] = uVar35;
        auVar5[0xb] = uVar36;
        auVar5[0xc] = uVar37;
        auVar5[0xd] = uVar38;
        auVar5[0xe] = uVar39;
        auVar5[0xf] = uVar40;
        auVar46 = NEON_frsqrte(auVar5,4);
        auVar59._0_4_ =
             (float)CONCAT13(uVar36,CONCAT12(uVar35,CONCAT11(uVar34,uVar33))) * auVar46._0_4_;
        auVar59._4_4_ =
             (float)CONCAT13(uVar40,CONCAT12(uVar39,CONCAT11(uVar38,uVar37))) * auVar46._4_4_;
        auVar59._8_4_ = (float)CONCAT13(uVar36,CONCAT12(uVar35,uVar2)) * auVar46._8_4_;
        auVar59._12_4_ = (float)CONCAT13(uVar40,CONCAT12(uVar39,uVar14)) * auVar46._12_4_;
        auVar60 = NEON_frsqrts(auVar46,auVar59,4);
        auVar49._0_4_ = auVar46._0_4_ * auVar60._0_4_;
        auVar49._4_4_ = auVar46._4_4_ * auVar60._4_4_;
        auVar49._8_4_ = auVar46._8_4_ * auVar60._8_4_;
        auVar49._12_4_ = auVar46._12_4_ * auVar60._12_4_;
        auVar61._0_4_ =
             (float)CONCAT13(uVar36,CONCAT12(uVar35,CONCAT11(uVar34,uVar33))) * auVar49._0_4_;
        auVar61._4_4_ =
             (float)CONCAT13(uVar40,CONCAT12(uVar39,CONCAT11(uVar38,uVar37))) * auVar49._4_4_;
        auVar61._8_4_ = (float)CONCAT13(uVar36,CONCAT12(uVar35,uVar2)) * auVar49._8_4_;
        auVar61._12_4_ = (float)CONCAT13(uVar40,CONCAT12(uVar39,uVar14)) * auVar49._12_4_;
        iVar43 = -(uint)((float)CONCAT13(uVar36,CONCAT12(uVar35,CONCAT11(uVar34,uVar33))) == 0.0);
        iVar51 = -(uint)((float)CONCAT13(uVar40,CONCAT12(uVar39,CONCAT11(uVar38,uVar37))) == 0.0);
        iVar52 = -(uint)((float)CONCAT13(uVar36,CONCAT12(uVar35,uVar2)) == 0.0);
        iVar53 = -(uint)((float)CONCAT13(uVar40,CONCAT12(uVar39,uVar14)) == 0.0);
        auVar46 = NEON_frsqrts(auVar49,auVar61,4);
        fVar25 = (float)uVar27 * auVar49._0_4_ * auVar46._0_4_;
        fVar26 = (float)((ulong)uVar27 >> 0x20) * auVar49._4_4_ * auVar46._4_4_;
        fVar62 = (float)uVar30 * auVar49._8_4_ * auVar46._8_4_;
        fVar29 = (float)(uVar30 >> 0x20) * auVar49._12_4_ * auVar46._12_4_;
        uVar27 = CONCAT17((byte)((uint)fVar26 >> 0x18) & ~(byte)((uint)iVar51 >> 0x18),
                          CONCAT16((byte)((uint)fVar26 >> 0x10) & ~(byte)((uint)iVar51 >> 0x10),
                                   CONCAT15((byte)((uint)fVar26 >> 8) & ~(byte)((uint)iVar51 >> 8),
                                            CONCAT14(SUB41(fVar26,0) & ~(byte)iVar51,
                                                     CONCAT13((byte)((uint)fVar25 >> 0x18) &
                                                              ~(byte)((uint)iVar43 >> 0x18),
                                                              CONCAT12((byte)((uint)fVar25 >> 0x10)
                                                                       & ~(byte)((uint)iVar43 >>
                                                                                0x10),
                                                                       CONCAT11((byte)((uint)fVar25
                                                                                      >> 8) &
                                                                                ~(byte)((uint)iVar43
                                                                                       >> 8),
                                                                                SUB41(fVar25,0) &
                                                                                ~(byte)iVar43)))))))
        ;
        uVar30 = CONCAT17((byte)((uint)fVar29 >> 0x18) & ~(byte)((uint)iVar53 >> 0x18),
                          CONCAT16((byte)((uint)fVar29 >> 0x10) & ~(byte)((uint)iVar53 >> 0x10),
                                   CONCAT15((byte)((uint)fVar29 >> 8) & ~(byte)((uint)iVar53 >> 8),
                                            CONCAT14(SUB41(fVar29,0) & ~(byte)iVar53,
                                                     CONCAT13((byte)((uint)fVar62 >> 0x18) &
                                                              ~(byte)((uint)iVar52 >> 0x18),
                                                              CONCAT12((byte)((uint)fVar62 >> 0x10)
                                                                       & ~(byte)((uint)iVar52 >>
                                                                                0x10),
                                                                       CONCAT11((byte)((uint)fVar62
                                                                                      >> 8) &
                                                                                ~(byte)((uint)iVar52
                                                                                       >> 8),
                                                                                SUB41(fVar62,0) &
                                                                                ~(byte)iVar52)))))))
        ;
      }
      *(ulong *)(param_2 + 0x12) = uVar30;
      *(undefined8 *)(param_2 + 0x10) = uVar27;
      puVar17[3] = *(undefined8 *)(param_2 + 0x12);
      puVar17[2] = *(undefined8 *)(param_2 + 0x10);
      fVar25 = param_2[0x20];
    }
    if (fVar25 == 2.8026e-45) {
      puVar18[3] = puVar17[3];
      puVar18[2] = puVar17[2];
    }
    (*(code *)puVar22[9])
              (puVar22[7] +
               (puVar22[10] * (ulong)*(byte *)(puVar22 + 0xf) +
                (long)*(int *)((long)puVar22 + 100) * (long)(int)param_2[0x21] * 0x30 &
               0xfffffffffffffffc),param_2,pbVar19);
  }
  return;
}



void FUN_71005eb8bc(float param_1,float *param_2,undefined8 *param_3,undefined8 *param_4,int param_5
                   ,int param_6)

{
  float *pfVar1;
  float *pfVar2;
  undefined8 *puVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  float fVar8;
  undefined8 uVar9;
  float fVar10;
  float fVar12;
  float fVar13;
  undefined1 auVar11 [16];
  float fVar14;
  undefined8 uVar15;
  undefined8 local_50;
  ulong uStack_48;
  undefined8 local_40;
  ulong uStack_38;
  undefined8 local_30;
  ulong uStack_28;
  undefined8 local_20;
  ulong uStack_18;
  
  if (param_5 == 0) {
    local_20 = *param_4;
    pfVar1 = (float *)param_4[6];
    pfVar2 = *(float **)(pfVar1 + 0xc);
    fVar7 = (float)param_4[1];
    uStack_18 = param_4[1] & 0xffffffff;
    local_30 = *(undefined8 *)pfVar1;
    uStack_28 = (ulong)(uint)pfVar1[2];
    fVar4 = (float)((ulong)local_20 >> 0x20);
    local_50 = CONCAT44((pfVar2[1] - fVar4) * 0.5,(*pfVar2 - (float)local_20) * 0.5);
    uStack_48 = (ulong)(uint)((pfVar2[2] - fVar7) * 0.5);
    auVar11 = NEON_fmov(0x3e800000,4);
    local_40 = CONCAT44(((pfVar1[1] - fVar4) +
                        (pfVar1[1] - (float)((ulong)*(undefined8 *)pfVar2 >> 0x20))) * auVar11._4_4_
                        ,((*pfVar1 - (float)local_20) + (*pfVar1 - (float)*(undefined8 *)pfVar2)) *
                         auVar11._0_4_);
    fVar4 = 1.0 - param_1;
    fVar5 = *(float *)(param_4 + 2) * fVar4;
    fVar6 = *(float *)((long)param_4 + 0x14) * fVar4;
    fVar8 = *(float *)(param_4 + 3) * fVar4;
    fVar4 = *(float *)((long)param_4 + 0x1c) * fVar4;
    fVar10 = pfVar1[4] * param_1;
    fVar12 = pfVar1[5] * param_1;
    fVar13 = pfVar1[6] * param_1;
    fVar14 = pfVar1[7] * param_1;
    uStack_38 = (ulong)(uint)(((pfVar1[2] - fVar7) +
                              (pfVar1[2] - (float)*(undefined8 *)(pfVar2 + 2))) * auVar11._8_4_);
  }
  else {
    if (param_6 + -1 == param_5) {
      pfVar1 = (float *)param_4[7];
      pfVar2 = *(float **)(pfVar1 + 0xe);
      local_20 = *(undefined8 *)pfVar1;
      local_30 = *param_4;
      fVar5 = (float)param_4[1];
      uStack_18 = (ulong)(uint)pfVar1[2];
      uStack_28 = param_4[1] & 0xffffffff;
      fVar4 = (float)((ulong)local_30 >> 0x20);
      local_40 = CONCAT44((fVar4 - pfVar2[1]) * 0.5,((float)local_30 - *pfVar2) * 0.5);
      uStack_38 = (ulong)(uint)((fVar5 - pfVar2[2]) * 0.5);
      auVar11 = NEON_fmov(0xbe800000,4);
      local_50 = CONCAT44(((pfVar1[1] - fVar4) + (pfVar1[1] - pfVar2[1])) * auVar11._4_4_,
                          ((*pfVar1 - (float)local_30) + (*pfVar1 - *pfVar2)) * auVar11._0_4_);
      uVar15 = CONCAT44(pfVar1[5] * 0.0 + (float)((ulong)param_4[2] >> 0x20),
                        pfVar1[4] * 0.0 + (float)param_4[2]);
      uVar9 = CONCAT44(pfVar1[7] * 0.0 + (float)((ulong)param_4[3] >> 0x20),
                       pfVar1[6] * 0.0 + (float)param_4[3]);
      param_1 = 1.0;
      uStack_48 = (ulong)(uint)(((pfVar1[2] - fVar5) + (pfVar1[2] - pfVar2[2])) * auVar11._8_4_);
      goto LAB_71005ebb64;
    }
    pfVar1 = (float *)param_4[6];
    if (param_6 + -2 == param_5) {
      puVar3 = *(undefined8 **)(pfVar1 + 0xe);
      pfVar2 = (float *)puVar3[7];
      local_20 = *puVar3;
      uStack_18 = puVar3[1] & 0xffffffff;
      local_30 = *(undefined8 *)pfVar1;
      uStack_28 = *(ulong *)(pfVar1 + 2) & 0xffffffff;
      local_40 = CONCAT44(((float)((ulong)*(undefined8 *)pfVar1 >> 0x20) - pfVar2[1]) * 0.5,
                          ((float)*(undefined8 *)pfVar1 - *pfVar2) * 0.5);
      uStack_38 = (ulong)(uint)(((float)*(undefined8 *)(pfVar1 + 2) - pfVar2[2]) * 0.5);
      fVar4 = (float)*puVar3;
      fVar5 = (float)((ulong)*puVar3 >> 0x20);
      auVar11 = NEON_fmov(0xbe800000,4);
      local_50 = CONCAT44(((fVar5 - pfVar1[1]) +
                          (fVar5 - (float)((ulong)*(undefined8 *)pfVar2 >> 0x20))) * auVar11._4_4_,
                          ((fVar4 - *pfVar1) + (fVar4 - (float)*(undefined8 *)pfVar2)) *
                          auVar11._0_4_);
      fVar4 = 1.0 - param_1;
      fVar5 = *(float *)(puVar3 + 2) * fVar4;
      fVar6 = *(float *)((long)puVar3 + 0x14) * fVar4;
      fVar8 = *(float *)(puVar3 + 3) * fVar4;
      fVar4 = *(float *)((long)puVar3 + 0x1c) * fVar4;
      fVar10 = pfVar1[4] * param_1;
      fVar12 = pfVar1[5] * param_1;
      fVar13 = pfVar1[6] * param_1;
      fVar14 = pfVar1[7] * param_1;
      uStack_48 = (ulong)(uint)((((float)puVar3[1] - pfVar1[2]) +
                                ((float)puVar3[1] - (float)*(undefined8 *)(pfVar2 + 2))) *
                               auVar11._8_4_);
    }
    else {
      local_20 = *param_4;
      uStack_18 = param_4[1] & 0xffffffff;
      local_30 = *(undefined8 *)pfVar1;
      uStack_28 = (ulong)(uint)pfVar1[2];
      uVar15 = *(undefined8 *)param_4[7];
      pfVar2 = *(float **)(pfVar1 + 0xc);
      local_40 = CONCAT44((pfVar1[1] - (float)((ulong)uVar15 >> 0x20)) * 0.5,
                          (*pfVar1 - (float)uVar15) * 0.5);
      uStack_38 = (ulong)(uint)((pfVar1[2] - (float)((undefined8 *)param_4[7])[1]) * 0.5);
      local_50 = CONCAT44((pfVar2[1] - (float)((ulong)local_20 >> 0x20)) * 0.5,
                          (*pfVar2 - (float)local_20) * 0.5);
      fVar4 = 1.0 - param_1;
      fVar5 = *(float *)(param_4 + 2) * fVar4;
      fVar6 = *(float *)((long)param_4 + 0x14) * fVar4;
      fVar8 = *(float *)(param_4 + 3) * fVar4;
      fVar4 = *(float *)((long)param_4 + 0x1c) * fVar4;
      fVar10 = pfVar1[4] * param_1;
      fVar12 = pfVar1[5] * param_1;
      fVar13 = pfVar1[6] * param_1;
      fVar14 = pfVar1[7] * param_1;
      uStack_48 = (ulong)(uint)((pfVar2[2] - (float)param_4[1]) * 0.5);
    }
  }
  uVar15 = CONCAT44(fVar6 + fVar12,fVar5 + fVar10);
  uVar9 = CONCAT44(fVar4 + fVar14,fVar8 + fVar13);
LAB_71005ebb64:
  param_3[1] = uVar9;
  *param_3 = uVar15;
  FUN_71005dee80(param_1,param_2,&local_20,&local_40,&local_30,&local_50);
  return;
}



int FUN_71005ebb88(long param_1)

{
  float fVar1;
  
  fVar1 = *(float *)(param_1 + 0x2c);
  if (fVar1 <= 1.0) {
    fVar1 = 1.0;
  }
  return (int)(*(float *)(*(long *)(*(long *)(param_1 + 0x40) + 0x1f8) + 8) * fVar1);
}



int FUN_71005ebbb0(long param_1)

{
  int iVar1;
  long lVar2;
  
  iVar1 = *(int *)(param_1 + 0xa0);
  for (lVar2 = *(long *)(*(long *)(param_1 + 0x3a8) + 0x40); lVar2 != 0;
      lVar2 = *(long *)(lVar2 + 0x78)) {
    iVar1 = iVar1 + 1;
  }
  return iVar1;
}



void FUN_71005ebbd0(undefined8 *param_1,long param_2,long param_3,undefined8 *param_4)

{
  undefined8 uVar1;
  
  uVar1 = param_4[4];
  param_1[1] = param_4[5];
  *param_1 = uVar1;
  uVar1 = *(undefined8 *)(param_3 + 0x18);
  param_1[2] = *(undefined8 *)(param_3 + 0x10);
  param_1[3] = uVar1;
  uVar1 = *param_4;
  param_1[5] = param_4[1];
  param_1[4] = uVar1;
  uVar1 = param_4[2];
  param_1[7] = param_4[3];
  param_1[6] = uVar1;
  *(undefined4 *)(param_1 + 8) = *(undefined4 *)((long)param_4 + 0x8c);
  *(float *)((long)param_1 + 0x44) =
       (float)*(int *)(param_4 + 0x10) +
       (float)(*(int *)(param_4 + 0x10) + -1) * *(float *)(param_2 + 4);
  *(float *)(param_1 + 9) = (float)*(int *)((long)param_4 + 0x84);
  *(undefined4 *)((long)param_1 + 0x4c) = *(undefined4 *)(param_4 + 0x12);
  *(undefined4 *)(param_1 + 10) = *(undefined4 *)(param_4 + 10);
  *(undefined4 *)((long)param_1 + 0x54) = *(undefined4 *)((long)param_4 + 0x54);
  *(undefined4 *)(param_1 + 0xb) = *(undefined4 *)(param_4 + 0xb);
  *(float *)((long)param_1 + 0x5c) = (float)*(int *)(param_3 + 100);
  uVar1 = param_4[6];
  param_1[0xd] = param_4[7];
  param_1[0xc] = uVar1;
  return;
}



bool FUN_71005ebd80(undefined8 *param_1)

{
  short *psVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  short sVar5;
  short sVar6;
  bool bVar7;
  uint uVar8;
  int iVar9;
  int iVar10;
  long lVar11;
  ulong uVar12;
  long lVar13;
  int iVar14;
  ulong uVar15;
  ulong uVar16;
  ulong uVar17;
  long lVar18;
  
  uVar8 = FUN_71005ef540(*(uint *)(*(long *)(*(long *)(*(long *)*param_1 + 0x40) + 0x1f8) + 0x20));
  uVar2 = uVar8 + 1;
  uVar17 = (ulong)uVar2;
  iVar10 = *(int *)(param_1 + 5);
  lVar13 = *(long *)*param_1;
  lVar11 = *(long *)(((long *)*param_1)[1] + 0x40);
  iVar14 = *(int *)(lVar13 + 0x98);
  uVar16 = (lVar11 + (long)(int)(uVar2 * 2 + 2) * ((long)iVar10 + -1) * 2) - 1U & -lVar11;
  iVar9 = FUN_71005ec04c(lVar13,(int)*(float *)(*(long *)(*(long *)(lVar13 + 0x40) + 0x1f8) + 8));
  lVar13 = *(long *)(((long *)*param_1)[1] + 0x40);
  uVar12 = (lVar13 + (long)iVar10 * ((long)iVar14 + (long)iVar9) * 0x30) - 1U & -lVar13;
  *(undefined4 *)((long)param_1 + 0x2c) = 1;
  param_1[3] = uVar12;
  param_1[4] = uVar16;
  lVar11 = *(long *)*param_1;
  lVar18 = *(long *)(lVar11 + 0x3a8);
  lVar13 = *(long *)(lVar11 + 0x658);
  lVar11 = uVar12 * *(byte *)(lVar11 + 0x710);
  uVar12 = lVar11 + uVar16;
  *(int *)(lVar18 + 0x2c) = (int)uVar12;
  uVar12 = FUN_71005cedd0(lVar13,uVar12 & 0xffffffff,*(long *)(lVar13 + 0x1d8));
  *(ulong *)(lVar18 + 0x20) = uVar12;
  if (uVar12 != 0) {
    iVar10 = (int)*(undefined8 *)(*(long *)(*(long *)*param_1 + 0x658) + 0x1d8);
    uVar3 = ((int)lVar11 + iVar10) - 1U & -iVar10;
    bVar7 = uVar3 <= *(uint *)(lVar18 + 0x2c);
    uVar4 = 0;
    if (bVar7) {
      uVar4 = uVar3;
    }
    *(uint *)(lVar18 + 0x28) = uVar4;
    uVar15 = 0;
    if (bVar7) {
      uVar15 = uVar12;
    }
    param_1[1] = uVar15;
    if (uVar16 == 0) {
      lVar13 = param_1[2];
    }
    else {
      uVar4 = *(uint *)(lVar18 + 0x28);
      uVar3 = uVar4 + (((int)uVar16 + iVar10) - 1U & -iVar10);
      if (*(uint *)(lVar18 + 0x2c) < uVar3) {
        lVar13 = 0;
      }
      else {
        *(uint *)(lVar18 + 0x28) = uVar3;
        lVar13 = *(long *)(lVar18 + 0x20) + (ulong)uVar4;
      }
      param_1[2] = lVar13;
    }
    thunk_EXT_FUN_02e95df0(lVar13,0,uVar16);
    if (1 < *(int *)(param_1 + 5)) {
      if ((int)uVar8 < 0) {
        iVar14 = uVar8 * 2;
        lVar18 = 0;
        lVar11 = 0;
        iVar10 = iVar14 + 3;
        do {
          sVar5 = (short)lVar18;
          lVar18 = uVar17 + lVar18;
          *(ushort *)(lVar13 + (long)(iVar10 + -1) * 2) = ((ushort)iVar14 | 1) + sVar5;
          lVar11 = lVar11 + 1;
          *(short *)(lVar13 + (long)iVar10 * 2) = (short)lVar18;
          iVar10 = iVar10 + iVar14 + 4;
        } while (lVar11 < (long)*(int *)(param_1 + 5) + -1);
      }
      else {
        lVar18 = 0;
        lVar11 = 0;
        uVar16 = (ulong)uVar8;
        iVar10 = 3;
        do {
          uVar15 = 0;
          iVar14 = iVar10;
          if (uVar8 != 0) {
            do {
              sVar5 = (short)lVar18 + (short)uVar15;
              *(short *)(lVar13 + (long)(iVar14 + -3) * 2) = sVar5;
              sVar6 = (short)uVar16 + (short)uVar15;
              uVar15 = uVar15 + 2;
              *(short *)(lVar13 + (long)(iVar14 + -2) * 2) = sVar6 + 1;
              *(short *)(lVar13 + (long)(iVar14 + -1) * 2) = sVar5 + 1;
              *(short *)(lVar13 + (long)iVar14 * 2) = sVar6 + 2;
              iVar14 = iVar14 + 4;
            } while ((uVar17 & 0xfffffffe) != uVar15);
          }
          iVar14 = (int)lVar11;
          if ((uVar2 & 1) != 0) {
            iVar9 = (int)uVar15 + iVar14 * uVar2;
            psVar1 = (short *)(lVar13 + (long)((iVar9 + iVar14) * 2) * 2);
            sVar5 = (short)iVar9;
            *psVar1 = sVar5;
            psVar1[1] = (short)uVar2 + sVar5;
          }
          lVar11 = lVar11 + 1;
          uVar16 = uVar16 + uVar17;
          sVar5 = (short)lVar11 * (short)uVar2;
          lVar18 = lVar18 + uVar17;
          iVar10 = iVar10 + uVar8 * 2 + 4;
          psVar1 = (short *)(lVar13 + (long)(int)((iVar14 + uVar2 * (int)lVar11) * 2) * 2);
          *psVar1 = (short)uVar8 + sVar5;
          psVar1[1] = sVar5;
        } while (lVar11 < (long)*(int *)(param_1 + 5) + -1);
      }
    }
  }
  return uVar12 != 0;
}



int FUN_71005ec04c(long param_1,int param_2)

{
  uint uVar1;
  long lVar2;
  uint uVar3;
  bool bVar4;
  int iVar5;
  int *piVar6;
  int iVar7;
  float fVar8;
  float fVar9;
  float fVar10;
  
  lVar2 = *(long *)(param_1 + 0x48);
  fVar8 = *(float *)(*(long *)(param_1 + 0x40) + 0xf4);
  bVar4 = false;
  if ((*(long *)(*(long *)(param_1 + 0x40) + 0x450) != 0) && (bVar4 = false, !NAN(fVar8))) {
    bVar4 = fVar8 < 1.0;
  }
  fVar9 = 1.0;
  if (!bVar4) {
    fVar9 = fVar8;
  }
  uVar3 = *(uint *)(param_1 + 0x30);
  fVar8 = 1.0;
  if (*(int *)(lVar2 + 0xd74) != 0) {
    fVar8 = (float)*(int *)(lVar2 + 0xd74);
  }
  fVar10 = (float)(*(int *)(lVar2 + 0xd80) + 1);
  iVar5 = (int)(fVar8 / fVar10);
  iVar7 = (int)((float)param_2 / fVar10);
  uVar1 = (uint)(iVar5 < iVar7) & uVar3 >> 0x14;
  if (((uVar3 ^ 0xffffffff) & 0x180000) == 0) {
    uVar1 = 1;
  }
  if (uVar1 == 0) {
    iVar5 = iVar7;
  }
  iVar5 = (int)((float)(int)fVar9 + (float)(int)(fVar9 * (float)iVar5));
  if (*(int *)(lVar2 + 0xdec) == 0) {
    if (*(char *)(lVar2 + 0xdb0) == '\r') {
      piVar6 = (int *)(lVar2 + 0xe00);
    }
    else {
      if (*(char *)(lVar2 + 0xdb0) != '\x02') goto LAB_71005ec104;
      piVar6 = (int *)(lVar2 + 0xdf8);
    }
    iVar5 = *piVar6 * iVar5;
  }
LAB_71005ec104:
  if ((uVar3 & 0x20001) == 1) {
    iVar5 = *(int *)(*(long *)(*(long *)(param_1 + 0x58) + 0x70) + 0x98) * iVar5;
  }
  return iVar5;
}



undefined8
FUN_71005ec12c(long param_1,long *param_2,byte param_3,long *param_4,undefined8 param_5,
              long *param_6,int *param_7)

{
  undefined8 uVar1;
  
  if (*(int *)((long)param_6 + 0x24) != -1) {
    return 0;
  }
  FUN_71005fc9f0(param_1,*param_4,0x1ff);
  FUN_71005fc820(param_1,(long *)(param_2[8] + 0x2c8));
  FUN_71005fc8c4(param_1,param_2[8] + 0x2f0);
  FUN_71005fc71c(param_1,param_2[8] + 0x30c);
  FUN_71005fc99c(param_1,param_2[8] + (ulong)*(byte *)((long)param_6 + 0x2c) * 0x20 + 0xf8);
  FUN_71005cf5f4((long *)param_2[0xe1],param_1,(long)param_2,(long)param_4,param_6,param_7);
  FUN_71005cfadc(param_1,(long)param_2,(long)param_4);
  uVar1 = FUN_71005c9d10(param_2,param_1,param_3,param_5,(long)param_6);
  return uVar1;
}



void FUN_71005ec220(undefined8 *param_1)

{
  *(undefined4 *)(param_1 + 10) = 0;
  param_1[8] = 0;
  param_1[9] = 0;
  param_1[6] = 0;
  param_1[7] = 0;
  param_1[4] = 0;
  param_1[5] = 0;
  param_1[2] = 0;
  param_1[3] = 0;
  *param_1 = 0;
  param_1[1] = 0;
  return;
}



void FUN_71005ec32c(undefined8 *param_1,long *param_2,long *param_3)

{
  (**(code **)(*param_3 + 0x18))(param_3,*param_1);
  *param_1 = 0;
                    // WARNING: Could not recover jumptable at 0x0071005ec370. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_2 + 0x18))(param_2,param_1[1]);
  return;
}



undefined8 FUN_71005ecf5c(long param_1)

{
  int iVar1;
  int iVar2;
  long lVar3;
  long lVar4;
  float fVar5;
  
  if (((*(byte *)(*(long *)(param_1 + 0x10) + 0x31) >> 6 & 1) != 0) &&
     (lVar3 = FUN_71005ed000(*(long **)(param_1 + 0x18),*(long *)(param_1 + 0x10)), lVar3 != 0)) {
    *(undefined8 *)(lVar3 + 0x9c) = 0;
    *(undefined4 *)(lVar3 + 0x84) = 0;
    fVar5 = *(float *)(*(long *)(param_1 + 0x10) + 0x28);
    *(float *)(lVar3 + 0x98) = fVar5 - (float)(int)fVar5;
    *(long *)(param_1 + 8) = lVar3;
    lVar4 = *(long *)(*(long *)(param_1 + 0x10) + 0x3a8);
    iVar1 = *(int *)(lVar4 + 0x6c);
    iVar2 = 0;
    if (iVar1 != 0) {
      iVar2 = *(int *)(lVar4 + 0x70) / iVar1;
    }
    *(int *)(lVar3 + 0x8c) = *(int *)(lVar4 + 0x70) - iVar2 * iVar1;
    iVar1 = 0;
    if (*(int *)(lVar4 + 0x70) + 1 < *(int *)(lVar4 + 0x6c)) {
      iVar1 = *(int *)(lVar4 + 0x70) + 1;
    }
    *(int *)(lVar4 + 0x70) = iVar1;
    FUN_71005e4220(param_1,(undefined8 *)(lVar3 + 0x20));
    return 1;
  }
  return 0;
}



long FUN_71005ed000(long *param_1,long param_2)

{
  ulong uVar1;
  long lVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  long lVar7;
  long *plVar8;
  ulong uVar9;
  long lVar10;
  int iVar11;
  ulong uVar12;
  long lVar13;
  long lVar14;
  char *pcVar15;
  uint uVar16;
  
  (*(code *)**(undefined8 **)param_1[1])();
  iVar4 = (int)param_1[9];
  if (0 < iVar4) {
    lVar14 = *param_1;
    iVar11 = *(int *)((long)param_1 + 0x4c);
    iVar5 = iVar4;
    do {
      pcVar15 = (char *)(lVar14 + (long)iVar11 * 0xb0 + 0xa4);
      if (*pcVar15 == '\0') {
        lVar10 = param_2 + 0x6d0;
        uVar16 = (uint)*(float *)(*(long *)(*(long *)(param_2 + 0x40) + 0x1f8) + 0xc);
        lVar2 = (ulong)uVar16 * 0x70;
        thunk_EXT_FUN_02e95df0(lVar10);
        lVar7 = (**(code **)(**(long **)(param_2 + 0x6f0) + 0x10))
                          (*(long **)(param_2 + 0x6f0),lVar2,0x80);
        if (lVar7 == 0) {
          thunk_EXT_FUN_02e95df0(lVar10);
          lVar13 = 0;
          *(undefined8 *)(lVar14 + (long)iVar11 * 0xb0 + 0x60) = 0;
        }
        else {
          lVar13 = lVar14 + (long)iVar11 * 0xb0;
          *(long *)(param_2 + 0x6f8) = *(long *)(param_2 + 0x6f8) + lVar2;
          *(long *)(param_2 + 0x700) = *(long *)(param_2 + 0x700) + 1;
          thunk_EXT_FUN_02e95df0(lVar10);
          uVar6 = uVar16 - 1;
          plVar8 = (long *)(lVar14 + (long)iVar11 * 0xb0 + 0x60);
          *plVar8 = lVar7;
          if (uVar6 != 0) {
            if (uVar6 == 1) {
              uVar9 = 0;
            }
            else {
              lVar10 = 0;
              uVar9 = 0;
              do {
                uVar9 = uVar9 + 2;
                *(long *)(*plVar8 + lVar10 + 0x50) = *plVar8 + lVar10 + 0x70;
                lVar2 = *plVar8 + lVar10;
                lVar10 = lVar10 + 0xe0;
                *(long *)(lVar2 + 0xc0) = lVar2 + 0xe0;
              } while (((ulong)uVar6 & 0xfffffffe) != uVar9);
            }
            if ((uVar6 & 1) != 0) {
              lVar10 = *plVar8 + uVar9 * 0x70;
              *(long *)(lVar10 + 0x50) = lVar10 + 0x70;
            }
            if (1 < uVar16) {
              uVar9 = (ulong)uVar16 - 1;
              if (uVar16 == 2) {
                lVar10 = 1;
              }
              else {
                lVar10 = 0;
                uVar1 = 0;
                do {
                  uVar12 = uVar1;
                  uVar1 = uVar12 + 2;
                  *(long *)(*plVar8 + lVar10 + 200) = *plVar8 + lVar10;
                  lVar2 = *plVar8 + lVar10;
                  lVar10 = lVar10 + 0xe0;
                  *(long *)(lVar2 + 0x138) = lVar2 + 0x70;
                } while ((uVar9 & 0xfffffffffffffffe) != uVar1);
                lVar10 = uVar12 + 3;
              }
              if ((uVar9 & 1) != 0) {
                lVar10 = *plVar8 + lVar10 * 0x70;
                *(long *)(lVar10 + 0x58) = lVar10 + -0x70;
              }
            }
          }
          *(long *)(*plVar8 + (ulong)uVar6 * 0x70 + 0x50) = *plVar8;
          *(ulong *)(*plVar8 + 0x58) = *plVar8 + (ulong)uVar6 * 0x70;
          lVar10 = *plVar8;
          lVar14 = lVar14 + (long)iVar11 * 0xb0;
          *(undefined4 *)(lVar14 + 0x90) = 0;
          *(undefined4 *)(lVar14 + 0x80) = 0;
          *(undefined4 *)(lVar14 + 0x88) = 0;
          *(undefined8 *)(lVar14 + 0x78) = 0;
          *(long *)(lVar14 + 0x68) = lVar10;
          *(long *)(lVar14 + 0x70) = lVar10;
          *pcVar15 = '\x01';
          *(int *)(param_1 + 10) = (int)param_1[10] + 1;
        }
        goto LAB_71005ed248;
      }
      iVar3 = 0;
      if (iVar11 + 1 < iVar4) {
        iVar3 = iVar11 + 1;
      }
      iVar5 = iVar5 + -1;
      *(int *)((long)param_1 + 0x4c) = iVar3;
      iVar11 = iVar3;
    } while (iVar5 != 0);
  }
  lVar13 = 0;
LAB_71005ed248:
  (**(code **)(*(long *)param_1[1] + 8))();
  return lVar13;
}



void FUN_71005ed3b8(long param_1,float *param_2)

{
  bool bVar1;
  bool bVar2;
  uint uVar3;
  byte *pbVar4;
  long *plVar5;
  long lVar6;
  long lVar7;
  float fVar8;
  float fVar9;
  undefined8 uVar10;
  undefined8 uVar11;
  float fVar12;
  float afStack_60 [4];
  
  lVar7 = *(long *)(param_1 + 0x10);
  lVar6 = *(long *)(lVar7 + 0x3a8);
  pbVar4 = *(byte **)(*(long *)(lVar7 + 0x40) + 0x1f8);
  fVar8 = (float)FUN_71005e3d3c(param_1);
  param_2[0x24] = fVar8;
  fVar8 = (float)FUN_71005e3d44(param_1);
  param_2[0x25] = fVar8;
  param_2[0x22] = 0.0;
  FUN_71005e437c(param_1,(undefined8 *)(param_2 + 0xc));
  FUN_71005e4220(param_1,(undefined8 *)afStack_60);
  plVar5 = *(long **)(*(long *)(param_1 + 0x10) + 0x40);
  fVar8 = (float)FUN_71005e3d44(param_1);
  fVar9 = (float)FUN_71005e3d3c(param_1);
  FUN_71005e1b1c(fVar8,fVar9,(undefined8 *)param_2,plVar5,afStack_60);
  plVar5 = *(long **)(*(long *)(param_1 + 0x10) + 0x40);
  fVar8 = (float)FUN_71005e3d44(param_1);
  fVar9 = (float)FUN_71005e3d3c(param_1);
  FUN_71005e2368(fVar8,fVar9,(undefined8 *)(param_2 + 4),plVar5,afStack_60);
  uVar10 = *(undefined8 *)param_2;
  uVar11 = *(undefined8 *)(param_2 + 4);
  fVar8 = *(float *)(*(long *)(*(long *)(*(long *)(param_1 + 0x10) + 0x40) + 0x340) + 0x630);
  *param_2 = fVar8 * (float)uVar10;
  param_2[2] = fVar8 * (float)*(undefined8 *)(param_2 + 2);
  param_2[1] = fVar8 * (float)((ulong)uVar10 >> 0x20);
  param_2[4] = fVar8 * (float)uVar11;
  param_2[5] = fVar8 * (float)((ulong)uVar11 >> 0x20);
  param_2[6] = fVar8 * (float)*(undefined8 *)(param_2 + 6);
  fVar8 = param_2[0x24] + 0.0005 + param_2[0x26];
  fVar9 = fVar8 + *(float *)(lVar7 + 0x2c);
  if (fVar9 - fVar8 < 0.9995) {
    fVar12 = fVar9 - (float)(int)fVar9;
    bVar1 = true;
    bVar2 = false;
    if (0.0 < (float)(int)fVar9 - (float)(int)fVar8) {
      bVar1 = false;
      bVar2 = true;
      if (!NAN(fVar12)) {
        bVar1 = fVar12 < 0.001;
        bVar2 = false;
      }
    }
    if (bVar1 != bVar2) {
      uVar3 = 0;
      if (0.0005 <= fVar9 - fVar8) {
        uVar3 = (uint)(fVar8 - (float)(int)fVar8 <= 0.001);
      }
      if (param_2[0x24] == 0.0) {
        uVar3 = 1;
      }
      goto LAB_71005ed568;
    }
  }
  uVar3 = 1;
LAB_71005ed568:
  FUN_71005ed5d0(param_1,(long)param_2,pbVar4,uVar3);
  (**(code **)(lVar6 + 0x48))
            (*(long *)(lVar6 + 0x38) +
             (*(long *)(lVar6 + 0x50) * (ulong)*(byte *)(lVar6 + 0x7c) +
              (long)*(int *)(lVar6 + 100) * (long)(int)param_2[0x23] * 0x60 & 0xfffffffffffffffc),
             param_2,pbVar4);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_71005ed5d0(long param_1,long param_2,byte *param_3,uint param_4)

{
  float *pfVar1;
  long lVar2;
  long lVar3;
  undefined1 auVar4 [16];
  undefined1 auVar5 [16];
  undefined1 auVar6 [16];
  undefined1 auVar7 [16];
  undefined1 auVar8 [16];
  undefined1 auVar9 [16];
  undefined1 auVar10 [16];
  undefined1 auVar11 [16];
  undefined1 auVar12 [16];
  undefined1 auVar13 [16];
  undefined1 auVar14 [16];
  undefined1 auVar15 [16];
  undefined1 auVar16 [16];
  undefined1 auVar17 [16];
  undefined1 auVar18 [16];
  undefined1 auVar19 [16];
  undefined1 auVar20 [16];
  undefined1 auVar21 [16];
  undefined1 auVar22 [16];
  undefined1 auVar23 [16];
  undefined1 auVar24 [16];
  undefined1 auVar25 [16];
  undefined1 auVar26 [16];
  undefined1 auVar27 [16];
  undefined1 auVar28 [16];
  undefined1 auVar29 [16];
  undefined2 uVar30;
  float *pfVar31;
  float *pfVar32;
  float *pfVar33;
  ulong uVar34;
  long lVar35;
  float *pfVar36;
  ulong uVar37;
  ulong uVar38;
  float *pfVar39;
  float *pfVar40;
  undefined8 *puVar41;
  undefined8 *puVar42;
  float *pfVar43;
  undefined1 uVar44;
  byte bVar45;
  undefined1 uVar46;
  byte bVar47;
  undefined1 uVar48;
  byte bVar49;
  undefined1 uVar50;
  byte bVar51;
  undefined1 uVar52;
  byte bVar53;
  undefined1 uVar54;
  byte bVar55;
  undefined1 uVar56;
  byte bVar57;
  undefined1 uVar58;
  byte bVar59;
  undefined1 uVar60;
  byte bVar61;
  undefined1 uVar62;
  byte bVar63;
  undefined1 uVar64;
  byte bVar65;
  undefined1 uVar66;
  byte bVar67;
  undefined1 uVar68;
  byte bVar69;
  undefined1 uVar70;
  byte bVar71;
  undefined1 uVar72;
  byte bVar73;
  undefined1 uVar74;
  byte bVar75;
  float fVar76;
  float fVar77;
  float fVar78;
  float fVar79;
  undefined1 auVar82 [12];
  undefined8 uVar80;
  float fVar120;
  float fVar122;
  float fVar123;
  undefined1 auVar84 [16];
  undefined1 auVar85 [16];
  undefined1 auVar86 [16];
  undefined1 auVar87 [16];
  undefined1 auVar88 [16];
  undefined1 auVar89 [16];
  undefined1 auVar90 [16];
  undefined1 auVar91 [16];
  undefined1 auVar92 [16];
  undefined1 auVar93 [16];
  undefined1 auVar94 [16];
  undefined1 auVar96 [16];
  undefined1 auVar97 [16];
  undefined1 auVar98 [16];
  undefined1 auVar83 [12];
  undefined1 auVar100 [16];
  undefined1 auVar101 [16];
  undefined8 uVar81;
  undefined1 auVar102 [16];
  undefined1 auVar103 [16];
  undefined1 auVar104 [16];
  undefined1 auVar105 [16];
  undefined1 auVar106 [16];
  undefined1 auVar107 [16];
  undefined1 auVar108 [16];
  undefined1 auVar109 [16];
  undefined1 auVar110 [16];
  undefined1 auVar111 [16];
  undefined1 auVar112 [16];
  undefined1 auVar113 [16];
  undefined1 auVar114 [16];
  float fVar121;
  undefined1 auVar115 [16];
  undefined1 auVar116 [16];
  undefined1 auVar117 [16];
  undefined1 auVar118 [16];
  undefined1 auVar119 [16];
  float fVar124;
  float fVar125;
  int iVar127;
  int iVar128;
  float fVar154;
  int iVar155;
  int iVar156;
  int iVar157;
  int iVar158;
  undefined1 auVar129 [16];
  undefined1 auVar130 [16];
  undefined1 auVar131 [16];
  undefined1 auVar132 [16];
  float fVar126;
  undefined1 auVar133 [16];
  undefined1 auVar134 [16];
  undefined1 auVar135 [16];
  undefined1 auVar136 [16];
  undefined1 auVar137 [16];
  undefined1 auVar138 [16];
  undefined1 auVar139 [16];
  undefined1 auVar140 [16];
  undefined1 auVar141 [16];
  undefined1 auVar142 [16];
  undefined1 auVar143 [16];
  undefined1 auVar144 [16];
  undefined1 auVar145 [16];
  undefined1 auVar146 [16];
  undefined1 auVar147 [16];
  undefined1 auVar148 [16];
  undefined1 auVar149 [16];
  undefined1 auVar150 [16];
  undefined1 auVar151 [16];
  undefined1 auVar152 [16];
  undefined1 auVar153 [16];
  int iVar159;
  int iVar160;
  float fVar161;
  undefined8 uVar162;
  undefined1 auVar164 [16];
  undefined1 auVar165 [16];
  undefined1 auVar166 [16];
  undefined1 auVar167 [16];
  undefined1 auVar168 [16];
  undefined1 auVar169 [16];
  undefined1 auVar170 [16];
  undefined1 auVar171 [16];
  undefined1 auVar172 [16];
  undefined1 auVar173 [16];
  undefined1 auVar174 [16];
  undefined1 auVar175 [16];
  undefined1 auVar176 [16];
  undefined1 auVar177 [16];
  undefined1 auVar178 [16];
  undefined1 auVar179 [16];
  undefined1 auVar180 [16];
  undefined1 auVar181 [16];
  undefined1 auVar182 [16];
  undefined8 uVar163;
  undefined1 auVar183 [16];
  undefined1 auVar184 [16];
  undefined1 auVar185 [16];
  undefined1 auVar186 [16];
  undefined1 auVar187 [16];
  undefined1 auVar188 [16];
  undefined1 auVar189 [16];
  undefined1 auVar190 [16];
  undefined1 auVar191 [16];
  undefined1 auVar192 [16];
  undefined1 auVar193 [16];
  undefined1 auVar194 [16];
  undefined1 auVar195 [16];
  undefined1 auVar196 [16];
  undefined1 auVar197 [16];
  undefined1 auVar198 [16];
  float fVar199;
  undefined1 auVar200 [16];
  undefined1 auVar201 [16];
  undefined1 auVar202 [16];
  undefined1 auVar203 [16];
  undefined1 auVar204 [16];
  undefined1 auVar205 [16];
  undefined1 auVar206 [16];
  undefined8 uVar207;
  undefined1 auVar209 [16];
  undefined1 auVar210 [16];
  undefined1 auVar211 [16];
  undefined1 auVar212 [16];
  undefined8 uVar208;
  undefined1 auVar213 [16];
  undefined1 auVar214 [16];
  undefined1 auVar215 [16];
  undefined1 auVar216 [16];
  undefined1 auVar217 [16];
  undefined1 auVar218 [16];
  undefined1 auVar219 [16];
  undefined1 auVar220 [16];
  undefined1 auVar221 [16];
  undefined1 auVar222 [16];
  undefined1 auVar223 [16];
  undefined1 auVar224 [16];
  undefined1 auVar225 [16];
  undefined8 uVar226;
  undefined1 auVar227 [16];
  undefined1 auVar228 [16];
  undefined1 auVar229 [16];
  undefined1 auVar230 [16];
  undefined8 uVar231;
  float local_e0;
  float fStack_dc;
  float fStack_d8;
  float fStack_d4;
  float local_b0 [4];
  float afStack_a0 [4];
  float afStack_90 [4];
  float afStack_80 [2];
  float local_78;
  undefined8 local_70;
  undefined8 uStack_68;
  undefined1 auVar95 [16];
  undefined1 auVar99 [16];
  
  fVar121 = 1.0;
  fVar76 = *(float *)(*(long *)(param_1 + 0x10) + 0x2c);
  puVar42 = *(undefined8 **)(*(long *)(param_1 + 0x10) + 0x3a8);
  fVar79 = *(float *)(param_3 + 0x28) + (1.0 - fVar76) * (1.0 - *(float *)(param_3 + 0x28));
  FUN_71005e415c(param_1,afStack_90);
  FUN_71005e41c0(param_1,afStack_a0);
  if ((param_4 & 1) == 0) {
    puVar41 = *(undefined8 **)(*(long *)(param_2 + 0x68) + 0x50);
    uVar80 = puVar41[1];
    uVar162 = *puVar41;
    if (param_3[1] == 0) {
      FUN_71005e4078(param_1,local_b0);
      FUN_71005e3d7c(param_1,puVar41);
    }
    else {
      FUN_71005e4104(param_1,local_b0);
      FUN_71005e3d54(param_1,puVar41);
    }
    *(undefined8 *)(param_2 + 0x58) = puVar41[1];
    local_e0 = (float)uVar162;
    fStack_dc = (float)((ulong)uVar162 >> 0x20);
    fStack_d8 = (float)uVar80;
    fStack_d4 = (float)((ulong)uVar80 >> 0x20);
    *(undefined8 *)(param_2 + 0x50) = *puVar41;
    local_e0 = (float)*puVar41 - local_e0;
    fStack_dc = (float)((ulong)*puVar41 >> 0x20) - fStack_dc;
    fStack_d8 = (float)puVar41[1] - fStack_d8;
    fStack_d4 = (float)((ulong)puVar41[1] >> 0x20) - fStack_d4;
    local_e0 = local_e0 * local_e0;
    fStack_dc = fStack_dc * fStack_dc;
    uVar44 = (undefined1)((uint)fStack_dc >> 8);
    uVar46 = (undefined1)((uint)fStack_dc >> 0x10);
    uVar48 = (undefined1)((uint)fStack_dc >> 0x18);
    fStack_d8 = fStack_d8 * fStack_d8;
    uVar50 = (undefined1)((uint)fStack_d8 >> 8);
    uVar52 = (undefined1)((uint)fStack_d8 >> 0x10);
    uVar54 = (undefined1)((uint)fStack_d8 >> 0x18);
    fStack_d4 = fStack_d4 * fStack_d4;
    uVar56 = (undefined1)((uint)fStack_d4 >> 8);
    uVar58 = (undefined1)((uint)fStack_d4 >> 0x10);
    uVar60 = (undefined1)((uint)fStack_d4 >> 0x18);
    auVar136[4] = SUB41(fStack_dc,0);
    auVar136._0_4_ = local_e0;
    auVar136[5] = uVar44;
    auVar136[6] = uVar46;
    auVar136[7] = uVar48;
    auVar136[8] = SUB41(fStack_d8,0);
    auVar136[9] = uVar50;
    auVar136[10] = uVar52;
    auVar136[0xb] = uVar54;
    auVar136[0xc] = SUB41(fStack_d4,0);
    auVar136[0xd] = uVar56;
    auVar136[0xe] = uVar58;
    auVar136[0xf] = uVar60;
    auVar214[4] = SUB41(fStack_dc,0);
    auVar214._0_4_ = local_e0;
    auVar214[5] = uVar44;
    auVar214[6] = uVar46;
    auVar214[7] = uVar48;
    auVar214[8] = SUB41(fStack_d8,0);
    auVar214[9] = uVar50;
    auVar214[10] = uVar52;
    auVar214[0xb] = uVar54;
    auVar214[0xc] = SUB41(fStack_d4,0);
    auVar214[0xd] = uVar56;
    auVar214[0xe] = uVar58;
    auVar214[0xf] = uVar60;
    auVar136 = NEON_ext(auVar136,auVar214,8,1);
    *(float *)(param_2 + 0xa0) =
         *(float *)(param_2 + 0xa0) + SQRT(auVar136._0_4_ + local_e0 + auVar136._4_4_ + fStack_dc);
    *(float *)(puVar41 + 0xc) = local_b0[0];
    if (param_3[1] == 0) {
      uVar34 = *(ulong *)(*(long *)(param_1 + 0x10) + 0x118);
      puVar41[8] = *(undefined8 *)(*(long *)(param_1 + 0x10) + 0x110);
      puVar41[9] = uVar34 & 0xffffffff;
      puVar41[8] = puVar41[8];
      bVar45 = *param_3;
    }
    else {
      puVar41[9] = puVar42[1];
      puVar41[8] = *puVar42;
      bVar45 = *param_3;
    }
    if ((bVar45 - 1 < 2) &&
       (lVar35 = *(long *)(param_1 + 0x10), *(char *)(*(long *)(lVar35 + 0x48) + 0xe22) != '\0')) {
      iVar127 = *(int *)(param_2 + 0x80);
      if (iVar127 < 1) {
        uVar162 = puVar41[4];
        uVar80 = puVar41[5];
        uVar60 = (undefined1)uVar80;
        uVar62 = (undefined1)((ulong)uVar80 >> 8);
        uVar64 = (undefined1)((ulong)uVar80 >> 0x10);
        uVar66 = (undefined1)((ulong)uVar80 >> 0x18);
        uVar68 = (undefined1)((ulong)uVar80 >> 0x20);
        uVar70 = (undefined1)((ulong)uVar80 >> 0x28);
        uVar72 = (undefined1)((ulong)uVar80 >> 0x30);
        uVar74 = (undefined1)((ulong)uVar80 >> 0x38);
        uVar44 = (undefined1)uVar162;
        uVar46 = (undefined1)((ulong)uVar162 >> 8);
        uVar48 = (undefined1)((ulong)uVar162 >> 0x10);
        uVar50 = (undefined1)((ulong)uVar162 >> 0x18);
        uVar52 = (undefined1)((ulong)uVar162 >> 0x20);
        uVar54 = (undefined1)((ulong)uVar162 >> 0x28);
        uVar56 = (undefined1)((ulong)uVar162 >> 0x30);
        uVar58 = (undefined1)((ulong)uVar162 >> 0x38);
      }
      else {
        pfVar39 = (float *)puVar41[10];
        fVar125 = 1.0 / *(float *)(lVar35 + 0x2c);
        fVar121 = ((float)*puVar41 - *pfVar39) * fVar125 + 0.0;
        uVar44 = SUB41(fVar121,0);
        uVar46 = (undefined1)((uint)fVar121 >> 8);
        uVar48 = (undefined1)((uint)fVar121 >> 0x10);
        uVar50 = (undefined1)((uint)fVar121 >> 0x18);
        fVar121 = ((float)((ulong)*puVar41 >> 0x20) - pfVar39[1]) * fVar125 + 0.0;
        uVar52 = SUB41(fVar121,0);
        uVar54 = (undefined1)((uint)fVar121 >> 8);
        uVar56 = (undefined1)((uint)fVar121 >> 0x10);
        uVar58 = (undefined1)((uint)fVar121 >> 0x18);
        fVar121 = ((float)puVar41[1] - pfVar39[2]) * fVar125 + 0.0;
        uVar60 = SUB41(fVar121,0);
        uVar62 = (undefined1)((uint)fVar121 >> 8);
        uVar64 = (undefined1)((uint)fVar121 >> 0x10);
        uVar66 = (undefined1)((uint)fVar121 >> 0x18);
        fVar121 = ((float)((ulong)puVar41[1] >> 0x20) - pfVar39[3]) * fVar125 + 0.0;
        uVar68 = SUB41(fVar121,0);
        uVar70 = (undefined1)((uint)fVar121 >> 8);
        uVar72 = (undefined1)((uint)fVar121 >> 0x10);
        uVar74 = (undefined1)((uint)fVar121 >> 0x18);
      }
      auVar222._0_4_ =
           (float)CONCAT13(uVar50,CONCAT12(uVar48,CONCAT11(uVar46,uVar44))) *
           (float)CONCAT13(uVar50,CONCAT12(uVar48,CONCAT11(uVar46,uVar44)));
      auVar222._4_4_ =
           (float)CONCAT13(uVar58,CONCAT12(uVar56,CONCAT11(uVar54,uVar52))) *
           (float)CONCAT13(uVar58,CONCAT12(uVar56,CONCAT11(uVar54,uVar52)));
      auVar222._8_4_ =
           (float)CONCAT13(uVar66,CONCAT12(uVar64,CONCAT11(uVar62,uVar60))) *
           (float)CONCAT13(uVar66,CONCAT12(uVar64,CONCAT11(uVar62,uVar60)));
      auVar222._12_4_ =
           (float)CONCAT13(uVar74,CONCAT12(uVar72,CONCAT11(uVar70,uVar68))) *
           (float)CONCAT13(uVar74,CONCAT12(uVar72,CONCAT11(uVar70,uVar68)));
      auVar136 = NEON_ext(auVar222,auVar222,8,1);
      fVar125 = auVar136._0_4_ + auVar222._0_4_;
      fVar77 = auVar136._4_4_ + auVar222._4_4_;
      fVar121 = fVar125 + fVar77;
      uVar162 = CONCAT44(fVar125 + fVar77,fVar121);
      if (fVar121 < 1e-05) {
        uVar80 = *(undefined8 *)(lVar35 + 0x128);
        uVar60 = (undefined1)uVar80;
        uVar62 = (undefined1)((ulong)uVar80 >> 8);
        uVar64 = (undefined1)((ulong)uVar80 >> 0x10);
        uVar66 = (undefined1)((ulong)uVar80 >> 0x18);
        uVar68 = (undefined1)((ulong)uVar80 >> 0x20);
        uVar70 = (undefined1)((ulong)uVar80 >> 0x28);
        uVar72 = (undefined1)((ulong)uVar80 >> 0x30);
        uVar74 = (undefined1)((ulong)uVar80 >> 0x38);
        uVar162 = *(undefined8 *)(lVar35 + 0x120);
        uVar44 = (undefined1)uVar162;
        uVar46 = (undefined1)((ulong)uVar162 >> 8);
        uVar48 = (undefined1)((ulong)uVar162 >> 0x10);
        uVar50 = (undefined1)((ulong)uVar162 >> 0x18);
        uVar52 = (undefined1)((ulong)uVar162 >> 0x20);
        uVar54 = (undefined1)((ulong)uVar162 >> 0x28);
        uVar56 = (undefined1)((ulong)uVar162 >> 0x30);
        uVar58 = (undefined1)((ulong)uVar162 >> 0x38);
        auVar89._0_4_ = (float)uVar162 * (float)uVar162;
        fVar121 = (float)((ulong)uVar162 >> 0x20);
        auVar89._4_4_ = fVar121 * fVar121;
        auVar89._8_4_ = (float)uVar80 * (float)uVar80;
        fVar121 = (float)((ulong)uVar80 >> 0x20);
        auVar89._12_4_ = fVar121 * fVar121;
        auVar136 = NEON_ext(auVar89,auVar89,8,1);
        fVar121 = auVar136._0_4_ + auVar89._0_4_;
        fVar125 = auVar136._4_4_ + auVar89._4_4_;
        uVar162 = CONCAT44(fVar121 + fVar125,fVar121 + fVar125);
      }
      auVar90._8_8_ = uVar162;
      auVar90._0_8_ = uVar162;
      auVar136 = NEON_frsqrte(auVar90,4);
      fVar121 = (float)uVar162;
      auVar171._0_4_ = fVar121 * auVar136._0_4_;
      fVar125 = (float)((ulong)uVar162 >> 0x20);
      auVar171._4_4_ = fVar125 * auVar136._4_4_;
      auVar171._8_4_ = fVar121 * auVar136._8_4_;
      auVar171._12_4_ = fVar125 * auVar136._12_4_;
      auVar214 = NEON_frsqrts(auVar136,auVar171,4);
      auVar134._0_4_ = auVar136._0_4_ * auVar214._0_4_;
      auVar134._4_4_ = auVar136._4_4_ * auVar214._4_4_;
      auVar134._8_4_ = auVar136._8_4_ * auVar214._8_4_;
      auVar134._12_4_ = auVar136._12_4_ * auVar214._12_4_;
      auVar172._0_4_ = fVar121 * auVar134._0_4_;
      auVar172._4_4_ = fVar125 * auVar134._4_4_;
      auVar172._8_4_ = fVar121 * auVar134._8_4_;
      auVar172._12_4_ = fVar125 * auVar134._12_4_;
      iVar128 = -(uint)(fVar121 == 0.0);
      iVar155 = -(uint)(fVar125 == 0.0);
      iVar156 = -(uint)(fVar121 == 0.0);
      iVar157 = -(uint)(fVar125 == 0.0);
      auVar136 = NEON_frsqrts(auVar134,auVar172,4);
      fVar121 = (float)CONCAT13(uVar50,CONCAT12(uVar48,CONCAT11(uVar46,uVar44))) *
                auVar134._0_4_ * auVar136._0_4_;
      fVar125 = (float)CONCAT13(uVar58,CONCAT12(uVar56,CONCAT11(uVar54,uVar52))) *
                auVar134._4_4_ * auVar136._4_4_;
      fVar77 = (float)CONCAT13(uVar66,CONCAT12(uVar64,CONCAT11(uVar62,uVar60))) *
               auVar134._8_4_ * auVar136._8_4_;
      fVar124 = (float)CONCAT13(uVar74,CONCAT12(uVar72,CONCAT11(uVar70,uVar68))) *
                auVar134._12_4_ * auVar136._12_4_;
      uStack_68 = CONCAT17((byte)((uint)fVar124 >> 0x18) & ~(byte)((uint)iVar157 >> 0x18),
                           CONCAT16((byte)((uint)fVar124 >> 0x10) & ~(byte)((uint)iVar157 >> 0x10),
                                    CONCAT15((byte)((uint)fVar124 >> 8) &
                                             ~(byte)((uint)iVar157 >> 8),
                                             CONCAT14(SUB41(fVar124,0) & ~(byte)iVar157,
                                                      CONCAT13((byte)((uint)fVar77 >> 0x18) &
                                                               ~(byte)((uint)iVar156 >> 0x18),
                                                               CONCAT12((byte)((uint)fVar77 >> 0x10)
                                                                        & ~(byte)((uint)iVar156 >>
                                                                                 0x10),
                                                                        CONCAT11((byte)((uint)fVar77
                                                                                       >> 8) &
                                                                                 ~(byte)((uint)
                                                  iVar156 >> 8),SUB41(fVar77,0) & ~(byte)iVar156))))
                                            )));
      local_70 = CONCAT17((byte)((uint)fVar125 >> 0x18) & ~(byte)((uint)iVar155 >> 0x18),
                          CONCAT16((byte)((uint)fVar125 >> 0x10) & ~(byte)((uint)iVar155 >> 0x10),
                                   CONCAT15((byte)((uint)fVar125 >> 8) & ~(byte)((uint)iVar155 >> 8)
                                            ,CONCAT14(SUB41(fVar125,0) & ~(byte)iVar155,
                                                      CONCAT13((byte)((uint)fVar121 >> 0x18) &
                                                               ~(byte)((uint)iVar128 >> 0x18),
                                                               CONCAT12((byte)((uint)fVar121 >> 0x10
                                                                              ) & ~(byte)((uint)
                                                  iVar128 >> 0x10),
                                                  CONCAT11((byte)((uint)fVar121 >> 8) &
                                                           ~(byte)((uint)iVar128 >> 8),
                                                           SUB41(fVar121,0) & ~(byte)iVar128)))))));
      FUN_71005e3ff8(param_1,afStack_80);
      puVar42 = puVar41 + 8;
      FUN_71005def50(local_78,puVar42,puVar42,&local_70);
      fVar121 = (float)puVar41[8];
      auVar91._0_4_ = fVar121 * fVar121;
      fVar125 = (float)((ulong)puVar41[8] >> 0x20);
      auVar91._4_4_ = fVar125 * fVar125;
      fVar77 = (float)puVar41[9];
      auVar91._8_4_ = fVar77 * fVar77;
      fVar124 = (float)((ulong)puVar41[9] >> 0x20);
      auVar91._12_4_ = fVar124 * fVar124;
      auVar136 = NEON_ext(auVar91,auVar91,8,1);
      fVar78 = auVar136._0_4_ + auVar91._0_4_;
      fVar120 = auVar136._4_4_ + auVar91._4_4_;
      fVar199 = fVar78 + fVar120;
      fVar78 = fVar78 + fVar120;
      auVar92._8_8_ = CONCAT44(fVar78,fVar199);
      auVar92._0_8_ = CONCAT44(fVar78,fVar199);
      auVar136 = NEON_frsqrte(auVar92,4);
      auVar173._0_4_ = auVar136._0_4_ * fVar199;
      auVar173._4_4_ = auVar136._4_4_ * fVar78;
      auVar173._8_4_ = auVar136._8_4_ * fVar199;
      auVar173._12_4_ = auVar136._12_4_ * fVar78;
      auVar214 = NEON_frsqrts(auVar136,auVar173,4);
      auVar135._0_4_ = auVar136._0_4_ * auVar214._0_4_;
      auVar135._4_4_ = auVar136._4_4_ * auVar214._4_4_;
      auVar135._8_4_ = auVar136._8_4_ * auVar214._8_4_;
      auVar135._12_4_ = auVar136._12_4_ * auVar214._12_4_;
      auVar174._0_4_ = fVar199 * auVar135._0_4_;
      auVar174._4_4_ = fVar78 * auVar135._4_4_;
      auVar174._8_4_ = fVar199 * auVar135._8_4_;
      auVar174._12_4_ = fVar78 * auVar135._12_4_;
      iVar128 = -(uint)(fVar199 == 0.0);
      iVar155 = -(uint)(fVar78 == 0.0);
      iVar156 = -(uint)(fVar199 == 0.0);
      iVar157 = -(uint)(fVar78 == 0.0);
      auVar136 = NEON_frsqrts(auVar135,auVar174,4);
      fVar121 = fVar121 * auVar135._0_4_ * auVar136._0_4_;
      fVar125 = fVar125 * auVar135._4_4_ * auVar136._4_4_;
      fVar77 = fVar77 * auVar135._8_4_ * auVar136._8_4_;
      fVar124 = fVar124 * auVar135._12_4_ * auVar136._12_4_;
      puVar41[9] = CONCAT17((byte)((uint)fVar124 >> 0x18) & ~(byte)((uint)iVar157 >> 0x18),
                            CONCAT16((byte)((uint)fVar124 >> 0x10) & ~(byte)((uint)iVar157 >> 0x10),
                                     CONCAT15((byte)((uint)fVar124 >> 8) &
                                              ~(byte)((uint)iVar157 >> 8),
                                              CONCAT14(SUB41(fVar124,0) & ~(byte)iVar157,
                                                       CONCAT13((byte)((uint)fVar77 >> 0x18) &
                                                                ~(byte)((uint)iVar156 >> 0x18),
                                                                CONCAT12((byte)((uint)fVar77 >> 0x10
                                                                               ) & ~(byte)((uint)
                                                  iVar156 >> 0x10),
                                                  CONCAT11((byte)((uint)fVar77 >> 8) &
                                                           ~(byte)((uint)iVar156 >> 8),
                                                           SUB41(fVar77,0) & ~(byte)iVar156)))))));
      puVar41[8] = CONCAT17((byte)((uint)fVar125 >> 0x18) & ~(byte)((uint)iVar155 >> 0x18),
                            CONCAT16((byte)((uint)fVar125 >> 0x10) & ~(byte)((uint)iVar155 >> 0x10),
                                     CONCAT15((byte)((uint)fVar125 >> 8) &
                                              ~(byte)((uint)iVar155 >> 8),
                                              CONCAT14(SUB41(fVar125,0) & ~(byte)iVar155,
                                                       CONCAT13((byte)((uint)fVar121 >> 0x18) &
                                                                ~(byte)((uint)iVar128 >> 0x18),
                                                                CONCAT12((byte)((uint)fVar121 >>
                                                                               0x10) &
                                                                         ~(byte)((uint)iVar128 >>
                                                                                0x10),
                                                                         CONCAT11((byte)((uint)
                                                  fVar121 >> 8) & ~(byte)((uint)iVar128 >> 8),
                                                  SUB41(fVar121,0) & ~(byte)iVar128)))))));
      if (iVar127 == 1) {
        lVar35 = puVar41[10];
        *(undefined8 *)(lVar35 + 0x48) = puVar41[9];
        *(undefined8 *)(lVar35 + 0x40) = *puVar42;
      }
    }
    iVar127 = *(int *)(param_2 + 0x80);
    if (1 < iVar127) {
      fVar121 = fVar76 * fVar79;
      fVar125 = *(float *)(param_3 + 0x2c);
      fVar124 = *(float *)(param_3 + 0x30);
      iVar128 = 1;
      pfVar39 = *(float **)(*(long *)(param_2 + 0x68) + 0x50);
      fVar77 = *(float *)(param_3 + 0x34);
      do {
        pfVar39 = *(float **)(pfVar39 + 0x14);
        iVar128 = iVar128 + 1;
        fVar199 = fVar121 * fVar125 + (float)*(undefined8 *)(pfVar39 + 4) * fVar79;
        fVar78 = fVar121 * fVar124 + (float)((ulong)*(undefined8 *)(pfVar39 + 4) >> 0x20) * fVar79;
        fVar120 = fVar121 * fVar77 + (float)*(undefined8 *)(pfVar39 + 6) * fVar79;
        fVar122 = (float)((ulong)*(undefined8 *)(pfVar39 + 6) >> 0x20) * fVar79 + 0.0;
        pfVar39[4] = pfVar39[2] + fVar120 * fVar76;
        pfVar39[5] = pfVar39[3] + fVar122 * fVar76;
        *pfVar39 = *pfVar39 + fVar199 * fVar76;
        pfVar39[1] = pfVar39[1] + fVar78 * fVar76;
        *(ulong *)(pfVar39 + 6) =
             CONCAT17((char)((uint)fVar122 >> 0x18),
                      CONCAT16((char)((uint)fVar122 >> 0x10),
                               CONCAT15((char)((uint)fVar122 >> 8),
                                        CONCAT14(SUB41(fVar122,0),fVar120))));
        *(ulong *)(pfVar39 + 4) =
             CONCAT17((char)((uint)fVar78 >> 0x18),
                      CONCAT16((char)((uint)fVar78 >> 0x10),
                               CONCAT15((char)((uint)fVar78 >> 8),CONCAT14(SUB41(fVar78,0),fVar199))
                              ));
        iVar127 = *(int *)(param_2 + 0x80);
      } while (iVar128 < iVar127);
    }
  }
  else {
    pfVar40 = *(float **)(param_2 + 0x68);
    bVar45 = *param_3;
    pfVar39 = pfVar40 + 0x14;
    pfVar43 = *(float **)pfVar39;
    *(undefined8 *)(param_2 + 0x68) = *(undefined8 *)(pfVar40 + 0x16);
    if (bVar45 == 3) {
      if ((float)*(int *)(param_2 + 0x80) < *(float *)(param_3 + 0xc) + -1.0) {
        *(int *)(param_2 + 0x80) = *(int *)(param_2 + 0x80) + 1;
      }
      if (param_3[1] == 0) {
        FUN_71005e3d7c(param_1,(undefined8 *)pfVar40);
      }
      else {
        FUN_71005e3d54(param_1,(undefined8 *)pfVar40);
      }
      *(undefined8 *)(param_2 + 0x58) = *(undefined8 *)(pfVar40 + 2);
      *(undefined8 *)(param_2 + 0x50) = *(undefined8 *)pfVar40;
      if (1 < *(int *)(param_2 + 0x80)) {
        fVar77 = fVar76 * fVar79;
        fVar125 = *(float *)(param_3 + 0x2c);
        fVar124 = *(float *)(param_3 + 0x30);
        fVar199 = *(float *)(param_3 + 0x34);
        iVar127 = 1;
        do {
          pfVar36 = *(float **)pfVar39;
          iVar127 = iVar127 + 1;
          pfVar39 = pfVar36 + 0x14;
          fVar78 = fVar77 * fVar125 + pfVar36[4] * fVar79;
          fVar120 = fVar77 * fVar124 + pfVar36[5] * fVar79;
          fVar122 = fVar77 * fVar199 + pfVar36[6] * fVar79;
          fVar123 = pfVar36[7] * fVar79 + 0.0;
          pfVar36[4] = pfVar36[2] + fVar122 * fVar76;
          pfVar36[5] = pfVar36[3] + fVar123 * fVar76;
          *pfVar36 = *pfVar36 + fVar78 * fVar76;
          pfVar36[1] = pfVar36[1] + fVar120 * fVar76;
          pfVar36[8] = fVar122;
          pfVar36[9] = fVar123;
          pfVar36[4] = fVar78;
          pfVar36[5] = fVar120;
        } while (iVar127 < *(int *)(param_2 + 0x80));
      }
      FUN_71005e4220(param_1,&local_70);
      lVar3 = DAT_7103a66ef0;
      fVar125 = *(float *)(param_3 + 0x38);
      fVar79 = *(float *)(param_3 + 0x3c);
      fVar76 = *(float *)(param_2 + 0x90);
      fVar77 = *(float *)(param_3 + 0x48);
      fVar124 = (float)NEON_ucvtf(*DAT_7103a66ee8);
      fVar124 = fVar124 / *DAT_7103a67640;
      uVar34 = (ulong)(fVar124 *
                      ((float)local_70 * 360.0 + *(float *)(param_3 + 0x40) * fVar125 * fVar76));
      lVar35 = DAT_7103a66ef0 + (uVar34 >> 0x18 & 0xff) * 0x10;
      uVar37 = (ulong)(fVar124 * (local_70._4_4_ * 360.0 + fVar76 * 0.5));
      lVar2 = DAT_7103a66ef0 + (uVar37 >> 0x18 & 0xff) * 0x10;
      uVar38 = (ulong)(fVar124 *
                      (local_70._4_4_ * 360.0 + fVar125 * *(float *)(param_3 + 0x44) * fVar76));
      pfVar40[4] = *(float *)(lVar35 + 4) +
                   (float)((uint)uVar34 & 0xffffff) * 5.9604645e-08 * *(float *)(lVar35 + 0xc) +
                   *(float *)(lVar2 + 4) +
                   (float)((uint)uVar37 & 0xffffff) * 5.9604645e-08 * *(float *)(lVar2 + 0xc);
      lVar35 = lVar3 + (uVar38 >> 0x18 & 0xff) * 0x10;
      uVar34 = (ulong)(fVar124 * ((float)uStack_68 * 360.0 + fVar76 * 0.5));
      lVar2 = lVar3 + (uVar34 >> 0x18 & 0xff) * 0x10;
      pfVar40[5] = *(float *)(lVar35 + 4) +
                   (float)((uint)uVar38 & 0xffffff) * 5.9604645e-08 * *(float *)(lVar35 + 0xc) +
                   *(float *)(lVar2 + 4) +
                   (float)((uint)uVar34 & 0xffffff) * 5.9604645e-08 * *(float *)(lVar2 + 0xc);
      uVar34 = (ulong)(fVar124 * ((float)uStack_68 * 360.0 + fVar125 * fVar77 * fVar76));
      lVar35 = lVar3 + (uVar34 >> 0x18 & 0xff) * 0x10;
      uVar37 = (ulong)(fVar124 * (uStack_68._4_4_ * 360.0 + fVar76 * 0.5));
      lVar3 = lVar3 + (uVar37 >> 0x18 & 0xff) * 0x10;
      fVar76 = pfVar40[5] * fVar79;
      fVar125 = fVar79 * 0.0;
      *(ulong *)(pfVar40 + 6) =
           CONCAT17((char)((uint)fVar125 >> 0x18),
                    CONCAT16((char)((uint)fVar125 >> 0x10),
                             CONCAT15((char)((uint)fVar125 >> 8),
                                      CONCAT14(SUB41(fVar125,0),
                                               (*(float *)(lVar35 + 4) +
                                                (float)((uint)uVar34 & 0xffffff) * 5.9604645e-08 *
                                                *(float *)(lVar35 + 0xc) +
                                               *(float *)(lVar3 + 4) +
                                               (float)((uint)uVar37 & 0xffffff) * 5.9604645e-08 *
                                               *(float *)(lVar3 + 0xc)) * fVar79))));
      *(ulong *)(pfVar40 + 4) =
           CONCAT17((char)((uint)fVar76 >> 0x18),
                    CONCAT16((char)((uint)fVar76 >> 0x10),
                             CONCAT15((char)((uint)fVar76 >> 8),
                                      CONCAT14(SUB41(fVar76,0),pfVar40[4] * fVar79))));
      if (param_3[1] == 0) {
        uVar34 = *(ulong *)(*(long *)(param_1 + 0x10) + 0x118);
        *(undefined8 *)(pfVar40 + 0x10) = *(undefined8 *)(*(long *)(param_1 + 0x10) + 0x110);
        *(ulong *)(pfVar40 + 0x12) = uVar34 & 0xffffffff;
        *(undefined8 *)(pfVar40 + 0x10) = *(undefined8 *)(pfVar40 + 0x10);
      }
      else {
        *(undefined8 *)(pfVar40 + 0x12) = puVar42[1];
        *(undefined8 *)(pfVar40 + 0x10) = *puVar42;
      }
      FUN_71005e4078(param_1,(float *)&local_70);
      pfVar40[0x18] = (float)local_70;
      if (*(int *)(param_2 + 0x80) == 1) {
        if (param_3[1] == 0) {
          FUN_71005e3efc(param_1,(undefined8 *)(pfVar40 + 8));
        }
        else {
          FUN_71005e3ed4(param_1,(undefined8 *)(pfVar40 + 8));
        }
        fVar79 = (float)FUN_71005e3d44(param_1);
        fVar121 = (float)*(undefined8 *)(pfVar40 + 8) + fVar79 * *(float *)(param_3 + 0x2c);
        fVar76 = (float)((ulong)*(undefined8 *)(pfVar40 + 8) >> 0x20) +
                 fVar79 * *(float *)(param_3 + 0x30);
        fVar79 = (float)*(undefined8 *)(pfVar40 + 10) + fVar79 * *(float *)(param_3 + 0x34);
        fVar125 = (float)((ulong)*(undefined8 *)(pfVar40 + 10) >> 0x20) + 0.0;
        auVar93._0_4_ = fVar121 * fVar121;
        auVar93._4_4_ = fVar76 * fVar76;
        auVar93._8_4_ = fVar79 * fVar79;
        auVar93._12_4_ = fVar125 * fVar125;
        auVar136 = NEON_ext(auVar93,auVar93,8,1);
        *(ulong *)(pfVar40 + 10) =
             CONCAT17((char)((uint)fVar125 >> 0x18),
                      CONCAT16((char)((uint)fVar125 >> 0x10),
                               CONCAT15((char)((uint)fVar125 >> 8),CONCAT14(SUB41(fVar125,0),fVar79)
                                       )));
        *(ulong *)(pfVar40 + 8) =
             CONCAT17((char)((uint)fVar76 >> 0x18),
                      CONCAT16((char)((uint)fVar76 >> 0x10),
                               CONCAT15((char)((uint)fVar76 >> 8),CONCAT14(SUB41(fVar76,0),fVar121))
                              ));
        fVar124 = auVar136._0_4_ + auVar93._0_4_;
        fVar199 = auVar136._4_4_ + auVar93._4_4_;
        fVar77 = fVar124 + fVar199;
        fVar124 = fVar124 + fVar199;
        if (1e-05 <= fVar77) {
          auVar94._8_8_ = CONCAT44(fVar124,fVar77);
          auVar94._0_8_ = CONCAT44(fVar124,fVar77);
          auVar136 = NEON_frsqrte(auVar94,4);
          auVar175._0_4_ = fVar77 * auVar136._0_4_;
          auVar175._4_4_ = fVar124 * auVar136._4_4_;
          auVar175._8_4_ = fVar77 * auVar136._8_4_;
          auVar175._12_4_ = fVar124 * auVar136._12_4_;
          auVar214 = NEON_frsqrts(auVar136,auVar175,4);
          auVar137._0_4_ = auVar136._0_4_ * auVar214._0_4_;
          auVar137._4_4_ = auVar136._4_4_ * auVar214._4_4_;
          auVar137._8_4_ = auVar136._8_4_ * auVar214._8_4_;
          auVar137._12_4_ = auVar136._12_4_ * auVar214._12_4_;
          auVar176._0_4_ = fVar77 * auVar137._0_4_;
          auVar176._4_4_ = fVar124 * auVar137._4_4_;
          auVar176._8_4_ = fVar77 * auVar137._8_4_;
          auVar176._12_4_ = fVar124 * auVar137._12_4_;
          iVar127 = -(uint)(fVar77 == 0.0);
          iVar128 = -(uint)(fVar124 == 0.0);
          iVar155 = -(uint)(fVar77 == 0.0);
          iVar156 = -(uint)(fVar124 == 0.0);
          auVar136 = NEON_frsqrts(auVar137,auVar176,4);
          fVar121 = fVar121 * auVar137._0_4_ * auVar136._0_4_;
          fVar76 = fVar76 * auVar137._4_4_ * auVar136._4_4_;
          fVar79 = fVar79 * auVar137._8_4_ * auVar136._8_4_;
          fVar125 = fVar125 * auVar137._12_4_ * auVar136._12_4_;
          fVar121 = (float)CONCAT13((byte)((uint)fVar121 >> 0x18) & ~(byte)((uint)iVar127 >> 0x18),
                                    CONCAT12((byte)((uint)fVar121 >> 0x10) &
                                             ~(byte)((uint)iVar127 >> 0x10),
                                             CONCAT11((byte)((uint)fVar121 >> 8) &
                                                      ~(byte)((uint)iVar127 >> 8),
                                                      SUB41(fVar121,0) & ~(byte)iVar127)));
          auVar82._0_8_ =
               CONCAT17((byte)((uint)fVar76 >> 0x18) & ~(byte)((uint)iVar128 >> 0x18),
                        CONCAT16((byte)((uint)fVar76 >> 0x10) & ~(byte)((uint)iVar128 >> 0x10),
                                 CONCAT15((byte)((uint)fVar76 >> 8) & ~(byte)((uint)iVar128 >> 8),
                                          CONCAT14(SUB41(fVar76,0) & ~(byte)iVar128,fVar121))));
          auVar82[8] = SUB41(fVar79,0) & ~(byte)iVar155;
          auVar82[9] = (byte)((uint)fVar79 >> 8) & ~(byte)((uint)iVar155 >> 8);
          auVar82[10] = (byte)((uint)fVar79 >> 0x10) & ~(byte)((uint)iVar155 >> 0x10);
          auVar82[0xb] = (byte)((uint)fVar79 >> 0x18) & ~(byte)((uint)iVar155 >> 0x18);
          auVar95[0xc] = SUB41(fVar125,0) & ~(byte)iVar156;
          auVar95._0_12_ = auVar82;
          auVar95[0xd] = (byte)((uint)fVar125 >> 8) & ~(byte)((uint)iVar156 >> 8);
          auVar95[0xe] = (byte)((uint)fVar125 >> 0x10) & ~(byte)((uint)iVar156 >> 0x10);
          auVar95[0xf] = (byte)((uint)fVar125 >> 0x18) & ~(byte)((uint)iVar156 >> 0x18);
          auVar138._0_4_ = fVar121 * 0.0;
          auVar138._4_4_ = (float)((ulong)auVar82._0_8_ >> 0x20) * 1.0;
          auVar138._8_4_ = auVar82._8_4_ * 0.0;
          auVar138._12_4_ = auVar95._12_4_ * 0.0;
          auVar136 = NEON_ext(auVar138,auVar138,8,1);
          fVar79 = auVar136._0_4_ + auVar138._0_4_ + auVar136._4_4_ + auVar138._4_4_;
          if (1e-05 <= ABS(ABS(fVar79) + -1.0)) {
            uVar163 = a64_TBL(ZEXT816(0),auVar95,0xb0a090807060504);
            uVar207 = a64_TBL(ZEXT816(0),auVar95,0xf0e0d0c03020100);
            auVar8._9_7_ = 0;
            auVar8._0_9_ = _DAT_7102ec03b0;
            uVar226 = a64_TBL(ZEXT816(0),auVar8,0x30201000b0a0908);
            auVar9._9_7_ = 0;
            auVar9._0_9_ = _DAT_7102ec03b0;
            uVar231 = a64_TBL(ZEXT816(0),auVar9,0xf0e0d0c07060504);
            uVar208 = a64_TBL(ZEXT816(0),auVar95,0x30201000b0a0908);
            uVar80 = a64_TBL(ZEXT816(0),auVar95,0xf0e0d0c07060504);
            auVar10._9_7_ = 0;
            auVar10._0_9_ = _DAT_7102ec03b0;
            uVar81 = a64_TBL(ZEXT816(0),auVar10,0xb0a090807060504);
            auVar11._9_7_ = 0;
            auVar11._0_9_ = _DAT_7102ec03b0;
            uVar162 = a64_TBL(ZEXT816(0),auVar11,0xf0e0d0c03020100);
            fVar77 = (float)uVar163 * (float)uVar226 - (float)uVar81 * (float)uVar208;
            fVar124 = (float)((ulong)uVar163 >> 0x20) * (float)((ulong)uVar226 >> 0x20) -
                      (float)((ulong)uVar81 >> 0x20) * (float)((ulong)uVar208 >> 0x20);
            fVar199 = (float)uVar207 * (float)uVar231 - (float)uVar162 * (float)uVar80;
            fVar78 = (float)((ulong)uVar207 >> 0x20) * (float)((ulong)uVar231 >> 0x20) -
                     (float)((ulong)uVar162 >> 0x20) * (float)((ulong)uVar80 >> 0x20);
            fVar79 = fVar77 * fVar77;
            fVar121 = fVar124 * fVar124;
            uVar44 = (undefined1)((uint)fVar121 >> 8);
            uVar46 = (undefined1)((uint)fVar121 >> 0x10);
            uVar48 = (undefined1)((uint)fVar121 >> 0x18);
            fVar76 = fVar199 * fVar199;
            uVar50 = (undefined1)((uint)fVar76 >> 8);
            uVar52 = (undefined1)((uint)fVar76 >> 0x10);
            uVar54 = (undefined1)((uint)fVar76 >> 0x18);
            fVar125 = fVar78 * fVar78;
            uVar56 = (undefined1)((uint)fVar125 >> 8);
            uVar58 = (undefined1)((uint)fVar125 >> 0x10);
            uVar60 = (undefined1)((uint)fVar125 >> 0x18);
            auVar12[4] = SUB41(fVar121,0);
            auVar12._0_4_ = fVar79;
            auVar12[5] = uVar44;
            auVar12[6] = uVar46;
            auVar12[7] = uVar48;
            auVar12[8] = SUB41(fVar76,0);
            auVar12[9] = uVar50;
            auVar12[10] = uVar52;
            auVar12[0xb] = uVar54;
            auVar12[0xc] = SUB41(fVar125,0);
            auVar12[0xd] = uVar56;
            auVar12[0xe] = uVar58;
            auVar12[0xf] = uVar60;
            auVar13[4] = SUB41(fVar121,0);
            auVar13._0_4_ = fVar79;
            auVar13[5] = uVar44;
            auVar13[6] = uVar46;
            auVar13[7] = uVar48;
            auVar13[8] = SUB41(fVar76,0);
            auVar13[9] = uVar50;
            auVar13[10] = uVar52;
            auVar13[0xb] = uVar54;
            auVar13[0xc] = SUB41(fVar125,0);
            auVar13[0xd] = uVar56;
            auVar13[0xe] = uVar58;
            auVar13[0xf] = uVar60;
            auVar136 = NEON_ext(auVar12,auVar13,8,1);
            fVar79 = auVar136._0_4_ + fVar79;
            fVar121 = auVar136._4_4_ + fVar121;
            fVar76 = fVar79 + fVar121;
            fVar79 = fVar79 + fVar121;
            uVar44 = SUB41(fVar79,0);
            uVar46 = (undefined1)((uint)fVar79 >> 8);
            uVar48 = (undefined1)((uint)fVar79 >> 0x10);
            uVar50 = (undefined1)((uint)fVar79 >> 0x18);
            auVar14[4] = uVar44;
            auVar14._0_4_ = fVar76;
            auVar14[5] = uVar46;
            auVar14[6] = uVar48;
            auVar14[7] = uVar50;
            auVar14[8] = SUB41(fVar76,0);
            auVar14[9] = (char)((uint)fVar76 >> 8);
            auVar14[10] = (char)((uint)fVar76 >> 0x10);
            auVar14[0xb] = (char)((uint)fVar76 >> 0x18);
            auVar14[0xc] = uVar44;
            auVar14[0xd] = uVar46;
            auVar14[0xe] = uVar48;
            auVar14[0xf] = uVar50;
            auVar136 = NEON_frsqrte(auVar14,4);
            auVar143._0_4_ = auVar136._0_4_ * fVar76;
            auVar143._4_4_ = auVar136._4_4_ * fVar79;
            auVar143._8_4_ = auVar136._8_4_ * fVar76;
            uVar30 = (undefined2)(CONCAT15(uVar46,CONCAT14(uVar44,fVar76)) >> 0x20);
            auVar143._12_4_ = auVar136._12_4_ * (float)CONCAT13(uVar50,CONCAT12(uVar48,uVar30));
            auVar214 = NEON_frsqrts(auVar136,auVar143,4);
            auVar102._0_4_ = auVar136._0_4_ * auVar214._0_4_;
            auVar102._4_4_ = auVar136._4_4_ * auVar214._4_4_;
            auVar102._8_4_ = auVar136._8_4_ * auVar214._8_4_;
            auVar102._12_4_ = auVar136._12_4_ * auVar214._12_4_;
            auVar144._0_4_ = fVar76 * auVar102._0_4_;
            auVar144._4_4_ = fVar79 * auVar102._4_4_;
            auVar144._8_4_ = fVar76 * auVar102._8_4_;
            auVar144._12_4_ = (float)CONCAT13(uVar50,CONCAT12(uVar48,uVar30)) * auVar102._12_4_;
            iVar127 = -(uint)(fVar76 == 0.0);
            iVar128 = -(uint)(fVar79 == 0.0);
            iVar155 = -(uint)(fVar76 == 0.0);
            iVar156 = -(uint)((float)CONCAT13(uVar50,CONCAT12(uVar48,uVar30)) == 0.0);
            auVar136 = NEON_frsqrts(auVar102,auVar144,4);
            fVar77 = fVar77 * auVar102._0_4_ * auVar136._0_4_;
            fVar124 = fVar124 * auVar102._4_4_ * auVar136._4_4_;
            fVar199 = fVar199 * auVar102._8_4_ * auVar136._8_4_;
            fVar78 = fVar78 * auVar102._12_4_ * auVar136._12_4_;
            *(ulong *)(pfVar40 + 0xe) =
                 CONCAT17((byte)((uint)fVar78 >> 0x18) & ~(byte)((uint)iVar156 >> 0x18),
                          CONCAT16((byte)((uint)fVar78 >> 0x10) & ~(byte)((uint)iVar156 >> 0x10),
                                   CONCAT15((byte)((uint)fVar78 >> 8) & ~(byte)((uint)iVar156 >> 8),
                                            CONCAT14(SUB41(fVar78,0) & ~(byte)iVar156,
                                                     CONCAT13((byte)((uint)fVar199 >> 0x18) &
                                                              ~(byte)((uint)iVar155 >> 0x18),
                                                              CONCAT12((byte)((uint)fVar199 >> 0x10)
                                                                       & ~(byte)((uint)iVar155 >>
                                                                                0x10),
                                                                       CONCAT11((byte)((uint)fVar199
                                                                                      >> 8) &
                                                                                ~(byte)((uint)
                                                  iVar155 >> 8),SUB41(fVar199,0) & ~(byte)iVar155)))
                                                  ))));
            *(ulong *)(pfVar40 + 0xc) =
                 CONCAT17((byte)((uint)fVar124 >> 0x18) & ~(byte)((uint)iVar128 >> 0x18),
                          CONCAT16((byte)((uint)fVar124 >> 0x10) & ~(byte)((uint)iVar128 >> 0x10),
                                   CONCAT15((byte)((uint)fVar124 >> 8) & ~(byte)((uint)iVar128 >> 8)
                                            ,CONCAT14(SUB41(fVar124,0) & ~(byte)iVar128,
                                                      CONCAT13((byte)((uint)fVar77 >> 0x18) &
                                                               ~(byte)((uint)iVar127 >> 0x18),
                                                               CONCAT12((byte)((uint)fVar77 >> 0x10)
                                                                        & ~(byte)((uint)iVar127 >>
                                                                                 0x10),
                                                                        CONCAT11((byte)((uint)fVar77
                                                                                       >> 8) &
                                                                                 ~(byte)((uint)
                                                  iVar127 >> 8),SUB41(fVar77,0) & ~(byte)iVar127))))
                                           )));
          }
          else {
            fVar121 = fVar79 * 1.0;
            fVar76 = fVar79 * 0.0;
            fVar125 = fVar79 * 0.0;
            fVar79 = fVar79 * 0.0;
            auVar96._0_4_ = fVar121 * fVar121;
            auVar96._4_4_ = fVar76 * fVar76;
            auVar96._8_4_ = fVar125 * fVar125;
            auVar96._12_4_ = fVar79 * fVar79;
            auVar136 = NEON_ext(auVar96,auVar96,8,1);
            fVar124 = auVar136._0_4_ + auVar96._0_4_;
            fVar199 = auVar136._4_4_ + auVar96._4_4_;
            fVar77 = fVar124 + fVar199;
            fVar124 = fVar124 + fVar199;
            auVar97._8_8_ = CONCAT44(fVar124,fVar77);
            auVar97._0_8_ = CONCAT44(fVar124,fVar77);
            auVar136 = NEON_frsqrte(auVar97,4);
            auVar177._0_4_ = auVar136._0_4_ * fVar77;
            auVar177._4_4_ = auVar136._4_4_ * fVar124;
            auVar177._8_4_ = auVar136._8_4_ * fVar77;
            auVar177._12_4_ = auVar136._12_4_ * fVar124;
            auVar214 = NEON_frsqrts(auVar136,auVar177,4);
            auVar139._0_4_ = auVar136._0_4_ * auVar214._0_4_;
            auVar139._4_4_ = auVar136._4_4_ * auVar214._4_4_;
            auVar139._8_4_ = auVar136._8_4_ * auVar214._8_4_;
            auVar139._12_4_ = auVar136._12_4_ * auVar214._12_4_;
            auVar178._0_4_ = fVar77 * auVar139._0_4_;
            auVar178._4_4_ = fVar124 * auVar139._4_4_;
            auVar178._8_4_ = fVar77 * auVar139._8_4_;
            auVar178._12_4_ = fVar124 * auVar139._12_4_;
            iVar127 = -(uint)(fVar77 == 0.0);
            iVar128 = -(uint)(fVar124 == 0.0);
            iVar155 = -(uint)(fVar77 == 0.0);
            iVar156 = -(uint)(fVar124 == 0.0);
            auVar136 = NEON_frsqrts(auVar139,auVar178,4);
            fVar121 = fVar121 * auVar139._0_4_ * auVar136._0_4_;
            fVar76 = fVar76 * auVar139._4_4_ * auVar136._4_4_;
            fVar125 = fVar125 * auVar139._8_4_ * auVar136._8_4_;
            fVar79 = fVar79 * auVar139._12_4_ * auVar136._12_4_;
            *(ulong *)(pfVar40 + 0xe) =
                 CONCAT17((byte)((uint)fVar79 >> 0x18) & ~(byte)((uint)iVar156 >> 0x18),
                          CONCAT16((byte)((uint)fVar79 >> 0x10) & ~(byte)((uint)iVar156 >> 0x10),
                                   CONCAT15((byte)((uint)fVar79 >> 8) & ~(byte)((uint)iVar156 >> 8),
                                            CONCAT14(SUB41(fVar79,0) & ~(byte)iVar156,
                                                     CONCAT13((byte)((uint)fVar125 >> 0x18) &
                                                              ~(byte)((uint)iVar155 >> 0x18),
                                                              CONCAT12((byte)((uint)fVar125 >> 0x10)
                                                                       & ~(byte)((uint)iVar155 >>
                                                                                0x10),
                                                                       CONCAT11((byte)((uint)fVar125
                                                                                      >> 8) &
                                                                                ~(byte)((uint)
                                                  iVar155 >> 8),SUB41(fVar125,0) & ~(byte)iVar155)))
                                                  ))));
            *(ulong *)(pfVar40 + 0xc) =
                 CONCAT17((byte)((uint)fVar76 >> 0x18) & ~(byte)((uint)iVar128 >> 0x18),
                          CONCAT16((byte)((uint)fVar76 >> 0x10) & ~(byte)((uint)iVar128 >> 0x10),
                                   CONCAT15((byte)((uint)fVar76 >> 8) & ~(byte)((uint)iVar128 >> 8),
                                            CONCAT14(SUB41(fVar76,0) & ~(byte)iVar128,
                                                     CONCAT13((byte)((uint)fVar121 >> 0x18) &
                                                              ~(byte)((uint)iVar127 >> 0x18),
                                                              CONCAT12((byte)((uint)fVar121 >> 0x10)
                                                                       & ~(byte)((uint)iVar127 >>
                                                                                0x10),
                                                                       CONCAT11((byte)((uint)fVar121
                                                                                      >> 8) &
                                                                                ~(byte)((uint)
                                                  iVar127 >> 8),SUB41(fVar121,0) & ~(byte)iVar127)))
                                                  ))));
          }
        }
        else {
          pfVar40[10] = 0.0;
          pfVar40[0xb] = 0.0;
          pfVar40[8] = 0.0;
          pfVar40[9] = 1.0;
          pfVar40[0xe] = 0.0;
          pfVar40[0xf] = 0.0;
          pfVar40[0xc] = 1.0;
          pfVar40[0xd] = 0.0;
        }
      }
      else {
        puVar42 = *(undefined8 **)(pfVar40 + 0x14);
        fVar79 = *pfVar40 - (float)*puVar42;
        fVar76 = pfVar40[1] - (float)((ulong)*puVar42 >> 0x20);
        fVar125 = pfVar40[2] - (float)puVar42[1];
        fVar77 = pfVar40[3] - (float)((ulong)puVar42[1] >> 0x20);
        auVar84._0_4_ = fVar79 * fVar79;
        auVar84._4_4_ = fVar76 * fVar76;
        auVar84._8_4_ = fVar125 * fVar125;
        auVar84._12_4_ = fVar77 * fVar77;
        auVar136 = NEON_ext(auVar84,auVar84,8,1);
        pfVar39 = pfVar40 + 8;
        *(ulong *)(pfVar40 + 10) =
             CONCAT17((char)((uint)fVar77 >> 0x18),
                      CONCAT16((char)((uint)fVar77 >> 0x10),
                               CONCAT15((char)((uint)fVar77 >> 8),CONCAT14(SUB41(fVar77,0),fVar125))
                              ));
        *(ulong *)pfVar39 =
             CONCAT17((char)((uint)fVar76 >> 0x18),
                      CONCAT16((char)((uint)fVar76 >> 0x10),
                               CONCAT15((char)((uint)fVar76 >> 8),CONCAT14(SUB41(fVar76,0),fVar79)))
                     );
        fVar199 = auVar136._0_4_ + auVar84._0_4_;
        fVar78 = auVar136._4_4_ + auVar84._4_4_;
        fVar124 = fVar199 + fVar78;
        fVar199 = fVar199 + fVar78;
        if (1e-05 <= fVar124) {
          auVar86._8_8_ = CONCAT44(fVar199,fVar124);
          auVar86._0_8_ = CONCAT44(fVar199,fVar124);
          auVar136 = NEON_frsqrte(auVar86,4);
          auVar164._0_4_ = fVar124 * auVar136._0_4_;
          auVar164._4_4_ = fVar199 * auVar136._4_4_;
          auVar164._8_4_ = fVar124 * auVar136._8_4_;
          auVar164._12_4_ = fVar199 * auVar136._12_4_;
          auVar214 = NEON_frsqrts(auVar136,auVar164,4);
          auVar129._0_4_ = auVar136._0_4_ * auVar214._0_4_;
          auVar129._4_4_ = auVar136._4_4_ * auVar214._4_4_;
          auVar129._8_4_ = auVar136._8_4_ * auVar214._8_4_;
          auVar129._12_4_ = auVar136._12_4_ * auVar214._12_4_;
          auVar165._0_4_ = fVar124 * auVar129._0_4_;
          auVar165._4_4_ = fVar199 * auVar129._4_4_;
          auVar165._8_4_ = fVar124 * auVar129._8_4_;
          auVar165._12_4_ = fVar199 * auVar129._12_4_;
          iVar127 = -(uint)(fVar124 == 0.0);
          iVar128 = -(uint)(fVar199 == 0.0);
          iVar155 = -(uint)(fVar124 == 0.0);
          iVar156 = -(uint)(fVar199 == 0.0);
          auVar136 = NEON_frsqrts(auVar129,auVar165,4);
          fVar79 = fVar79 * auVar129._0_4_ * auVar136._0_4_;
          fVar76 = fVar76 * auVar129._4_4_ * auVar136._4_4_;
          fVar125 = fVar125 * auVar129._8_4_ * auVar136._8_4_;
          fVar77 = fVar77 * auVar129._12_4_ * auVar136._12_4_;
          bVar45 = SUB41(fVar79,0) & ~(byte)iVar127;
          bVar47 = (byte)((uint)fVar79 >> 8) & ~(byte)((uint)iVar127 >> 8);
          bVar49 = (byte)((uint)fVar79 >> 0x10) & ~(byte)((uint)iVar127 >> 0x10);
          bVar51 = (byte)((uint)fVar79 >> 0x18) & ~(byte)((uint)iVar127 >> 0x18);
          bVar53 = SUB41(fVar76,0) & ~(byte)iVar128;
          bVar55 = (byte)((uint)fVar76 >> 8) & ~(byte)((uint)iVar128 >> 8);
          bVar57 = (byte)((uint)fVar76 >> 0x10) & ~(byte)((uint)iVar128 >> 0x10);
          bVar59 = (byte)((uint)fVar76 >> 0x18) & ~(byte)((uint)iVar128 >> 0x18);
          bVar61 = SUB41(fVar125,0) & ~(byte)iVar155;
          bVar63 = (byte)((uint)fVar125 >> 8) & ~(byte)((uint)iVar155 >> 8);
          bVar65 = (byte)((uint)fVar125 >> 0x10) & ~(byte)((uint)iVar155 >> 0x10);
          bVar67 = (byte)((uint)fVar125 >> 0x18) & ~(byte)((uint)iVar155 >> 0x18);
          bVar69 = SUB41(fVar77,0) & ~(byte)iVar156;
          bVar71 = (byte)((uint)fVar77 >> 8) & ~(byte)((uint)iVar156 >> 8);
          bVar73 = (byte)((uint)fVar77 >> 0x10) & ~(byte)((uint)iVar156 >> 0x10);
          bVar75 = (byte)((uint)fVar77 >> 0x18) & ~(byte)((uint)iVar156 >> 0x18);
          fVar79 = *(float *)(puVar42 + 4);
          fVar76 = *(float *)((long)puVar42 + 0x24);
          fVar125 = *(float *)(puVar42 + 5);
          fVar77 = *(float *)((long)puVar42 + 0x2c);
          fVar124 = *(float *)(puVar42 + 6);
          fVar199 = *(float *)((long)puVar42 + 0x34);
          fVar78 = *(float *)(puVar42 + 7);
          fVar120 = *(float *)((long)puVar42 + 0x3c);
          auVar200._0_4_ = fVar79 * fVar79;
          auVar200._4_4_ = fVar76 * fVar76;
          auVar200._8_4_ = fVar125 * fVar125;
          auVar200._12_4_ = fVar77 * fVar77;
          auVar136 = NEON_ext(auVar200,auVar200,8,1);
          fVar123 = auVar136._0_4_ + auVar200._0_4_;
          fVar161 = auVar136._4_4_ + auVar200._4_4_;
          fVar122 = fVar123 + fVar161;
          fVar123 = fVar123 + fVar161;
          auVar201._8_8_ = CONCAT44(fVar123,fVar122);
          auVar201._0_8_ = CONCAT44(fVar123,fVar122);
          auVar136 = NEON_frsqrte(auVar201,4);
          auVar218._0_4_ = auVar136._0_4_ * fVar122;
          auVar218._4_4_ = auVar136._4_4_ * fVar123;
          auVar218._8_4_ = auVar136._8_4_ * fVar122;
          auVar218._12_4_ = auVar136._12_4_ * fVar123;
          auVar214 = NEON_frsqrts(auVar136,auVar218,4);
          auVar209._0_4_ = auVar136._0_4_ * auVar214._0_4_;
          auVar209._4_4_ = auVar136._4_4_ * auVar214._4_4_;
          auVar209._8_4_ = auVar136._8_4_ * auVar214._8_4_;
          auVar209._12_4_ = auVar136._12_4_ * auVar214._12_4_;
          auVar219._0_4_ = fVar122 * auVar209._0_4_;
          auVar219._4_4_ = fVar123 * auVar209._4_4_;
          auVar219._8_4_ = fVar122 * auVar209._8_4_;
          auVar219._12_4_ = fVar123 * auVar209._12_4_;
          iVar127 = -(uint)(fVar122 == 0.0);
          iVar128 = -(uint)(fVar123 == 0.0);
          iVar155 = -(uint)(fVar122 == 0.0);
          iVar156 = -(uint)(fVar123 == 0.0);
          auVar136 = NEON_frsqrts(auVar209,auVar219,4);
          fVar79 = fVar79 * auVar209._0_4_ * auVar136._0_4_;
          fVar76 = fVar76 * auVar209._4_4_ * auVar136._4_4_;
          fVar125 = fVar125 * auVar209._8_4_ * auVar136._8_4_;
          fVar77 = fVar77 * auVar209._12_4_ * auVar136._12_4_;
          auVar202[0] = SUB41(fVar79,0) & ~(byte)iVar127;
          auVar202[1] = (byte)((uint)fVar79 >> 8) & ~(byte)((uint)iVar127 >> 8);
          auVar202[2] = (byte)((uint)fVar79 >> 0x10) & ~(byte)((uint)iVar127 >> 0x10);
          auVar202[3] = (byte)((uint)fVar79 >> 0x18) & ~(byte)((uint)iVar127 >> 0x18);
          auVar202[4] = SUB41(fVar76,0) & ~(byte)iVar128;
          auVar202[5] = (byte)((uint)fVar76 >> 8) & ~(byte)((uint)iVar128 >> 8);
          auVar202[6] = (byte)((uint)fVar76 >> 0x10) & ~(byte)((uint)iVar128 >> 0x10);
          auVar202[7] = (byte)((uint)fVar76 >> 0x18) & ~(byte)((uint)iVar128 >> 0x18);
          auVar202[8] = SUB41(fVar125,0) & ~(byte)iVar155;
          auVar202[9] = (byte)((uint)fVar125 >> 8) & ~(byte)((uint)iVar155 >> 8);
          auVar202[10] = (byte)((uint)fVar125 >> 0x10) & ~(byte)((uint)iVar155 >> 0x10);
          auVar202[0xb] = (byte)((uint)fVar125 >> 0x18) & ~(byte)((uint)iVar155 >> 0x18);
          auVar202[0xc] = SUB41(fVar77,0) & ~(byte)iVar156;
          auVar202[0xd] = (byte)((uint)fVar77 >> 8) & ~(byte)((uint)iVar156 >> 8);
          auVar202[0xe] = (byte)((uint)fVar77 >> 0x10) & ~(byte)((uint)iVar156 >> 0x10);
          auVar202[0xf] = (byte)((uint)fVar77 >> 0x18) & ~(byte)((uint)iVar156 >> 0x18);
          auVar210._0_4_ = fVar124 * fVar124;
          auVar210._4_4_ = fVar199 * fVar199;
          auVar210._8_4_ = fVar78 * fVar78;
          auVar210._12_4_ = fVar120 * fVar120;
          auVar136 = NEON_ext(auVar210,auVar210,8,1);
          fVar76 = auVar136._0_4_ + auVar210._0_4_;
          fVar125 = auVar136._4_4_ + auVar210._4_4_;
          fVar79 = fVar76 + fVar125;
          fVar76 = fVar76 + fVar125;
          auVar211._8_8_ = CONCAT44(fVar76,fVar79);
          auVar211._0_8_ = CONCAT44(fVar76,fVar79);
          auVar136 = NEON_frsqrte(auVar211,4);
          auVar227._0_4_ = auVar136._0_4_ * fVar79;
          auVar227._4_4_ = auVar136._4_4_ * fVar76;
          auVar227._8_4_ = auVar136._8_4_ * fVar79;
          auVar227._12_4_ = auVar136._12_4_ * fVar76;
          auVar214 = NEON_frsqrts(auVar136,auVar227,4);
          auVar220._0_4_ = auVar136._0_4_ * auVar214._0_4_;
          auVar220._4_4_ = auVar136._4_4_ * auVar214._4_4_;
          auVar220._8_4_ = auVar136._8_4_ * auVar214._8_4_;
          auVar220._12_4_ = auVar136._12_4_ * auVar214._12_4_;
          auVar228._0_4_ = fVar79 * auVar220._0_4_;
          auVar228._4_4_ = fVar76 * auVar220._4_4_;
          auVar228._8_4_ = fVar79 * auVar220._8_4_;
          auVar228._12_4_ = fVar76 * auVar220._12_4_;
          iVar127 = -(uint)(fVar79 == 0.0);
          iVar128 = -(uint)(fVar76 == 0.0);
          iVar155 = -(uint)(fVar79 == 0.0);
          iVar156 = -(uint)(fVar76 == 0.0);
          auVar136 = NEON_frsqrts(auVar220,auVar228,4);
          fVar124 = fVar124 * auVar220._0_4_ * auVar136._0_4_;
          fVar199 = fVar199 * auVar220._4_4_ * auVar136._4_4_;
          fVar78 = fVar78 * auVar220._8_4_ * auVar136._8_4_;
          fVar120 = fVar120 * auVar220._12_4_ * auVar136._12_4_;
          auVar166[0] = SUB41(fVar124,0) & ~(byte)iVar127;
          auVar166[1] = (byte)((uint)fVar124 >> 8) & ~(byte)((uint)iVar127 >> 8);
          auVar166[2] = (byte)((uint)fVar124 >> 0x10) & ~(byte)((uint)iVar127 >> 0x10);
          auVar166[3] = (byte)((uint)fVar124 >> 0x18) & ~(byte)((uint)iVar127 >> 0x18);
          auVar166[4] = SUB41(fVar199,0) & ~(byte)iVar128;
          auVar166[5] = (byte)((uint)fVar199 >> 8) & ~(byte)((uint)iVar128 >> 8);
          auVar166[6] = (byte)((uint)fVar199 >> 0x10) & ~(byte)((uint)iVar128 >> 0x10);
          auVar166[7] = (byte)((uint)fVar199 >> 0x18) & ~(byte)((uint)iVar128 >> 0x18);
          auVar166[8] = SUB41(fVar78,0) & ~(byte)iVar155;
          auVar166[9] = (byte)((uint)fVar78 >> 8) & ~(byte)((uint)iVar155 >> 8);
          auVar166[10] = (byte)((uint)fVar78 >> 0x10) & ~(byte)((uint)iVar155 >> 0x10);
          auVar166[0xb] = (byte)((uint)fVar78 >> 0x18) & ~(byte)((uint)iVar155 >> 0x18);
          auVar166[0xc] = SUB41(fVar120,0) & ~(byte)iVar156;
          auVar166[0xd] = (byte)((uint)fVar120 >> 8) & ~(byte)((uint)iVar156 >> 8);
          auVar166[0xe] = (byte)((uint)fVar120 >> 0x10) & ~(byte)((uint)iVar156 >> 0x10);
          auVar166[0xf] = (byte)((uint)fVar120 >> 0x18) & ~(byte)((uint)iVar156 >> 0x18);
          uVar226 = a64_TBL(ZEXT816(0),auVar202,0x30201000b0a0908);
          uVar163 = a64_TBL(ZEXT816(0),auVar166,0xb0a090807060504);
          uVar207 = a64_TBL(ZEXT816(0),auVar166,0xf0e0d0c03020100);
          uVar231 = a64_TBL(ZEXT816(0),auVar202,0xf0e0d0c07060504);
          uVar208 = a64_TBL(ZEXT816(0),auVar166,0x30201000b0a0908);
          uVar162 = a64_TBL(ZEXT816(0),auVar166,0xf0e0d0c07060504);
          uVar80 = a64_TBL(ZEXT816(0),auVar202,0xb0a090807060504);
          uVar81 = a64_TBL(ZEXT816(0),auVar202,0xf0e0d0c03020100);
          fVar77 = (float)uVar163 * (float)uVar226 - (float)uVar80 * (float)uVar208;
          fVar124 = (float)((ulong)uVar163 >> 0x20) * (float)((ulong)uVar226 >> 0x20) -
                    (float)((ulong)uVar80 >> 0x20) * (float)((ulong)uVar208 >> 0x20);
          fVar199 = (float)uVar207 * (float)uVar231 - (float)uVar81 * (float)uVar162;
          fVar78 = (float)((ulong)uVar207 >> 0x20) * (float)((ulong)uVar231 >> 0x20) -
                   (float)((ulong)uVar81 >> 0x20) * (float)((ulong)uVar162 >> 0x20);
          auVar167._0_4_ = fVar77 * fVar77;
          auVar167._4_4_ = fVar124 * fVar124;
          auVar167._8_4_ = fVar199 * fVar199;
          auVar167._12_4_ = fVar78 * fVar78;
          auVar136 = NEON_ext(auVar167,auVar167,8,1);
          fVar76 = auVar136._0_4_ + auVar167._0_4_;
          fVar125 = auVar136._4_4_ + auVar167._4_4_;
          fVar79 = fVar76 + fVar125;
          fVar76 = fVar76 + fVar125;
          auVar168._8_8_ = CONCAT44(fVar76,fVar79);
          auVar168._0_8_ = CONCAT44(fVar76,fVar79);
          auVar136 = NEON_frsqrte(auVar168,4);
          iVar127 = -(uint)(fVar79 == 0.0);
          iVar128 = -(uint)(fVar76 == 0.0);
          iVar155 = -(uint)(fVar79 == 0.0);
          iVar156 = -(uint)(fVar76 == 0.0);
          auVar229._0_4_ = auVar136._0_4_ * fVar79;
          auVar229._4_4_ = auVar136._4_4_ * fVar76;
          auVar229._8_4_ = auVar136._8_4_ * fVar79;
          auVar229._12_4_ = auVar136._12_4_ * fVar76;
          auVar214 = NEON_frsqrts(auVar136,auVar229,4);
          auVar203._0_4_ = auVar136._0_4_ * auVar214._0_4_;
          auVar203._4_4_ = auVar136._4_4_ * auVar214._4_4_;
          auVar203._8_4_ = auVar136._8_4_ * auVar214._8_4_;
          auVar203._12_4_ = auVar136._12_4_ * auVar214._12_4_;
          auVar230._0_4_ = fVar79 * auVar203._0_4_;
          auVar230._4_4_ = fVar76 * auVar203._4_4_;
          auVar230._8_4_ = fVar79 * auVar203._8_4_;
          auVar230._12_4_ = fVar76 * auVar203._12_4_;
          auVar22[1] = bVar47;
          auVar22[0] = bVar45;
          auVar22[2] = bVar49;
          auVar22[3] = bVar51;
          auVar22[4] = bVar53;
          auVar22[5] = bVar55;
          auVar22[6] = bVar57;
          auVar22[7] = bVar59;
          auVar22[8] = bVar61;
          auVar22[9] = bVar63;
          auVar22[10] = bVar65;
          auVar22[0xb] = bVar67;
          auVar22[0xc] = bVar69;
          auVar22[0xd] = bVar71;
          auVar22[0xe] = bVar73;
          auVar22[0xf] = bVar75;
          uVar163 = a64_TBL(ZEXT816(0),auVar22,0xb0a090807060504);
          auVar136 = NEON_frsqrts(auVar203,auVar230,4);
          fVar77 = fVar77 * auVar203._0_4_ * auVar136._0_4_;
          fVar124 = fVar124 * auVar203._4_4_ * auVar136._4_4_;
          fVar199 = fVar199 * auVar203._8_4_ * auVar136._8_4_;
          fVar78 = fVar78 * auVar203._12_4_ * auVar136._12_4_;
          auVar87[0] = SUB41(fVar77,0) & ~(byte)iVar127;
          auVar87[1] = (byte)((uint)fVar77 >> 8) & ~(byte)((uint)iVar127 >> 8);
          auVar87[2] = (byte)((uint)fVar77 >> 0x10) & ~(byte)((uint)iVar127 >> 0x10);
          auVar87[3] = (byte)((uint)fVar77 >> 0x18) & ~(byte)((uint)iVar127 >> 0x18);
          auVar87[4] = SUB41(fVar124,0) & ~(byte)iVar128;
          auVar87[5] = (byte)((uint)fVar124 >> 8) & ~(byte)((uint)iVar128 >> 8);
          auVar87[6] = (byte)((uint)fVar124 >> 0x10) & ~(byte)((uint)iVar128 >> 0x10);
          auVar87[7] = (byte)((uint)fVar124 >> 0x18) & ~(byte)((uint)iVar128 >> 0x18);
          auVar87[8] = SUB41(fVar199,0) & ~(byte)iVar155;
          auVar87[9] = (byte)((uint)fVar199 >> 8) & ~(byte)((uint)iVar155 >> 8);
          auVar87[10] = (byte)((uint)fVar199 >> 0x10) & ~(byte)((uint)iVar155 >> 0x10);
          auVar87[0xb] = (byte)((uint)fVar199 >> 0x18) & ~(byte)((uint)iVar155 >> 0x18);
          auVar87[0xc] = SUB41(fVar78,0) & ~(byte)iVar156;
          auVar87[0xd] = (byte)((uint)fVar78 >> 8) & ~(byte)((uint)iVar156 >> 8);
          auVar87[0xe] = (byte)((uint)fVar78 >> 0x10) & ~(byte)((uint)iVar156 >> 0x10);
          auVar87[0xf] = (byte)((uint)fVar78 >> 0x18) & ~(byte)((uint)iVar156 >> 0x18);
          auVar23[1] = bVar47;
          auVar23[0] = bVar45;
          auVar23[2] = bVar49;
          auVar23[3] = bVar51;
          auVar23[4] = bVar53;
          auVar23[5] = bVar55;
          auVar23[6] = bVar57;
          auVar23[7] = bVar59;
          auVar23[8] = bVar61;
          auVar23[9] = bVar63;
          auVar23[10] = bVar65;
          auVar23[0xb] = bVar67;
          auVar23[0xc] = bVar69;
          auVar23[0xd] = bVar71;
          auVar23[0xe] = bVar73;
          auVar23[0xf] = bVar75;
          uVar207 = a64_TBL(ZEXT816(0),auVar23,0xf0e0d0c03020100);
          uVar226 = a64_TBL(ZEXT816(0),auVar87,0x30201000b0a0908);
          uVar231 = a64_TBL(ZEXT816(0),auVar87,0xf0e0d0c07060504);
          auVar24[1] = bVar47;
          auVar24[0] = bVar45;
          auVar24[2] = bVar49;
          auVar24[3] = bVar51;
          auVar24[4] = bVar53;
          auVar24[5] = bVar55;
          auVar24[6] = bVar57;
          auVar24[7] = bVar59;
          auVar24[8] = bVar61;
          auVar24[9] = bVar63;
          auVar24[10] = bVar65;
          auVar24[0xb] = bVar67;
          auVar24[0xc] = bVar69;
          auVar24[0xd] = bVar71;
          auVar24[0xe] = bVar73;
          auVar24[0xf] = bVar75;
          uVar208 = a64_TBL(ZEXT816(0),auVar24,0x30201000b0a0908);
          auVar25[1] = bVar47;
          auVar25[0] = bVar45;
          auVar25[2] = bVar49;
          auVar25[3] = bVar51;
          auVar25[4] = bVar53;
          auVar25[5] = bVar55;
          auVar25[6] = bVar57;
          auVar25[7] = bVar59;
          auVar25[8] = bVar61;
          auVar25[9] = bVar63;
          auVar25[10] = bVar65;
          auVar25[0xb] = bVar67;
          auVar25[0xc] = bVar69;
          auVar25[0xd] = bVar71;
          auVar25[0xe] = bVar73;
          auVar25[0xf] = bVar75;
          uVar162 = a64_TBL(ZEXT816(0),auVar25,0xf0e0d0c07060504);
          uVar80 = a64_TBL(ZEXT816(0),auVar87,0xb0a090807060504);
          uVar81 = a64_TBL(ZEXT816(0),auVar87,0xf0e0d0c03020100);
          fVar79 = (float)uVar163 * (float)uVar226 - (float)uVar80 * (float)uVar208;
          fVar76 = (float)((ulong)uVar163 >> 0x20) * (float)((ulong)uVar226 >> 0x20) -
                   (float)((ulong)uVar80 >> 0x20) * (float)((ulong)uVar208 >> 0x20);
          fVar125 = (float)uVar207 * (float)uVar231 - (float)uVar81 * (float)uVar162;
          fVar77 = (float)((ulong)uVar207 >> 0x20) * (float)((ulong)uVar231 >> 0x20) -
                   (float)((ulong)uVar81 >> 0x20) * (float)((ulong)uVar162 >> 0x20);
LAB_71005eddac:
          fVar124 = fVar79 * fVar79;
          fVar199 = fVar76 * fVar76;
          uVar44 = (undefined1)((uint)fVar199 >> 8);
          uVar46 = (undefined1)((uint)fVar199 >> 0x10);
          uVar48 = (undefined1)((uint)fVar199 >> 0x18);
          fVar78 = fVar125 * fVar125;
          uVar50 = (undefined1)((uint)fVar78 >> 8);
          uVar52 = (undefined1)((uint)fVar78 >> 0x10);
          uVar54 = (undefined1)((uint)fVar78 >> 0x18);
          fVar120 = fVar77 * fVar77;
          uVar56 = (undefined1)((uint)fVar120 >> 8);
          uVar58 = (undefined1)((uint)fVar120 >> 0x10);
          uVar60 = (undefined1)((uint)fVar120 >> 0x18);
          auVar19[4] = SUB41(fVar199,0);
          auVar19._0_4_ = fVar124;
          auVar19[5] = uVar44;
          auVar19[6] = uVar46;
          auVar19[7] = uVar48;
          auVar19[8] = SUB41(fVar78,0);
          auVar19[9] = uVar50;
          auVar19[10] = uVar52;
          auVar19[0xb] = uVar54;
          auVar19[0xc] = SUB41(fVar120,0);
          auVar19[0xd] = uVar56;
          auVar19[0xe] = uVar58;
          auVar19[0xf] = uVar60;
          auVar20[4] = SUB41(fVar199,0);
          auVar20._0_4_ = fVar124;
          auVar20[5] = uVar44;
          auVar20[6] = uVar46;
          auVar20[7] = uVar48;
          auVar20[8] = SUB41(fVar78,0);
          auVar20[9] = uVar50;
          auVar20[10] = uVar52;
          auVar20[0xb] = uVar54;
          auVar20[0xc] = SUB41(fVar120,0);
          auVar20[0xd] = uVar56;
          auVar20[0xe] = uVar58;
          auVar20[0xf] = uVar60;
          auVar136 = NEON_ext(auVar19,auVar20,8,1);
          fVar124 = auVar136._0_4_ + fVar124;
          fVar199 = auVar136._4_4_ + fVar199;
          fVar78 = fVar124 + fVar199;
          fVar124 = fVar124 + fVar199;
          uVar44 = SUB41(fVar124,0);
          uVar46 = (undefined1)((uint)fVar124 >> 8);
          uVar48 = (undefined1)((uint)fVar124 >> 0x10);
          uVar50 = (undefined1)((uint)fVar124 >> 0x18);
          auVar21[4] = uVar44;
          auVar21._0_4_ = fVar78;
          auVar21[5] = uVar46;
          auVar21[6] = uVar48;
          auVar21[7] = uVar50;
          auVar21[8] = SUB41(fVar78,0);
          auVar21[9] = (char)((uint)fVar78 >> 8);
          auVar21[10] = (char)((uint)fVar78 >> 0x10);
          auVar21[0xb] = (char)((uint)fVar78 >> 0x18);
          auVar21[0xc] = uVar44;
          auVar21[0xd] = uVar46;
          auVar21[0xe] = uVar48;
          auVar21[0xf] = uVar50;
          auVar136 = NEON_frsqrte(auVar21,4);
          auVar130._0_4_ = auVar136._0_4_ * fVar78;
          auVar130._4_4_ = auVar136._4_4_ * fVar124;
          auVar130._8_4_ = auVar136._8_4_ * fVar78;
          uVar30 = (undefined2)(CONCAT15(uVar46,CONCAT14(uVar44,fVar78)) >> 0x20);
          auVar130._12_4_ = auVar136._12_4_ * (float)CONCAT13(uVar50,CONCAT12(uVar48,uVar30));
          auVar214 = NEON_frsqrts(auVar136,auVar130,4);
          auVar88._0_4_ = auVar136._0_4_ * auVar214._0_4_;
          auVar88._4_4_ = auVar136._4_4_ * auVar214._4_4_;
          auVar88._8_4_ = auVar136._8_4_ * auVar214._8_4_;
          auVar88._12_4_ = auVar136._12_4_ * auVar214._12_4_;
          auVar131._0_4_ = fVar78 * auVar88._0_4_;
          auVar131._4_4_ = fVar124 * auVar88._4_4_;
          auVar131._8_4_ = fVar78 * auVar88._8_4_;
          auVar131._12_4_ = (float)CONCAT13(uVar50,CONCAT12(uVar48,uVar30)) * auVar88._12_4_;
          iVar127 = -(uint)(fVar78 == 0.0);
          iVar128 = -(uint)(fVar124 == 0.0);
          iVar155 = -(uint)(fVar78 == 0.0);
          iVar156 = -(uint)((float)CONCAT13(uVar50,CONCAT12(uVar48,uVar30)) == 0.0);
          auVar136 = NEON_frsqrts(auVar88,auVar131,4);
          fVar79 = fVar79 * auVar88._0_4_ * auVar136._0_4_;
          fVar76 = fVar76 * auVar88._4_4_ * auVar136._4_4_;
          fVar125 = fVar125 * auVar88._8_4_ * auVar136._8_4_;
          fVar77 = fVar77 * auVar88._12_4_ * auVar136._12_4_;
          bVar45 = SUB41(fVar79,0) & ~(byte)iVar127;
          bVar47 = (byte)((uint)fVar79 >> 8) & ~(byte)((uint)iVar127 >> 8);
          bVar49 = (byte)((uint)fVar79 >> 0x10) & ~(byte)((uint)iVar127 >> 0x10);
          bVar51 = (byte)((uint)fVar79 >> 0x18) & ~(byte)((uint)iVar127 >> 0x18);
          bVar53 = SUB41(fVar76,0) & ~(byte)iVar128;
          bVar55 = (byte)((uint)fVar76 >> 8) & ~(byte)((uint)iVar128 >> 8);
          bVar57 = (byte)((uint)fVar76 >> 0x10) & ~(byte)((uint)iVar128 >> 0x10);
          bVar59 = (byte)((uint)fVar76 >> 0x18) & ~(byte)((uint)iVar128 >> 0x18);
          bVar61 = SUB41(fVar125,0) & ~(byte)iVar155;
          bVar63 = (byte)((uint)fVar125 >> 8) & ~(byte)((uint)iVar155 >> 8);
          bVar65 = (byte)((uint)fVar125 >> 0x10) & ~(byte)((uint)iVar155 >> 0x10);
          bVar67 = (byte)((uint)fVar125 >> 0x18) & ~(byte)((uint)iVar155 >> 0x18);
          bVar69 = SUB41(fVar77,0) & ~(byte)iVar156;
          bVar71 = (byte)((uint)fVar77 >> 8) & ~(byte)((uint)iVar156 >> 8);
          bVar73 = (byte)((uint)fVar77 >> 0x10) & ~(byte)((uint)iVar156 >> 0x10);
          bVar75 = (byte)((uint)fVar77 >> 0x18) & ~(byte)((uint)iVar156 >> 0x18);
LAB_71005edde8:
          *(ulong *)(pfVar40 + 0xe) =
               CONCAT17(bVar75,CONCAT16(bVar73,CONCAT15(bVar71,CONCAT14(bVar69,CONCAT13(bVar67,
                                                  CONCAT12(bVar65,CONCAT11(bVar63,bVar61)))))));
          *(ulong *)(pfVar40 + 0xc) =
               CONCAT17(bVar59,CONCAT16(bVar57,CONCAT15(bVar55,CONCAT14(bVar53,CONCAT13(bVar51,
                                                  CONCAT12(bVar49,CONCAT11(bVar47,bVar45)))))));
        }
        else {
          fVar79 = *pfVar40 - (float)*puVar42;
          fVar76 = pfVar40[1] - (float)((ulong)*puVar42 >> 0x20);
          fVar125 = pfVar40[2] - (float)puVar42[1];
          fVar77 = pfVar40[3] - (float)((ulong)puVar42[1] >> 0x20);
          auVar85._0_4_ = fVar79 * fVar79;
          auVar85._4_4_ = fVar76 * fVar76;
          auVar85._8_4_ = fVar125 * fVar125;
          auVar85._12_4_ = fVar77 * fVar77;
          auVar136 = NEON_ext(auVar85,auVar85,8,1);
          fVar199 = auVar136._0_4_ + auVar85._0_4_;
          fVar78 = auVar136._4_4_ + auVar85._4_4_;
          fVar124 = fVar199 + fVar78;
          fVar199 = fVar199 + fVar78;
          if (1e-05 <= fVar124) {
            auVar98._8_8_ = CONCAT44(fVar199,fVar124);
            auVar98._0_8_ = CONCAT44(fVar199,fVar124);
            auVar136 = NEON_frsqrte(auVar98,4);
            auVar179._0_4_ = fVar124 * auVar136._0_4_;
            auVar179._4_4_ = fVar199 * auVar136._4_4_;
            auVar179._8_4_ = fVar124 * auVar136._8_4_;
            auVar179._12_4_ = fVar199 * auVar136._12_4_;
            auVar214 = NEON_frsqrts(auVar136,auVar179,4);
            auVar140._0_4_ = auVar136._0_4_ * auVar214._0_4_;
            auVar140._4_4_ = auVar136._4_4_ * auVar214._4_4_;
            auVar140._8_4_ = auVar136._8_4_ * auVar214._8_4_;
            auVar140._12_4_ = auVar136._12_4_ * auVar214._12_4_;
            auVar180._0_4_ = fVar124 * auVar140._0_4_;
            auVar180._4_4_ = fVar199 * auVar140._4_4_;
            auVar180._8_4_ = fVar124 * auVar140._8_4_;
            auVar180._12_4_ = fVar199 * auVar140._12_4_;
            iVar127 = -(uint)(fVar124 == 0.0);
            iVar128 = -(uint)(fVar199 == 0.0);
            iVar155 = -(uint)(fVar124 == 0.0);
            iVar156 = -(uint)(fVar199 == 0.0);
            auVar136 = NEON_frsqrts(auVar140,auVar180,4);
            fVar79 = fVar79 * auVar140._0_4_ * auVar136._0_4_;
            fVar76 = fVar76 * auVar140._4_4_ * auVar136._4_4_;
            fVar125 = fVar125 * auVar140._8_4_ * auVar136._8_4_;
            fVar77 = fVar77 * auVar140._12_4_ * auVar136._12_4_;
            fVar79 = (float)CONCAT13((byte)((uint)fVar79 >> 0x18) & ~(byte)((uint)iVar127 >> 0x18),
                                     CONCAT12((byte)((uint)fVar79 >> 0x10) &
                                              ~(byte)((uint)iVar127 >> 0x10),
                                              CONCAT11((byte)((uint)fVar79 >> 8) &
                                                       ~(byte)((uint)iVar127 >> 8),
                                                       SUB41(fVar79,0) & ~(byte)iVar127)));
            auVar83._0_8_ =
                 CONCAT17((byte)((uint)fVar76 >> 0x18) & ~(byte)((uint)iVar128 >> 0x18),
                          CONCAT16((byte)((uint)fVar76 >> 0x10) & ~(byte)((uint)iVar128 >> 0x10),
                                   CONCAT15((byte)((uint)fVar76 >> 8) & ~(byte)((uint)iVar128 >> 8),
                                            CONCAT14(SUB41(fVar76,0) & ~(byte)iVar128,fVar79))));
            auVar83[8] = SUB41(fVar125,0) & ~(byte)iVar155;
            auVar83[9] = (byte)((uint)fVar125 >> 8) & ~(byte)((uint)iVar155 >> 8);
            auVar83[10] = (byte)((uint)fVar125 >> 0x10) & ~(byte)((uint)iVar155 >> 0x10);
            auVar83[0xb] = (byte)((uint)fVar125 >> 0x18) & ~(byte)((uint)iVar155 >> 0x18);
            auVar99[0xc] = SUB41(fVar77,0) & ~(byte)iVar156;
            auVar99._0_12_ = auVar83;
            auVar99[0xd] = (byte)((uint)fVar77 >> 8) & ~(byte)((uint)iVar156 >> 8);
            auVar99[0xe] = (byte)((uint)fVar77 >> 0x10) & ~(byte)((uint)iVar156 >> 0x10);
            auVar99[0xf] = (byte)((uint)fVar77 >> 0x18) & ~(byte)((uint)iVar156 >> 0x18);
            auVar141._0_4_ = fVar79 * 0.0;
            auVar141._4_4_ = (float)((ulong)auVar83._0_8_ >> 0x20) * 1.0;
            auVar141._8_4_ = auVar83._8_4_ * 0.0;
            auVar141._12_4_ = auVar99._12_4_ * 0.0;
            auVar136 = NEON_ext(auVar141,auVar141,8,1);
            fVar79 = auVar136._0_4_ + auVar141._0_4_ + auVar136._4_4_ + auVar141._4_4_;
            if (1e-05 <= ABS(ABS(fVar79) + -1.0)) {
              uVar163 = a64_TBL(ZEXT816(0),auVar99,0xb0a090807060504);
              uVar207 = a64_TBL(ZEXT816(0),auVar99,0xf0e0d0c03020100);
              auVar15._9_7_ = 0;
              auVar15._0_9_ = _DAT_7102ec03b0;
              uVar226 = a64_TBL(ZEXT816(0),auVar15,0x30201000b0a0908);
              auVar16._9_7_ = 0;
              auVar16._0_9_ = _DAT_7102ec03b0;
              uVar231 = a64_TBL(ZEXT816(0),auVar16,0xf0e0d0c07060504);
              uVar208 = a64_TBL(ZEXT816(0),auVar99,0x30201000b0a0908);
              uVar80 = a64_TBL(ZEXT816(0),auVar99,0xf0e0d0c07060504);
              auVar17._9_7_ = 0;
              auVar17._0_9_ = _DAT_7102ec03b0;
              uVar81 = a64_TBL(ZEXT816(0),auVar17,0xb0a090807060504);
              auVar18._9_7_ = 0;
              auVar18._0_9_ = _DAT_7102ec03b0;
              uVar162 = a64_TBL(ZEXT816(0),auVar18,0xf0e0d0c03020100);
              fVar79 = (float)uVar163 * (float)uVar226 - (float)uVar81 * (float)uVar208;
              fVar76 = (float)((ulong)uVar163 >> 0x20) * (float)((ulong)uVar226 >> 0x20) -
                       (float)((ulong)uVar81 >> 0x20) * (float)((ulong)uVar208 >> 0x20);
              fVar125 = (float)uVar207 * (float)uVar231 - (float)uVar162 * (float)uVar80;
              fVar77 = (float)((ulong)uVar207 >> 0x20) * (float)((ulong)uVar231 >> 0x20) -
                       (float)((ulong)uVar162 >> 0x20) * (float)((ulong)uVar80 >> 0x20);
              goto LAB_71005eddac;
            }
            fVar76 = fVar79 * 1.0;
            fVar125 = fVar79 * 0.0;
            fVar77 = fVar79 * 0.0;
            fVar79 = fVar79 * 0.0;
            auVar100._0_4_ = fVar76 * fVar76;
            auVar100._4_4_ = fVar125 * fVar125;
            auVar100._8_4_ = fVar77 * fVar77;
            auVar100._12_4_ = fVar79 * fVar79;
            auVar136 = NEON_ext(auVar100,auVar100,8,1);
            fVar199 = auVar136._0_4_ + auVar100._0_4_;
            fVar78 = auVar136._4_4_ + auVar100._4_4_;
            fVar124 = fVar199 + fVar78;
            fVar199 = fVar199 + fVar78;
            auVar101._8_8_ = CONCAT44(fVar199,fVar124);
            auVar101._0_8_ = CONCAT44(fVar199,fVar124);
            auVar136 = NEON_frsqrte(auVar101,4);
            auVar181._0_4_ = auVar136._0_4_ * fVar124;
            auVar181._4_4_ = auVar136._4_4_ * fVar199;
            auVar181._8_4_ = auVar136._8_4_ * fVar124;
            auVar181._12_4_ = auVar136._12_4_ * fVar199;
            auVar214 = NEON_frsqrts(auVar136,auVar181,4);
            auVar142._0_4_ = auVar136._0_4_ * auVar214._0_4_;
            auVar142._4_4_ = auVar136._4_4_ * auVar214._4_4_;
            auVar142._8_4_ = auVar136._8_4_ * auVar214._8_4_;
            auVar142._12_4_ = auVar136._12_4_ * auVar214._12_4_;
            auVar182._0_4_ = fVar124 * auVar142._0_4_;
            auVar182._4_4_ = fVar199 * auVar142._4_4_;
            auVar182._8_4_ = fVar124 * auVar142._8_4_;
            auVar182._12_4_ = fVar199 * auVar142._12_4_;
            iVar127 = -(uint)(fVar124 == 0.0);
            iVar128 = -(uint)(fVar199 == 0.0);
            iVar155 = -(uint)(fVar124 == 0.0);
            iVar156 = -(uint)(fVar199 == 0.0);
            auVar136 = NEON_frsqrts(auVar142,auVar182,4);
            fVar76 = fVar76 * auVar142._0_4_ * auVar136._0_4_;
            fVar125 = fVar125 * auVar142._4_4_ * auVar136._4_4_;
            fVar77 = fVar77 * auVar142._8_4_ * auVar136._8_4_;
            fVar79 = fVar79 * auVar142._12_4_ * auVar136._12_4_;
            bVar45 = SUB41(fVar76,0) & ~(byte)iVar127;
            bVar47 = (byte)((uint)fVar76 >> 8) & ~(byte)((uint)iVar127 >> 8);
            bVar49 = (byte)((uint)fVar76 >> 0x10) & ~(byte)((uint)iVar127 >> 0x10);
            bVar51 = (byte)((uint)fVar76 >> 0x18) & ~(byte)((uint)iVar127 >> 0x18);
            bVar53 = SUB41(fVar125,0) & ~(byte)iVar128;
            bVar55 = (byte)((uint)fVar125 >> 8) & ~(byte)((uint)iVar128 >> 8);
            bVar57 = (byte)((uint)fVar125 >> 0x10) & ~(byte)((uint)iVar128 >> 0x10);
            bVar59 = (byte)((uint)fVar125 >> 0x18) & ~(byte)((uint)iVar128 >> 0x18);
            bVar61 = SUB41(fVar77,0) & ~(byte)iVar155;
            bVar63 = (byte)((uint)fVar77 >> 8) & ~(byte)((uint)iVar155 >> 8);
            bVar65 = (byte)((uint)fVar77 >> 0x10) & ~(byte)((uint)iVar155 >> 0x10);
            bVar67 = (byte)((uint)fVar77 >> 0x18) & ~(byte)((uint)iVar155 >> 0x18);
            bVar69 = SUB41(fVar79,0) & ~(byte)iVar156;
            bVar71 = (byte)((uint)fVar79 >> 8) & ~(byte)((uint)iVar156 >> 8);
            bVar73 = (byte)((uint)fVar79 >> 0x10) & ~(byte)((uint)iVar156 >> 0x10);
            bVar75 = (byte)((uint)fVar79 >> 0x18) & ~(byte)((uint)iVar156 >> 0x18);
            goto LAB_71005edde8;
          }
          *(undefined8 *)(pfVar40 + 0xe) = puVar42[7];
          *(undefined8 *)(pfVar40 + 0xc) = puVar42[6];
          *(undefined8 *)(pfVar40 + 10) = puVar42[5];
          *(undefined8 *)pfVar39 = puVar42[4];
        }
        if (*(int *)(param_2 + 0x80) == 2) {
          if (*(char *)(*(long *)(*(long *)(param_1 + 0x10) + 0x48) + 0xe22) != '\0') {
            fVar124 = pfVar40[0xc];
            fVar199 = pfVar40[0xd];
            fVar78 = pfVar40[0xe];
            fVar120 = pfVar40[0xf];
            auVar169._0_4_ = fVar124 * fVar124;
            auVar169._4_4_ = fVar199 * fVar199;
            auVar169._8_4_ = fVar78 * fVar78;
            auVar169._12_4_ = fVar120 * fVar120;
            auVar214 = NEON_ext(auVar169,auVar169,8,1);
            fVar79 = (float)*(undefined8 *)(pfVar40 + 8);
            auVar132._0_4_ = fVar79 * fVar79;
            fVar76 = (float)((ulong)*(undefined8 *)(pfVar40 + 8) >> 0x20);
            auVar132._4_4_ = fVar76 * fVar76;
            fVar125 = (float)*(undefined8 *)(pfVar40 + 10);
            auVar132._8_4_ = fVar125 * fVar125;
            fVar77 = (float)((ulong)*(undefined8 *)(pfVar40 + 10) >> 0x20);
            auVar132._12_4_ = fVar77 * fVar77;
            auVar136 = NEON_ext(auVar132,auVar132,8,1);
            fVar161 = auVar214._0_4_ + auVar169._0_4_;
            fVar123 = auVar214._4_4_ + auVar169._4_4_;
            fVar126 = auVar136._0_4_ + auVar132._0_4_;
            fVar154 = auVar136._4_4_ + auVar132._4_4_;
            fVar122 = fVar161 + fVar123;
            fVar161 = fVar161 + fVar123;
            fVar123 = fVar126 + fVar154;
            fVar126 = fVar126 + fVar154;
            auVar170._8_8_ = CONCAT44(fVar161,fVar122);
            auVar170._0_8_ = CONCAT44(fVar161,fVar122);
            auVar133._8_8_ = CONCAT44(fVar126,fVar123);
            auVar133._0_8_ = CONCAT44(fVar126,fVar123);
            auVar214 = NEON_frsqrte(auVar170,4);
            auVar136 = NEON_frsqrte(auVar133,4);
            auVar221._0_4_ = auVar136._0_4_ * fVar123;
            auVar221._4_4_ = auVar136._4_4_ * fVar126;
            auVar221._8_4_ = auVar136._8_4_ * fVar123;
            auVar221._12_4_ = auVar136._12_4_ * fVar126;
            auVar222 = NEON_frsqrts(auVar136,auVar221,4);
            auVar204._0_4_ = auVar136._0_4_ * auVar222._0_4_;
            auVar204._4_4_ = auVar136._4_4_ * auVar222._4_4_;
            auVar204._8_4_ = auVar136._8_4_ * auVar222._8_4_;
            auVar204._12_4_ = auVar136._12_4_ * auVar222._12_4_;
            auVar223._0_4_ = auVar214._0_4_ * fVar122;
            auVar223._4_4_ = auVar214._4_4_ * fVar161;
            auVar223._8_4_ = auVar214._8_4_ * fVar122;
            auVar223._12_4_ = auVar214._12_4_ * fVar161;
            auVar136 = NEON_frsqrts(auVar214,auVar223,4);
            auVar212._0_4_ = auVar214._0_4_ * auVar136._0_4_;
            auVar212._4_4_ = auVar214._4_4_ * auVar136._4_4_;
            auVar212._8_4_ = auVar214._8_4_ * auVar136._8_4_;
            auVar212._12_4_ = auVar214._12_4_ * auVar136._12_4_;
            auVar224._0_4_ = fVar123 * auVar204._0_4_;
            auVar224._4_4_ = fVar126 * auVar204._4_4_;
            auVar224._8_4_ = fVar123 * auVar204._8_4_;
            auVar224._12_4_ = fVar126 * auVar204._12_4_;
            iVar127 = -(uint)(fVar123 == 0.0);
            iVar128 = -(uint)(fVar126 == 0.0);
            iVar155 = -(uint)(fVar123 == 0.0);
            iVar156 = -(uint)(fVar126 == 0.0);
            auVar136 = NEON_frsqrts(auVar204,auVar224,4);
            auVar225._0_4_ = fVar122 * auVar212._0_4_;
            auVar225._4_4_ = fVar161 * auVar212._4_4_;
            auVar225._8_4_ = fVar122 * auVar212._8_4_;
            auVar225._12_4_ = fVar161 * auVar212._12_4_;
            iVar157 = -(uint)(fVar122 == 0.0);
            iVar158 = -(uint)(fVar161 == 0.0);
            iVar159 = -(uint)(fVar122 == 0.0);
            iVar160 = -(uint)(fVar161 == 0.0);
            auVar214 = NEON_frsqrts(auVar212,auVar225,4);
            fVar79 = fVar79 * auVar204._0_4_ * auVar136._0_4_;
            fVar76 = fVar76 * auVar204._4_4_ * auVar136._4_4_;
            fVar125 = fVar125 * auVar204._8_4_ * auVar136._8_4_;
            fVar77 = fVar77 * auVar204._12_4_ * auVar136._12_4_;
            fVar124 = fVar124 * auVar212._0_4_ * auVar214._0_4_;
            fVar199 = fVar199 * auVar212._4_4_ * auVar214._4_4_;
            fVar78 = fVar78 * auVar212._8_4_ * auVar214._8_4_;
            fVar120 = fVar120 * auVar212._12_4_ * auVar214._12_4_;
            *(ulong *)(pfVar40 + 10) =
                 CONCAT17((byte)((uint)fVar77 >> 0x18) & ~(byte)((uint)iVar156 >> 0x18),
                          CONCAT16((byte)((uint)fVar77 >> 0x10) & ~(byte)((uint)iVar156 >> 0x10),
                                   CONCAT15((byte)((uint)fVar77 >> 8) & ~(byte)((uint)iVar156 >> 8),
                                            CONCAT14(SUB41(fVar77,0) & ~(byte)iVar156,
                                                     CONCAT13((byte)((uint)fVar125 >> 0x18) &
                                                              ~(byte)((uint)iVar155 >> 0x18),
                                                              CONCAT12((byte)((uint)fVar125 >> 0x10)
                                                                       & ~(byte)((uint)iVar155 >>
                                                                                0x10),
                                                                       CONCAT11((byte)((uint)fVar125
                                                                                      >> 8) &
                                                                                ~(byte)((uint)
                                                  iVar155 >> 8),SUB41(fVar125,0) & ~(byte)iVar155)))
                                                  ))));
            *(ulong *)(pfVar40 + 8) =
                 CONCAT17((byte)((uint)fVar76 >> 0x18) & ~(byte)((uint)iVar128 >> 0x18),
                          CONCAT16((byte)((uint)fVar76 >> 0x10) & ~(byte)((uint)iVar128 >> 0x10),
                                   CONCAT15((byte)((uint)fVar76 >> 8) & ~(byte)((uint)iVar128 >> 8),
                                            CONCAT14(SUB41(fVar76,0) & ~(byte)iVar128,
                                                     CONCAT13((byte)((uint)fVar79 >> 0x18) &
                                                              ~(byte)((uint)iVar127 >> 0x18),
                                                              CONCAT12((byte)((uint)fVar79 >> 0x10)
                                                                       & ~(byte)((uint)iVar127 >>
                                                                                0x10),
                                                                       CONCAT11((byte)((uint)fVar79
                                                                                      >> 8) &
                                                                                ~(byte)((uint)
                                                  iVar127 >> 8),SUB41(fVar79,0) & ~(byte)iVar127))))
                                           )));
            *(byte *)(pfVar40 + 0x10) = SUB41(fVar78,0) & ~(byte)iVar159;
            *(byte *)((long)pfVar40 + 0x41) =
                 (byte)((uint)fVar78 >> 8) & ~(byte)((uint)iVar159 >> 8);
            *(byte *)((long)pfVar40 + 0x42) =
                 (byte)((uint)fVar78 >> 0x10) & ~(byte)((uint)iVar159 >> 0x10);
            *(byte *)((long)pfVar40 + 0x43) =
                 (byte)((uint)fVar78 >> 0x18) & ~(byte)((uint)iVar159 >> 0x18);
            *(byte *)(pfVar40 + 0x11) = SUB41(fVar120,0) & ~(byte)iVar160;
            *(byte *)((long)pfVar40 + 0x45) =
                 (byte)((uint)fVar120 >> 8) & ~(byte)((uint)iVar160 >> 8);
            *(byte *)((long)pfVar40 + 0x46) =
                 (byte)((uint)fVar120 >> 0x10) & ~(byte)((uint)iVar160 >> 0x10);
            *(byte *)((long)pfVar40 + 0x47) =
                 (byte)((uint)fVar120 >> 0x18) & ~(byte)((uint)iVar160 >> 0x18);
            *(byte *)(pfVar40 + 0xc) = SUB41(fVar124,0) & ~(byte)iVar157;
            *(byte *)((long)pfVar40 + 0x31) =
                 (byte)((uint)fVar124 >> 8) & ~(byte)((uint)iVar157 >> 8);
            *(byte *)((long)pfVar40 + 0x32) =
                 (byte)((uint)fVar124 >> 0x10) & ~(byte)((uint)iVar157 >> 0x10);
            *(byte *)((long)pfVar40 + 0x33) =
                 (byte)((uint)fVar124 >> 0x18) & ~(byte)((uint)iVar157 >> 0x18);
            *(byte *)(pfVar40 + 0xd) = SUB41(fVar199,0) & ~(byte)iVar158;
            *(byte *)((long)pfVar40 + 0x35) =
                 (byte)((uint)fVar199 >> 8) & ~(byte)((uint)iVar158 >> 8);
            *(byte *)((long)pfVar40 + 0x36) =
                 (byte)((uint)fVar199 >> 0x10) & ~(byte)((uint)iVar158 >> 0x10);
            *(byte *)((long)pfVar40 + 0x37) =
                 (byte)((uint)fVar199 >> 0x18) & ~(byte)((uint)iVar158 >> 0x18);
            FUN_71005e4220(param_1,&local_70);
            lVar35 = *(long *)(*(long *)(*(long *)(param_1 + 0x10) + 0x40) + 0x340);
            fVar79 = *(float *)(lVar35 + 0xbc8) + *(float *)(lVar35 + 0xbd8) * (float)local_70;
            fVar76 = *DAT_7103a66e68;
            fVar79 = fVar79 - (float)(int)(fVar79 * *DAT_7103a66e88) * *DAT_7103a66e90;
            if (fVar79 <= fVar76) {
              fVar125 = fVar79;
              if (fVar79 < -fVar76) {
                fVar121 = -*DAT_7103a66e70;
                uVar44 = SUB41(fVar121,0);
                uVar46 = (undefined1)((uint)fVar121 >> 8);
                uVar48 = (undefined1)((uint)fVar121 >> 0x10);
                uVar50 = (undefined1)((uint)fVar121 >> 0x18);
                goto LAB_71005ee8e4;
              }
            }
            else {
              fVar121 = *DAT_7103a66e70;
              uVar44 = SUB41(fVar121,0);
              uVar46 = (undefined1)((uint)fVar121 >> 8);
              uVar48 = (undefined1)((uint)fVar121 >> 0x10);
              uVar50 = (undefined1)((uint)fVar121 >> 0x18);
LAB_71005ee8e4:
              fVar121 = -1.0;
              fVar125 = (float)CONCAT13(uVar50,CONCAT12(uVar48,CONCAT11(uVar46,uVar44))) - fVar79;
            }
            fVar77 = pfVar40[8];
            fVar199 = pfVar40[9];
            fVar125 = fVar125 * fVar125;
            fVar124 = pfVar40[10];
            fVar121 = fVar121 * (fVar125 * ((DAT_7103a66e80[3] +
                                            fVar125 * ((DAT_7103a66e80[1] -
                                                       fVar125 * *DAT_7103a66e80) * fVar125 -
                                                      DAT_7103a66e80[2])) * fVar125 -
                                           DAT_7103a66e80[4]) + 1.0);
            if (fVar79 <= fVar76) {
              if (fVar79 < -fVar76) {
                fVar76 = -*DAT_7103a66e70;
                goto LAB_71005ee954;
              }
            }
            else {
              fVar76 = *DAT_7103a66e70;
LAB_71005ee954:
              fVar79 = fVar76 - fVar79;
            }
            fVar76 = fVar79 * fVar79;
            fVar123 = 1.0 - fVar121;
            fVar79 = fVar79 * (fVar76 * ((DAT_7103a66e78[3] +
                                         fVar76 * ((DAT_7103a66e78[1] - fVar76 * *DAT_7103a66e78) *
                                                   fVar76 - DAT_7103a66e78[2])) * fVar76 -
                                        DAT_7103a66e78[4]) + 1.0);
            fVar76 = (float)*(undefined8 *)(pfVar40 + 0xc);
            fVar125 = (float)((ulong)*(undefined8 *)(pfVar40 + 0xc) >> 0x20);
            fVar78 = (float)*(undefined8 *)(pfVar40 + 0xe);
            fVar120 = (fVar77 * fVar199 * fVar123 - fVar124 * fVar79) * fVar76 +
                      (fVar121 + fVar123 * fVar199 * fVar199) * fVar125 +
                      (fVar77 * fVar79 + fVar123 * fVar199 * fVar124) * fVar78 + 0.0;
            fVar122 = fVar76 * 0.0 + fVar125 * 0.0 + fVar78 * 0.0 + 0.0;
            *(ulong *)(pfVar40 + 0xe) =
                 CONCAT17((char)((uint)fVar122 >> 0x18),
                          CONCAT16((char)((uint)fVar122 >> 0x10),
                                   CONCAT15((char)((uint)fVar122 >> 8),
                                            CONCAT14(SUB41(fVar122,0),
                                                     (fVar199 * fVar79 + fVar123 * fVar77 * fVar124)
                                                     * fVar76 +
                                                     (fVar199 * fVar124 * fVar123 - fVar77 * fVar79)
                                                     * fVar125 +
                                                     (fVar121 + fVar123 * fVar124 * fVar124) *
                                                     fVar78 + 0.0))));
            *(ulong *)(pfVar40 + 0xc) =
                 CONCAT17((char)((uint)fVar120 >> 0x18),
                          CONCAT16((char)((uint)fVar120 >> 0x10),
                                   CONCAT15((char)((uint)fVar120 >> 8),
                                            CONCAT14(SUB41(fVar120,0),
                                                     (fVar121 + fVar123 * fVar77 * fVar77) * fVar76
                                                     + (fVar124 * fVar79 +
                                                       fVar123 * fVar77 * fVar199) * fVar125 +
                                                     (fVar77 * fVar124 * fVar123 - fVar199 * fVar79)
                                                     * fVar78 + 0.0))));
          }
          lVar35 = *(long *)(pfVar40 + 0x14);
          uVar162 = *(undefined8 *)(pfVar40 + 0xe);
          *(undefined8 *)(lVar35 + 0x30) = *(undefined8 *)(pfVar40 + 0xc);
          *(undefined8 *)(lVar35 + 0x38) = uVar162;
          lVar35 = *(long *)(pfVar40 + 0x14);
          uVar162 = *(undefined8 *)(pfVar40 + 10);
          *(undefined8 *)(lVar35 + 0x20) = *(undefined8 *)pfVar39;
          *(undefined8 *)(lVar35 + 0x28) = uVar162;
          lVar35 = *(long *)(pfVar40 + 0x14);
          fVar79 = (float)*(undefined8 *)(lVar35 + 0x30);
          auVar116._0_4_ = fVar79 * fVar79;
          fVar121 = (float)((ulong)*(undefined8 *)(lVar35 + 0x30) >> 0x20);
          auVar116._4_4_ = fVar121 * fVar121;
          fVar76 = (float)*(undefined8 *)(lVar35 + 0x38);
          auVar116._8_4_ = fVar76 * fVar76;
          fVar125 = (float)((ulong)*(undefined8 *)(lVar35 + 0x38) >> 0x20);
          auVar116._12_4_ = fVar125 * fVar125;
          auVar136 = NEON_ext(auVar116,auVar116,8,1);
          fVar124 = auVar136._0_4_ + auVar116._0_4_;
          fVar199 = auVar136._4_4_ + auVar116._4_4_;
          fVar77 = fVar124 + fVar199;
          fVar124 = fVar124 + fVar199;
          auVar117._8_8_ = CONCAT44(fVar124,fVar77);
          auVar117._0_8_ = CONCAT44(fVar124,fVar77);
          auVar136 = NEON_frsqrte(auVar117,4);
          auVar193._0_4_ = auVar136._0_4_ * fVar77;
          auVar193._4_4_ = auVar136._4_4_ * fVar124;
          auVar193._8_4_ = auVar136._8_4_ * fVar77;
          auVar193._12_4_ = auVar136._12_4_ * fVar124;
          auVar214 = NEON_frsqrts(auVar136,auVar193,4);
          auVar150._0_4_ = auVar136._0_4_ * auVar214._0_4_;
          auVar150._4_4_ = auVar136._4_4_ * auVar214._4_4_;
          auVar150._8_4_ = auVar136._8_4_ * auVar214._8_4_;
          auVar150._12_4_ = auVar136._12_4_ * auVar214._12_4_;
          auVar194._0_4_ = fVar77 * auVar150._0_4_;
          auVar194._4_4_ = fVar124 * auVar150._4_4_;
          auVar194._8_4_ = fVar77 * auVar150._8_4_;
          auVar194._12_4_ = fVar124 * auVar150._12_4_;
          iVar127 = -(uint)(fVar77 == 0.0);
          iVar128 = -(uint)(fVar124 == 0.0);
          iVar155 = -(uint)(fVar77 == 0.0);
          iVar156 = -(uint)(fVar124 == 0.0);
          auVar136 = NEON_frsqrts(auVar150,auVar194,4);
          fVar79 = fVar79 * auVar150._0_4_ * auVar136._0_4_;
          fVar121 = fVar121 * auVar150._4_4_ * auVar136._4_4_;
          fVar76 = fVar76 * auVar150._8_4_ * auVar136._8_4_;
          fVar125 = fVar125 * auVar150._12_4_ * auVar136._12_4_;
          *(ulong *)(lVar35 + 0x38) =
               CONCAT17((byte)((uint)fVar125 >> 0x18) & ~(byte)((uint)iVar156 >> 0x18),
                        CONCAT16((byte)((uint)fVar125 >> 0x10) & ~(byte)((uint)iVar156 >> 0x10),
                                 CONCAT15((byte)((uint)fVar125 >> 8) & ~(byte)((uint)iVar156 >> 8),
                                          CONCAT14(SUB41(fVar125,0) & ~(byte)iVar156,
                                                   CONCAT13((byte)((uint)fVar76 >> 0x18) &
                                                            ~(byte)((uint)iVar155 >> 0x18),
                                                            CONCAT12((byte)((uint)fVar76 >> 0x10) &
                                                                     ~(byte)((uint)iVar155 >> 0x10),
                                                                     CONCAT11((byte)((uint)fVar76 >>
                                                                                    8) &
                                                                              ~(byte)((uint)iVar155
                                                                                     >> 8),
                                                                              SUB41(fVar76,0) &
                                                                              ~(byte)iVar155)))))));
          *(ulong *)(lVar35 + 0x30) =
               CONCAT17((byte)((uint)fVar121 >> 0x18) & ~(byte)((uint)iVar128 >> 0x18),
                        CONCAT16((byte)((uint)fVar121 >> 0x10) & ~(byte)((uint)iVar128 >> 0x10),
                                 CONCAT15((byte)((uint)fVar121 >> 8) & ~(byte)((uint)iVar128 >> 8),
                                          CONCAT14(SUB41(fVar121,0) & ~(byte)iVar128,
                                                   CONCAT13((byte)((uint)fVar79 >> 0x18) &
                                                            ~(byte)((uint)iVar127 >> 0x18),
                                                            CONCAT12((byte)((uint)fVar79 >> 0x10) &
                                                                     ~(byte)((uint)iVar127 >> 0x10),
                                                                     CONCAT11((byte)((uint)fVar79 >>
                                                                                    8) &
                                                                              ~(byte)((uint)iVar127
                                                                                     >> 8),
                                                                              SUB41(fVar79,0) &
                                                                              ~(byte)iVar127)))))));
          lVar35 = *(long *)(pfVar40 + 0x14);
          fVar79 = (float)*(undefined8 *)(lVar35 + 0x20);
          auVar118._0_4_ = fVar79 * fVar79;
          fVar121 = (float)((ulong)*(undefined8 *)(lVar35 + 0x20) >> 0x20);
          auVar118._4_4_ = fVar121 * fVar121;
          fVar76 = (float)*(undefined8 *)(lVar35 + 0x28);
          auVar118._8_4_ = fVar76 * fVar76;
          fVar125 = (float)((ulong)*(undefined8 *)(lVar35 + 0x28) >> 0x20);
          auVar118._12_4_ = fVar125 * fVar125;
          auVar136 = NEON_ext(auVar118,auVar118,8,1);
          fVar124 = auVar136._0_4_ + auVar118._0_4_;
          fVar199 = auVar136._4_4_ + auVar118._4_4_;
          fVar77 = fVar124 + fVar199;
          fVar124 = fVar124 + fVar199;
          auVar119._8_8_ = CONCAT44(fVar124,fVar77);
          auVar119._0_8_ = CONCAT44(fVar124,fVar77);
          auVar136 = NEON_frsqrte(auVar119,4);
          auVar195._0_4_ = auVar136._0_4_ * fVar77;
          auVar195._4_4_ = auVar136._4_4_ * fVar124;
          auVar195._8_4_ = auVar136._8_4_ * fVar77;
          auVar195._12_4_ = auVar136._12_4_ * fVar124;
          auVar214 = NEON_frsqrts(auVar136,auVar195,4);
          auVar151._0_4_ = auVar136._0_4_ * auVar214._0_4_;
          auVar151._4_4_ = auVar136._4_4_ * auVar214._4_4_;
          auVar151._8_4_ = auVar136._8_4_ * auVar214._8_4_;
          auVar151._12_4_ = auVar136._12_4_ * auVar214._12_4_;
          auVar196._0_4_ = fVar77 * auVar151._0_4_;
          auVar196._4_4_ = fVar124 * auVar151._4_4_;
          auVar196._8_4_ = fVar77 * auVar151._8_4_;
          auVar196._12_4_ = fVar124 * auVar151._12_4_;
          iVar127 = -(uint)(fVar77 == 0.0);
          iVar128 = -(uint)(fVar124 == 0.0);
          iVar155 = -(uint)(fVar77 == 0.0);
          iVar156 = -(uint)(fVar124 == 0.0);
          auVar136 = NEON_frsqrts(auVar151,auVar196,4);
          fVar79 = fVar79 * auVar151._0_4_ * auVar136._0_4_;
          fVar121 = fVar121 * auVar151._4_4_ * auVar136._4_4_;
          fVar76 = fVar76 * auVar151._8_4_ * auVar136._8_4_;
          fVar125 = fVar125 * auVar151._12_4_ * auVar136._12_4_;
          *(ulong *)(lVar35 + 0x28) =
               CONCAT17((byte)((uint)fVar125 >> 0x18) & ~(byte)((uint)iVar156 >> 0x18),
                        CONCAT16((byte)((uint)fVar125 >> 0x10) & ~(byte)((uint)iVar156 >> 0x10),
                                 CONCAT15((byte)((uint)fVar125 >> 8) & ~(byte)((uint)iVar156 >> 8),
                                          CONCAT14(SUB41(fVar125,0) & ~(byte)iVar156,
                                                   CONCAT13((byte)((uint)fVar76 >> 0x18) &
                                                            ~(byte)((uint)iVar155 >> 0x18),
                                                            CONCAT12((byte)((uint)fVar76 >> 0x10) &
                                                                     ~(byte)((uint)iVar155 >> 0x10),
                                                                     CONCAT11((byte)((uint)fVar76 >>
                                                                                    8) &
                                                                              ~(byte)((uint)iVar155
                                                                                     >> 8),
                                                                              SUB41(fVar76,0) &
                                                                              ~(byte)iVar155)))))));
          *(ulong *)(lVar35 + 0x20) =
               CONCAT17((byte)((uint)fVar121 >> 0x18) & ~(byte)((uint)iVar128 >> 0x18),
                        CONCAT16((byte)((uint)fVar121 >> 0x10) & ~(byte)((uint)iVar128 >> 0x10),
                                 CONCAT15((byte)((uint)fVar121 >> 8) & ~(byte)((uint)iVar128 >> 8),
                                          CONCAT14(SUB41(fVar121,0) & ~(byte)iVar128,
                                                   CONCAT13((byte)((uint)fVar79 >> 0x18) &
                                                            ~(byte)((uint)iVar127 >> 0x18),
                                                            CONCAT12((byte)((uint)fVar79 >> 0x10) &
                                                                     ~(byte)((uint)iVar127 >> 0x10),
                                                                     CONCAT11((byte)((uint)fVar79 >>
                                                                                    8) &
                                                                              ~(byte)((uint)iVar127
                                                                                     >> 8),
                                                                              SUB41(fVar79,0) &
                                                                              ~(byte)iVar127)))))));
        }
      }
      fVar77 = pfVar40[0xc];
      fVar124 = pfVar40[0xd];
      fVar199 = pfVar40[0xe];
      fVar78 = pfVar40[0xf];
      auVar197._0_4_ = fVar77 * fVar77;
      auVar197._4_4_ = fVar124 * fVar124;
      auVar197._8_4_ = fVar199 * fVar199;
      auVar197._12_4_ = fVar78 * fVar78;
      fVar79 = (float)*(undefined8 *)(pfVar40 + 8);
      auVar152._0_4_ = fVar79 * fVar79;
      fVar121 = (float)((ulong)*(undefined8 *)(pfVar40 + 8) >> 0x20);
      auVar152._4_4_ = fVar121 * fVar121;
      fVar76 = (float)*(undefined8 *)(pfVar40 + 10);
      auVar152._8_4_ = fVar76 * fVar76;
      fVar125 = (float)((ulong)*(undefined8 *)(pfVar40 + 10) >> 0x20);
      auVar152._12_4_ = fVar125 * fVar125;
      auVar136 = NEON_ext(auVar152,auVar152,8,1);
      fVar122 = auVar136._0_4_ + auVar152._0_4_;
      fVar123 = auVar136._4_4_ + auVar152._4_4_;
      fVar120 = fVar122 + fVar123;
      fVar122 = fVar122 + fVar123;
      auVar153._8_8_ = CONCAT44(fVar122,fVar120);
      auVar153._0_8_ = CONCAT44(fVar122,fVar120);
      auVar136 = NEON_frsqrte(auVar153,4);
      auVar213._0_4_ = auVar136._0_4_ * fVar120;
      auVar213._4_4_ = auVar136._4_4_ * fVar122;
      auVar213._8_4_ = auVar136._8_4_ * fVar120;
      auVar213._12_4_ = auVar136._12_4_ * fVar122;
      auVar214 = NEON_frsqrts(auVar136,auVar213,4);
      auVar205._0_4_ = auVar136._0_4_ * auVar214._0_4_;
      auVar205._4_4_ = auVar136._4_4_ * auVar214._4_4_;
      auVar205._8_4_ = auVar136._8_4_ * auVar214._8_4_;
      auVar205._12_4_ = auVar136._12_4_ * auVar214._12_4_;
      auVar215._0_4_ = fVar120 * auVar205._0_4_;
      auVar215._4_4_ = fVar122 * auVar205._4_4_;
      auVar215._8_4_ = fVar120 * auVar205._8_4_;
      auVar215._12_4_ = fVar122 * auVar205._12_4_;
      iVar127 = -(uint)(fVar120 == 0.0);
      iVar155 = -(uint)(fVar122 == 0.0);
      iVar157 = -(uint)(fVar120 == 0.0);
      iVar159 = -(uint)(fVar122 == 0.0);
      auVar136 = NEON_frsqrts(auVar205,auVar215,4);
      fVar79 = fVar79 * auVar205._0_4_ * auVar136._0_4_;
      fVar121 = fVar121 * auVar205._4_4_ * auVar136._4_4_;
      fVar76 = fVar76 * auVar205._8_4_ * auVar136._8_4_;
      fVar125 = fVar125 * auVar205._12_4_ * auVar136._12_4_;
      auVar136 = NEON_ext(auVar197,auVar197,8,1);
      fVar122 = auVar136._0_4_ + auVar197._0_4_;
      fVar123 = auVar136._4_4_ + auVar197._4_4_;
      fVar120 = fVar122 + fVar123;
      fVar122 = fVar122 + fVar123;
      auVar198._8_8_ = CONCAT44(fVar122,fVar120);
      auVar198._0_8_ = CONCAT44(fVar122,fVar120);
      auVar136 = NEON_frsqrte(auVar198,4);
      iVar128 = -(uint)(fVar120 == 0.0);
      iVar156 = -(uint)(fVar122 == 0.0);
      iVar158 = -(uint)(fVar120 == 0.0);
      iVar160 = -(uint)(fVar122 == 0.0);
      auVar216._0_4_ = auVar136._0_4_ * fVar120;
      auVar216._4_4_ = auVar136._4_4_ * fVar122;
      auVar216._8_4_ = auVar136._8_4_ * fVar120;
      auVar216._12_4_ = auVar136._12_4_ * fVar122;
      auVar214 = NEON_frsqrts(auVar136,auVar216,4);
      auVar206._0_4_ = auVar136._0_4_ * auVar214._0_4_;
      auVar206._4_4_ = auVar136._4_4_ * auVar214._4_4_;
      auVar206._8_4_ = auVar136._8_4_ * auVar214._8_4_;
      auVar206._12_4_ = auVar136._12_4_ * auVar214._12_4_;
      auVar217._0_4_ = fVar120 * auVar206._0_4_;
      auVar217._4_4_ = fVar122 * auVar206._4_4_;
      auVar217._8_4_ = fVar120 * auVar206._8_4_;
      auVar217._12_4_ = fVar122 * auVar206._12_4_;
      auVar136 = NEON_frsqrts(auVar206,auVar217,4);
      fVar77 = fVar77 * auVar206._0_4_ * auVar136._0_4_;
      fVar124 = fVar124 * auVar206._4_4_ * auVar136._4_4_;
      fVar199 = fVar199 * auVar206._8_4_ * auVar136._8_4_;
      fVar78 = fVar78 * auVar206._12_4_ * auVar136._12_4_;
      *(ulong *)(pfVar40 + 10) =
           CONCAT17((byte)((uint)fVar125 >> 0x18) & ~(byte)((uint)iVar159 >> 0x18),
                    CONCAT16((byte)((uint)fVar125 >> 0x10) & ~(byte)((uint)iVar159 >> 0x10),
                             CONCAT15((byte)((uint)fVar125 >> 8) & ~(byte)((uint)iVar159 >> 8),
                                      CONCAT14(SUB41(fVar125,0) & ~(byte)iVar159,
                                               CONCAT13((byte)((uint)fVar76 >> 0x18) &
                                                        ~(byte)((uint)iVar157 >> 0x18),
                                                        CONCAT12((byte)((uint)fVar76 >> 0x10) &
                                                                 ~(byte)((uint)iVar157 >> 0x10),
                                                                 CONCAT11((byte)((uint)fVar76 >> 8)
                                                                          & ~(byte)((uint)iVar157 >>
                                                                                   8),
                                                                          SUB41(fVar76,0) &
                                                                          ~(byte)iVar157)))))));
      *(ulong *)(pfVar40 + 8) =
           CONCAT17((byte)((uint)fVar121 >> 0x18) & ~(byte)((uint)iVar155 >> 0x18),
                    CONCAT16((byte)((uint)fVar121 >> 0x10) & ~(byte)((uint)iVar155 >> 0x10),
                             CONCAT15((byte)((uint)fVar121 >> 8) & ~(byte)((uint)iVar155 >> 8),
                                      CONCAT14(SUB41(fVar121,0) & ~(byte)iVar155,
                                               CONCAT13((byte)((uint)fVar79 >> 0x18) &
                                                        ~(byte)((uint)iVar127 >> 0x18),
                                                        CONCAT12((byte)((uint)fVar79 >> 0x10) &
                                                                 ~(byte)((uint)iVar127 >> 0x10),
                                                                 CONCAT11((byte)((uint)fVar79 >> 8)
                                                                          & ~(byte)((uint)iVar127 >>
                                                                                   8),
                                                                          SUB41(fVar79,0) &
                                                                          ~(byte)iVar127)))))));
      *(byte *)(pfVar40 + 0x10) = SUB41(fVar199,0) & ~(byte)iVar158;
      *(byte *)((long)pfVar40 + 0x41) = (byte)((uint)fVar199 >> 8) & ~(byte)((uint)iVar158 >> 8);
      *(byte *)((long)pfVar40 + 0x42) =
           (byte)((uint)fVar199 >> 0x10) & ~(byte)((uint)iVar158 >> 0x10);
      *(byte *)((long)pfVar40 + 0x43) =
           (byte)((uint)fVar199 >> 0x18) & ~(byte)((uint)iVar158 >> 0x18);
      *(byte *)(pfVar40 + 0x11) = SUB41(fVar78,0) & ~(byte)iVar160;
      *(byte *)((long)pfVar40 + 0x45) = (byte)((uint)fVar78 >> 8) & ~(byte)((uint)iVar160 >> 8);
      *(byte *)((long)pfVar40 + 0x46) =
           (byte)((uint)fVar78 >> 0x10) & ~(byte)((uint)iVar160 >> 0x10);
      *(byte *)((long)pfVar40 + 0x47) =
           (byte)((uint)fVar78 >> 0x18) & ~(byte)((uint)iVar160 >> 0x18);
      *(byte *)(pfVar40 + 0xc) = SUB41(fVar77,0) & ~(byte)iVar128;
      *(byte *)((long)pfVar40 + 0x31) = (byte)((uint)fVar77 >> 8) & ~(byte)((uint)iVar128 >> 8);
      *(byte *)((long)pfVar40 + 0x32) =
           (byte)((uint)fVar77 >> 0x10) & ~(byte)((uint)iVar128 >> 0x10);
      *(byte *)((long)pfVar40 + 0x33) =
           (byte)((uint)fVar77 >> 0x18) & ~(byte)((uint)iVar128 >> 0x18);
      *(byte *)(pfVar40 + 0xd) = SUB41(fVar124,0) & ~(byte)iVar156;
      *(byte *)((long)pfVar40 + 0x35) = (byte)((uint)fVar124 >> 8) & ~(byte)((uint)iVar156 >> 8);
      *(byte *)((long)pfVar40 + 0x36) =
           (byte)((uint)fVar124 >> 0x10) & ~(byte)((uint)iVar156 >> 0x10);
      *(byte *)((long)pfVar40 + 0x37) =
           (byte)((uint)fVar124 >> 0x18) & ~(byte)((uint)iVar156 >> 0x18);
      iVar127 = *(int *)(param_2 + 0x80);
      if (iVar127 == 1) {
        fVar79 = (float)*(undefined8 *)pfVar40;
        fVar79 = fVar79 * fVar79;
        fVar121 = (float)((ulong)*(undefined8 *)pfVar40 >> 0x20);
        fVar121 = fVar121 * fVar121;
        uVar44 = (undefined1)((uint)fVar121 >> 8);
        uVar46 = (undefined1)((uint)fVar121 >> 0x10);
        uVar48 = (undefined1)((uint)fVar121 >> 0x18);
        fVar76 = (float)*(undefined8 *)(pfVar40 + 2);
        fVar76 = fVar76 * fVar76;
        uVar50 = (undefined1)((uint)fVar76 >> 8);
        uVar52 = (undefined1)((uint)fVar76 >> 0x10);
        uVar54 = (undefined1)((uint)fVar76 >> 0x18);
        fVar125 = (float)((ulong)*(undefined8 *)(pfVar40 + 2) >> 0x20);
        fVar125 = fVar125 * fVar125;
        uVar56 = (undefined1)((uint)fVar125 >> 8);
        uVar58 = (undefined1)((uint)fVar125 >> 0x10);
        uVar60 = (undefined1)((uint)fVar125 >> 0x18);
        auVar4[4] = SUB41(fVar121,0);
        auVar4._0_4_ = fVar79;
        auVar4[5] = uVar44;
        auVar4[6] = uVar46;
        auVar4[7] = uVar48;
        auVar4[8] = SUB41(fVar76,0);
        auVar4[9] = uVar50;
        auVar4[10] = uVar52;
        auVar4[0xb] = uVar54;
        auVar4[0xc] = SUB41(fVar125,0);
        auVar4[0xd] = uVar56;
        auVar4[0xe] = uVar58;
        auVar4[0xf] = uVar60;
        auVar5[4] = SUB41(fVar121,0);
        auVar5._0_4_ = fVar79;
        auVar5[5] = uVar44;
        auVar5[6] = uVar46;
        auVar5[7] = uVar48;
        auVar5[8] = SUB41(fVar76,0);
        auVar5[9] = uVar50;
        auVar5[10] = uVar52;
        auVar5[0xb] = uVar54;
        auVar5[0xc] = SUB41(fVar125,0);
        auVar5[0xd] = uVar56;
        auVar5[0xe] = uVar58;
        auVar5[0xf] = uVar60;
        auVar136 = NEON_ext(auVar4,auVar5,8,1);
        *(float *)(param_2 + 0xa0) =
             *(float *)(param_2 + 0xa0) + SQRT(auVar136._0_4_ + fVar79 + auVar136._4_4_ + fVar121);
        uVar44 = 0;
        uVar46 = 0;
        uVar48 = 0;
        uVar50 = 0;
        goto LAB_71005eebc0;
      }
      fVar79 = *pfVar40 - (float)*(undefined8 *)pfVar43;
      fVar121 = pfVar40[1] - (float)((ulong)*(undefined8 *)pfVar43 >> 0x20);
      fVar76 = pfVar40[2] - (float)*(undefined8 *)(pfVar43 + 2);
      fVar125 = pfVar40[3] - (float)((ulong)*(undefined8 *)(pfVar43 + 2) >> 0x20);
      fVar79 = fVar79 * fVar79;
      fVar121 = fVar121 * fVar121;
      uVar44 = (undefined1)((uint)fVar121 >> 8);
      uVar46 = (undefined1)((uint)fVar121 >> 0x10);
      uVar48 = (undefined1)((uint)fVar121 >> 0x18);
      fVar76 = fVar76 * fVar76;
      uVar50 = (undefined1)((uint)fVar76 >> 8);
      uVar52 = (undefined1)((uint)fVar76 >> 0x10);
      uVar54 = (undefined1)((uint)fVar76 >> 0x18);
      fVar125 = fVar125 * fVar125;
      uVar56 = (undefined1)((uint)fVar125 >> 8);
      uVar58 = (undefined1)((uint)fVar125 >> 0x10);
      uVar60 = (undefined1)((uint)fVar125 >> 0x18);
      auVar6[4] = SUB41(fVar121,0);
      auVar6._0_4_ = fVar79;
      auVar6[5] = uVar44;
      auVar6[6] = uVar46;
      auVar6[7] = uVar48;
      auVar6[8] = SUB41(fVar76,0);
      auVar6[9] = uVar50;
      auVar6[10] = uVar52;
      auVar6[0xb] = uVar54;
      auVar6[0xc] = SUB41(fVar125,0);
      auVar6[0xd] = uVar56;
      auVar6[0xe] = uVar58;
      auVar6[0xf] = uVar60;
      auVar7[4] = SUB41(fVar121,0);
      auVar7._0_4_ = fVar79;
      auVar7[5] = uVar44;
      auVar7[6] = uVar46;
      auVar7[7] = uVar48;
      auVar7[8] = SUB41(fVar76,0);
      auVar7[9] = uVar50;
      auVar7[10] = uVar52;
      auVar7[0xb] = uVar54;
      auVar7[0xc] = SUB41(fVar125,0);
      auVar7[0xd] = uVar56;
      auVar7[0xe] = uVar58;
      auVar7[0xf] = uVar60;
      auVar136 = NEON_ext(auVar6,auVar7,8,1);
      *(float *)(param_2 + 0xa0) =
           *(float *)(param_2 + 0xa0) + SQRT(auVar136._0_4_ + fVar79 + auVar136._4_4_ + fVar121);
    }
    else {
      if (param_3[1] == 0) {
        FUN_71005e4078(param_1,local_b0);
        FUN_71005e3d7c(param_1,(undefined8 *)pfVar40);
        *(undefined8 *)(param_2 + 0x58) = *(undefined8 *)(pfVar40 + 2);
        *(undefined8 *)(param_2 + 0x50) = *(undefined8 *)pfVar40;
        if (*(int *)(param_2 + 0x80) != 0) goto LAB_71005ed708;
LAB_71005eda94:
        uVar162 = *(undefined8 *)(pfVar40 + 2);
        uVar60 = (undefined1)uVar162;
        uVar62 = (undefined1)((ulong)uVar162 >> 8);
        uVar64 = (undefined1)((ulong)uVar162 >> 0x10);
        uVar66 = (undefined1)((ulong)uVar162 >> 0x18);
        uVar68 = (undefined1)((ulong)uVar162 >> 0x20);
        uVar70 = (undefined1)((ulong)uVar162 >> 0x28);
        uVar72 = (undefined1)((ulong)uVar162 >> 0x30);
        uVar74 = (undefined1)((ulong)uVar162 >> 0x38);
        uVar162 = *(undefined8 *)pfVar40;
        uVar44 = (undefined1)uVar162;
        uVar46 = (undefined1)((ulong)uVar162 >> 8);
        uVar48 = (undefined1)((ulong)uVar162 >> 0x10);
        uVar50 = (undefined1)((ulong)uVar162 >> 0x18);
        uVar52 = (undefined1)((ulong)uVar162 >> 0x20);
        uVar54 = (undefined1)((ulong)uVar162 >> 0x28);
        uVar56 = (undefined1)((ulong)uVar162 >> 0x30);
        uVar58 = (undefined1)((ulong)uVar162 >> 0x38);
      }
      else {
        FUN_71005e4104(param_1,local_b0);
        FUN_71005e3d54(param_1,(undefined8 *)pfVar40);
        *(undefined8 *)(param_2 + 0x58) = *(undefined8 *)(pfVar40 + 2);
        *(undefined8 *)(param_2 + 0x50) = *(undefined8 *)pfVar40;
        if (*(int *)(param_2 + 0x80) == 0) goto LAB_71005eda94;
LAB_71005ed708:
        fVar121 = *pfVar40 - (float)*(undefined8 *)pfVar43;
        uVar44 = SUB41(fVar121,0);
        uVar46 = (undefined1)((uint)fVar121 >> 8);
        uVar48 = (undefined1)((uint)fVar121 >> 0x10);
        uVar50 = (undefined1)((uint)fVar121 >> 0x18);
        fVar121 = pfVar40[1] - (float)((ulong)*(undefined8 *)pfVar43 >> 0x20);
        uVar52 = SUB41(fVar121,0);
        uVar54 = (undefined1)((uint)fVar121 >> 8);
        uVar56 = (undefined1)((uint)fVar121 >> 0x10);
        uVar58 = (undefined1)((uint)fVar121 >> 0x18);
        fVar121 = pfVar40[2] - (float)*(undefined8 *)(pfVar43 + 2);
        uVar60 = SUB41(fVar121,0);
        uVar62 = (undefined1)((uint)fVar121 >> 8);
        uVar64 = (undefined1)((uint)fVar121 >> 0x10);
        uVar66 = (undefined1)((uint)fVar121 >> 0x18);
        fVar121 = pfVar40[3] - (float)((ulong)*(undefined8 *)(pfVar43 + 2) >> 0x20);
        uVar68 = SUB41(fVar121,0);
        uVar70 = (undefined1)((uint)fVar121 >> 8);
        uVar72 = (undefined1)((uint)fVar121 >> 0x10);
        uVar74 = (undefined1)((uint)fVar121 >> 0x18);
      }
      fVar121 = (float)CONCAT13(uVar50,CONCAT12(uVar48,CONCAT11(uVar46,uVar44))) *
                (float)CONCAT13(uVar50,CONCAT12(uVar48,CONCAT11(uVar46,uVar44)));
      fVar125 = (float)CONCAT13(uVar58,CONCAT12(uVar56,CONCAT11(uVar54,uVar52))) *
                (float)CONCAT13(uVar58,CONCAT12(uVar56,CONCAT11(uVar54,uVar52)));
      uVar44 = (undefined1)((uint)fVar125 >> 8);
      uVar46 = (undefined1)((uint)fVar125 >> 0x10);
      uVar48 = (undefined1)((uint)fVar125 >> 0x18);
      fVar77 = (float)CONCAT13(uVar66,CONCAT12(uVar64,CONCAT11(uVar62,uVar60))) *
               (float)CONCAT13(uVar66,CONCAT12(uVar64,CONCAT11(uVar62,uVar60)));
      uVar50 = (undefined1)((uint)fVar77 >> 8);
      uVar52 = (undefined1)((uint)fVar77 >> 0x10);
      uVar54 = (undefined1)((uint)fVar77 >> 0x18);
      fVar124 = (float)CONCAT13(uVar74,CONCAT12(uVar72,CONCAT11(uVar70,uVar68))) *
                (float)CONCAT13(uVar74,CONCAT12(uVar72,CONCAT11(uVar70,uVar68)));
      uVar56 = (undefined1)((uint)fVar124 >> 8);
      uVar58 = (undefined1)((uint)fVar124 >> 0x10);
      uVar60 = (undefined1)((uint)fVar124 >> 0x18);
      auVar26[4] = SUB41(fVar125,0);
      auVar26._0_4_ = fVar121;
      auVar26[5] = uVar44;
      auVar26[6] = uVar46;
      auVar26[7] = uVar48;
      auVar26[8] = SUB41(fVar77,0);
      auVar26[9] = uVar50;
      auVar26[10] = uVar52;
      auVar26[0xb] = uVar54;
      auVar26[0xc] = SUB41(fVar124,0);
      auVar26[0xd] = uVar56;
      auVar26[0xe] = uVar58;
      auVar26[0xf] = uVar60;
      auVar27[4] = SUB41(fVar125,0);
      auVar27._0_4_ = fVar121;
      auVar27[5] = uVar44;
      auVar27[6] = uVar46;
      auVar27[7] = uVar48;
      auVar27[8] = SUB41(fVar77,0);
      auVar27[9] = uVar50;
      auVar27[10] = uVar52;
      auVar27[0xb] = uVar54;
      auVar27[0xc] = SUB41(fVar124,0);
      auVar27[0xd] = uVar56;
      auVar27[0xe] = uVar58;
      auVar27[0xf] = uVar60;
      auVar136 = NEON_ext(auVar26,auVar27,8,1);
      *(float *)(param_2 + 0xa0) =
           *(float *)(param_2 + 0xa0) + SQRT(auVar136._0_4_ + fVar121 + auVar136._4_4_ + fVar125);
      pfVar40[0x18] = local_b0[0];
      if (param_3[1] == 0) {
        uVar34 = *(ulong *)(*(long *)(param_1 + 0x10) + 0x118);
        *(undefined8 *)(pfVar40 + 0x10) = *(undefined8 *)(*(long *)(param_1 + 0x10) + 0x110);
        *(ulong *)(pfVar40 + 0x12) = uVar34 & 0xffffffff;
        *(undefined8 *)(pfVar40 + 0x10) = *(undefined8 *)(pfVar40 + 0x10);
        bVar45 = *param_3;
      }
      else {
        *(undefined8 *)(pfVar40 + 0x12) = puVar42[1];
        *(undefined8 *)(pfVar40 + 0x10) = *puVar42;
        bVar45 = *param_3;
      }
      if ((bVar45 - 1 < 2) &&
         (lVar35 = *(long *)(param_1 + 0x10), *(char *)(*(long *)(lVar35 + 0x48) + 0xe22) != '\0'))
      {
        iVar127 = *(int *)(param_2 + 0x80);
        if (iVar127 < 1) {
          uVar162 = *(undefined8 *)(pfVar40 + 8);
          uVar80 = *(undefined8 *)(pfVar40 + 10);
          uVar60 = (undefined1)uVar80;
          uVar62 = (undefined1)((ulong)uVar80 >> 8);
          uVar64 = (undefined1)((ulong)uVar80 >> 0x10);
          uVar66 = (undefined1)((ulong)uVar80 >> 0x18);
          uVar68 = (undefined1)((ulong)uVar80 >> 0x20);
          uVar70 = (undefined1)((ulong)uVar80 >> 0x28);
          uVar72 = (undefined1)((ulong)uVar80 >> 0x30);
          uVar74 = (undefined1)((ulong)uVar80 >> 0x38);
          uVar44 = (undefined1)uVar162;
          uVar46 = (undefined1)((ulong)uVar162 >> 8);
          uVar48 = (undefined1)((ulong)uVar162 >> 0x10);
          uVar50 = (undefined1)((ulong)uVar162 >> 0x18);
          uVar52 = (undefined1)((ulong)uVar162 >> 0x20);
          uVar54 = (undefined1)((ulong)uVar162 >> 0x28);
          uVar56 = (undefined1)((ulong)uVar162 >> 0x30);
          uVar58 = (undefined1)((ulong)uVar162 >> 0x38);
        }
        else {
          pfVar36 = *(float **)(pfVar40 + 0x14);
          fVar125 = 1.0 / *(float *)(lVar35 + 0x2c);
          fVar121 = ((float)*(undefined8 *)pfVar40 - *pfVar36) * fVar125 + 0.0;
          uVar44 = SUB41(fVar121,0);
          uVar46 = (undefined1)((uint)fVar121 >> 8);
          uVar48 = (undefined1)((uint)fVar121 >> 0x10);
          uVar50 = (undefined1)((uint)fVar121 >> 0x18);
          fVar121 = ((float)((ulong)*(undefined8 *)pfVar40 >> 0x20) - pfVar36[1]) * fVar125 + 0.0;
          uVar52 = SUB41(fVar121,0);
          uVar54 = (undefined1)((uint)fVar121 >> 8);
          uVar56 = (undefined1)((uint)fVar121 >> 0x10);
          uVar58 = (undefined1)((uint)fVar121 >> 0x18);
          fVar121 = ((float)*(undefined8 *)(pfVar40 + 2) - pfVar36[2]) * fVar125 + 0.0;
          uVar60 = SUB41(fVar121,0);
          uVar62 = (undefined1)((uint)fVar121 >> 8);
          uVar64 = (undefined1)((uint)fVar121 >> 0x10);
          uVar66 = (undefined1)((uint)fVar121 >> 0x18);
          fVar121 = ((float)((ulong)*(undefined8 *)(pfVar40 + 2) >> 0x20) - pfVar36[3]) * fVar125 +
                    0.0;
          uVar68 = SUB41(fVar121,0);
          uVar70 = (undefined1)((uint)fVar121 >> 8);
          uVar72 = (undefined1)((uint)fVar121 >> 0x10);
          uVar74 = (undefined1)((uint)fVar121 >> 0x18);
        }
        auVar103._0_4_ =
             (float)CONCAT13(uVar50,CONCAT12(uVar48,CONCAT11(uVar46,uVar44))) *
             (float)CONCAT13(uVar50,CONCAT12(uVar48,CONCAT11(uVar46,uVar44)));
        auVar103._4_4_ =
             (float)CONCAT13(uVar58,CONCAT12(uVar56,CONCAT11(uVar54,uVar52))) *
             (float)CONCAT13(uVar58,CONCAT12(uVar56,CONCAT11(uVar54,uVar52)));
        auVar103._8_4_ =
             (float)CONCAT13(uVar66,CONCAT12(uVar64,CONCAT11(uVar62,uVar60))) *
             (float)CONCAT13(uVar66,CONCAT12(uVar64,CONCAT11(uVar62,uVar60)));
        auVar103._12_4_ =
             (float)CONCAT13(uVar74,CONCAT12(uVar72,CONCAT11(uVar70,uVar68))) *
             (float)CONCAT13(uVar74,CONCAT12(uVar72,CONCAT11(uVar70,uVar68)));
        auVar136 = NEON_ext(auVar103,auVar103,8,1);
        fVar125 = auVar136._0_4_ + auVar103._0_4_;
        fVar77 = auVar136._4_4_ + auVar103._4_4_;
        fVar121 = fVar125 + fVar77;
        uVar162 = CONCAT44(fVar125 + fVar77,fVar121);
        if (fVar121 < 1e-05) {
          uVar80 = *(undefined8 *)(lVar35 + 0x128);
          uVar60 = (undefined1)uVar80;
          uVar62 = (undefined1)((ulong)uVar80 >> 8);
          uVar64 = (undefined1)((ulong)uVar80 >> 0x10);
          uVar66 = (undefined1)((ulong)uVar80 >> 0x18);
          uVar68 = (undefined1)((ulong)uVar80 >> 0x20);
          uVar70 = (undefined1)((ulong)uVar80 >> 0x28);
          uVar72 = (undefined1)((ulong)uVar80 >> 0x30);
          uVar74 = (undefined1)((ulong)uVar80 >> 0x38);
          uVar162 = *(undefined8 *)(lVar35 + 0x120);
          uVar44 = (undefined1)uVar162;
          uVar46 = (undefined1)((ulong)uVar162 >> 8);
          uVar48 = (undefined1)((ulong)uVar162 >> 0x10);
          uVar50 = (undefined1)((ulong)uVar162 >> 0x18);
          uVar52 = (undefined1)((ulong)uVar162 >> 0x20);
          uVar54 = (undefined1)((ulong)uVar162 >> 0x28);
          uVar56 = (undefined1)((ulong)uVar162 >> 0x30);
          uVar58 = (undefined1)((ulong)uVar162 >> 0x38);
          auVar104._0_4_ = (float)uVar162 * (float)uVar162;
          fVar121 = (float)((ulong)uVar162 >> 0x20);
          auVar104._4_4_ = fVar121 * fVar121;
          auVar104._8_4_ = (float)uVar80 * (float)uVar80;
          fVar121 = (float)((ulong)uVar80 >> 0x20);
          auVar104._12_4_ = fVar121 * fVar121;
          auVar136 = NEON_ext(auVar104,auVar104,8,1);
          fVar121 = auVar136._0_4_ + auVar104._0_4_;
          fVar125 = auVar136._4_4_ + auVar104._4_4_;
          uVar162 = CONCAT44(fVar121 + fVar125,fVar121 + fVar125);
        }
        auVar105._8_8_ = uVar162;
        auVar105._0_8_ = uVar162;
        auVar136 = NEON_frsqrte(auVar105,4);
        fVar121 = (float)uVar162;
        auVar183._0_4_ = fVar121 * auVar136._0_4_;
        fVar125 = (float)((ulong)uVar162 >> 0x20);
        auVar183._4_4_ = fVar125 * auVar136._4_4_;
        auVar183._8_4_ = fVar121 * auVar136._8_4_;
        auVar183._12_4_ = fVar125 * auVar136._12_4_;
        auVar214 = NEON_frsqrts(auVar136,auVar183,4);
        auVar145._0_4_ = auVar136._0_4_ * auVar214._0_4_;
        auVar145._4_4_ = auVar136._4_4_ * auVar214._4_4_;
        auVar145._8_4_ = auVar136._8_4_ * auVar214._8_4_;
        auVar145._12_4_ = auVar136._12_4_ * auVar214._12_4_;
        auVar184._0_4_ = fVar121 * auVar145._0_4_;
        auVar184._4_4_ = fVar125 * auVar145._4_4_;
        auVar184._8_4_ = fVar121 * auVar145._8_4_;
        auVar184._12_4_ = fVar125 * auVar145._12_4_;
        iVar128 = -(uint)(fVar121 == 0.0);
        iVar155 = -(uint)(fVar125 == 0.0);
        iVar156 = -(uint)(fVar121 == 0.0);
        iVar157 = -(uint)(fVar125 == 0.0);
        auVar136 = NEON_frsqrts(auVar145,auVar184,4);
        fVar121 = (float)CONCAT13(uVar50,CONCAT12(uVar48,CONCAT11(uVar46,uVar44))) *
                  auVar145._0_4_ * auVar136._0_4_;
        fVar125 = (float)CONCAT13(uVar58,CONCAT12(uVar56,CONCAT11(uVar54,uVar52))) *
                  auVar145._4_4_ * auVar136._4_4_;
        fVar77 = (float)CONCAT13(uVar66,CONCAT12(uVar64,CONCAT11(uVar62,uVar60))) *
                 auVar145._8_4_ * auVar136._8_4_;
        fVar124 = (float)CONCAT13(uVar74,CONCAT12(uVar72,CONCAT11(uVar70,uVar68))) *
                  auVar145._12_4_ * auVar136._12_4_;
        uStack_68 = CONCAT17((byte)((uint)fVar124 >> 0x18) & ~(byte)((uint)iVar157 >> 0x18),
                             CONCAT16((byte)((uint)fVar124 >> 0x10) & ~(byte)((uint)iVar157 >> 0x10)
                                      ,CONCAT15((byte)((uint)fVar124 >> 8) &
                                                ~(byte)((uint)iVar157 >> 8),
                                                CONCAT14(SUB41(fVar124,0) & ~(byte)iVar157,
                                                         CONCAT13((byte)((uint)fVar77 >> 0x18) &
                                                                  ~(byte)((uint)iVar156 >> 0x18),
                                                                  CONCAT12((byte)((uint)fVar77 >>
                                                                                 0x10) &
                                                                           ~(byte)((uint)iVar156 >>
                                                                                  0x10),
                                                                           CONCAT11((byte)((uint)
                                                  fVar77 >> 8) & ~(byte)((uint)iVar156 >> 8),
                                                  SUB41(fVar77,0) & ~(byte)iVar156)))))));
        local_70 = CONCAT17((byte)((uint)fVar125 >> 0x18) & ~(byte)((uint)iVar155 >> 0x18),
                            CONCAT16((byte)((uint)fVar125 >> 0x10) & ~(byte)((uint)iVar155 >> 0x10),
                                     CONCAT15((byte)((uint)fVar125 >> 8) &
                                              ~(byte)((uint)iVar155 >> 8),
                                              CONCAT14(SUB41(fVar125,0) & ~(byte)iVar155,
                                                       CONCAT13((byte)((uint)fVar121 >> 0x18) &
                                                                ~(byte)((uint)iVar128 >> 0x18),
                                                                CONCAT12((byte)((uint)fVar121 >>
                                                                               0x10) &
                                                                         ~(byte)((uint)iVar128 >>
                                                                                0x10),
                                                                         CONCAT11((byte)((uint)
                                                  fVar121 >> 8) & ~(byte)((uint)iVar128 >> 8),
                                                  SUB41(fVar121,0) & ~(byte)iVar128)))))));
        FUN_71005e3ff8(param_1,afStack_80);
        pfVar36 = pfVar40 + 0x10;
        FUN_71005def50(local_78,(undefined8 *)pfVar36,(undefined8 *)pfVar36,&local_70);
        fVar121 = (float)*(undefined8 *)(pfVar40 + 0x10);
        auVar106._0_4_ = fVar121 * fVar121;
        fVar125 = (float)((ulong)*(undefined8 *)(pfVar40 + 0x10) >> 0x20);
        auVar106._4_4_ = fVar125 * fVar125;
        fVar77 = (float)*(undefined8 *)(pfVar40 + 0x12);
        auVar106._8_4_ = fVar77 * fVar77;
        fVar124 = (float)((ulong)*(undefined8 *)(pfVar40 + 0x12) >> 0x20);
        auVar106._12_4_ = fVar124 * fVar124;
        auVar136 = NEON_ext(auVar106,auVar106,8,1);
        fVar78 = auVar136._0_4_ + auVar106._0_4_;
        fVar120 = auVar136._4_4_ + auVar106._4_4_;
        fVar199 = fVar78 + fVar120;
        fVar78 = fVar78 + fVar120;
        auVar107._8_8_ = CONCAT44(fVar78,fVar199);
        auVar107._0_8_ = CONCAT44(fVar78,fVar199);
        auVar136 = NEON_frsqrte(auVar107,4);
        auVar185._0_4_ = auVar136._0_4_ * fVar199;
        auVar185._4_4_ = auVar136._4_4_ * fVar78;
        auVar185._8_4_ = auVar136._8_4_ * fVar199;
        auVar185._12_4_ = auVar136._12_4_ * fVar78;
        auVar214 = NEON_frsqrts(auVar136,auVar185,4);
        auVar146._0_4_ = auVar136._0_4_ * auVar214._0_4_;
        auVar146._4_4_ = auVar136._4_4_ * auVar214._4_4_;
        auVar146._8_4_ = auVar136._8_4_ * auVar214._8_4_;
        auVar146._12_4_ = auVar136._12_4_ * auVar214._12_4_;
        auVar186._0_4_ = fVar199 * auVar146._0_4_;
        auVar186._4_4_ = fVar78 * auVar146._4_4_;
        auVar186._8_4_ = fVar199 * auVar146._8_4_;
        auVar186._12_4_ = fVar78 * auVar146._12_4_;
        iVar128 = -(uint)(fVar199 == 0.0);
        iVar155 = -(uint)(fVar78 == 0.0);
        iVar156 = -(uint)(fVar199 == 0.0);
        iVar157 = -(uint)(fVar78 == 0.0);
        auVar136 = NEON_frsqrts(auVar146,auVar186,4);
        fVar121 = fVar121 * auVar146._0_4_ * auVar136._0_4_;
        fVar125 = fVar125 * auVar146._4_4_ * auVar136._4_4_;
        fVar77 = fVar77 * auVar146._8_4_ * auVar136._8_4_;
        fVar124 = fVar124 * auVar146._12_4_ * auVar136._12_4_;
        *(ulong *)(pfVar40 + 0x12) =
             CONCAT17((byte)((uint)fVar124 >> 0x18) & ~(byte)((uint)iVar157 >> 0x18),
                      CONCAT16((byte)((uint)fVar124 >> 0x10) & ~(byte)((uint)iVar157 >> 0x10),
                               CONCAT15((byte)((uint)fVar124 >> 8) & ~(byte)((uint)iVar157 >> 8),
                                        CONCAT14(SUB41(fVar124,0) & ~(byte)iVar157,
                                                 CONCAT13((byte)((uint)fVar77 >> 0x18) &
                                                          ~(byte)((uint)iVar156 >> 0x18),
                                                          CONCAT12((byte)((uint)fVar77 >> 0x10) &
                                                                   ~(byte)((uint)iVar156 >> 0x10),
                                                                   CONCAT11((byte)((uint)fVar77 >> 8
                                                                                  ) & ~(byte)((uint)
                                                  iVar156 >> 8),SUB41(fVar77,0) & ~(byte)iVar156))))
                                       )));
        *(ulong *)(pfVar40 + 0x10) =
             CONCAT17((byte)((uint)fVar125 >> 0x18) & ~(byte)((uint)iVar155 >> 0x18),
                      CONCAT16((byte)((uint)fVar125 >> 0x10) & ~(byte)((uint)iVar155 >> 0x10),
                               CONCAT15((byte)((uint)fVar125 >> 8) & ~(byte)((uint)iVar155 >> 8),
                                        CONCAT14(SUB41(fVar125,0) & ~(byte)iVar155,
                                                 CONCAT13((byte)((uint)fVar121 >> 0x18) &
                                                          ~(byte)((uint)iVar128 >> 0x18),
                                                          CONCAT12((byte)((uint)fVar121 >> 0x10) &
                                                                   ~(byte)((uint)iVar128 >> 0x10),
                                                                   CONCAT11((byte)((uint)fVar121 >>
                                                                                  8) &
                                                                            ~(byte)((uint)iVar128 >>
                                                                                   8),
                                                                            SUB41(fVar121,0) &
                                                                            ~(byte)iVar128)))))));
        if (iVar127 == 1) {
          lVar35 = *(long *)pfVar39;
          *(undefined8 *)(lVar35 + 0x48) = *(undefined8 *)(pfVar40 + 0x12);
          *(undefined8 *)(lVar35 + 0x40) = *(undefined8 *)pfVar36;
        }
      }
      FUN_71005e4220(param_1,&local_70);
      lVar3 = DAT_7103a66ef0;
      fVar77 = *(float *)(param_3 + 0x38);
      fVar121 = *(float *)(param_3 + 0x3c);
      fVar125 = *(float *)(param_2 + 0x90);
      fVar124 = *(float *)(param_3 + 0x48);
      fVar199 = (float)NEON_ucvtf(*DAT_7103a66ee8);
      fVar199 = fVar199 / *DAT_7103a67640;
      uVar34 = (ulong)(fVar199 *
                      ((float)local_70 * 360.0 + *(float *)(param_3 + 0x40) * fVar77 * fVar125));
      lVar35 = DAT_7103a66ef0 + (uVar34 >> 0x18 & 0xff) * 0x10;
      uVar37 = (ulong)(fVar199 * (local_70._4_4_ * 360.0 + fVar125 * 0.5));
      lVar2 = DAT_7103a66ef0 + (uVar37 >> 0x18 & 0xff) * 0x10;
      uVar38 = (ulong)(fVar199 *
                      (local_70._4_4_ * 360.0 + fVar77 * *(float *)(param_3 + 0x44) * fVar125));
      pfVar40[4] = *(float *)(lVar35 + 4) +
                   (float)((uint)uVar34 & 0xffffff) * 5.9604645e-08 * *(float *)(lVar35 + 0xc) +
                   *(float *)(lVar2 + 4) +
                   (float)((uint)uVar37 & 0xffffff) * 5.9604645e-08 * *(float *)(lVar2 + 0xc);
      lVar35 = lVar3 + (uVar38 >> 0x18 & 0xff) * 0x10;
      uVar34 = (ulong)(fVar199 * ((float)uStack_68 * 360.0 + fVar125 * 0.5));
      lVar2 = lVar3 + (uVar34 >> 0x18 & 0xff) * 0x10;
      pfVar40[5] = *(float *)(lVar35 + 4) +
                   (float)((uint)uVar38 & 0xffffff) * 5.9604645e-08 * *(float *)(lVar35 + 0xc) +
                   *(float *)(lVar2 + 4) +
                   (float)((uint)uVar34 & 0xffffff) * 5.9604645e-08 * *(float *)(lVar2 + 0xc);
      uVar34 = (ulong)(fVar199 * ((float)uStack_68 * 360.0 + fVar77 * fVar124 * fVar125));
      lVar35 = lVar3 + (uVar34 >> 0x18 & 0xff) * 0x10;
      uVar37 = (ulong)(fVar199 * (uStack_68._4_4_ * 360.0 + fVar125 * 0.5));
      lVar3 = lVar3 + (uVar37 >> 0x18 & 0xff) * 0x10;
      fVar125 = pfVar40[5] * fVar121;
      fVar77 = fVar121 * 0.0;
      *(ulong *)(pfVar40 + 6) =
           CONCAT17((char)((uint)fVar77 >> 0x18),
                    CONCAT16((char)((uint)fVar77 >> 0x10),
                             CONCAT15((char)((uint)fVar77 >> 8),
                                      CONCAT14(SUB41(fVar77,0),
                                               (*(float *)(lVar35 + 4) +
                                                (float)((uint)uVar34 & 0xffffff) * 5.9604645e-08 *
                                                *(float *)(lVar35 + 0xc) +
                                               *(float *)(lVar3 + 4) +
                                               (float)((uint)uVar37 & 0xffffff) * 5.9604645e-08 *
                                               *(float *)(lVar3 + 0xc)) * fVar121))));
      *(ulong *)(pfVar40 + 4) =
           CONCAT17((char)((uint)fVar125 >> 0x18),
                    CONCAT16((char)((uint)fVar125 >> 0x10),
                             CONCAT15((char)((uint)fVar125 >> 8),
                                      CONCAT14(SUB41(fVar125,0),pfVar40[4] * fVar121))));
      iVar127 = *(int *)(param_2 + 0x80);
      if ((float)iVar127 < *(float *)(param_3 + 0xc) + -1.0) {
        iVar127 = iVar127 + 1;
        *(int *)(param_2 + 0x80) = iVar127;
      }
      if (iVar127 < 2) {
        if (param_3[1] == 0) {
          FUN_71005e3efc(param_1,(undefined8 *)(pfVar40 + 8));
        }
        else {
          FUN_71005e3ed4(param_1,(undefined8 *)(pfVar40 + 8));
        }
        pfVar43 = pfVar40 + 8;
        uVar80 = *(undefined8 *)(pfVar40 + 10);
        uVar60 = (undefined1)uVar80;
        uVar62 = (undefined1)((ulong)uVar80 >> 8);
        uVar64 = (undefined1)((ulong)uVar80 >> 0x10);
        uVar66 = (undefined1)((ulong)uVar80 >> 0x18);
        uVar68 = (undefined1)((ulong)uVar80 >> 0x20);
        uVar70 = (undefined1)((ulong)uVar80 >> 0x28);
        uVar72 = (undefined1)((ulong)uVar80 >> 0x30);
        uVar74 = (undefined1)((ulong)uVar80 >> 0x38);
        uVar162 = *(undefined8 *)pfVar43;
        uVar44 = (undefined1)uVar162;
        uVar46 = (undefined1)((ulong)uVar162 >> 8);
        uVar48 = (undefined1)((ulong)uVar162 >> 0x10);
        uVar50 = (undefined1)((ulong)uVar162 >> 0x18);
        uVar52 = (undefined1)((ulong)uVar162 >> 0x20);
        uVar54 = (undefined1)((ulong)uVar162 >> 0x28);
        uVar56 = (undefined1)((ulong)uVar162 >> 0x30);
        uVar58 = (undefined1)((ulong)uVar162 >> 0x38);
        auVar110._0_4_ = (float)uVar162 * (float)uVar162;
        fVar121 = (float)((ulong)uVar162 >> 0x20);
        auVar110._4_4_ = fVar121 * fVar121;
        auVar110._8_4_ = (float)uVar80 * (float)uVar80;
        fVar121 = (float)((ulong)uVar80 >> 0x20);
        auVar110._12_4_ = fVar121 * fVar121;
        auVar136 = NEON_ext(auVar110,auVar110,8,1);
        fVar125 = auVar136._0_4_ + auVar110._0_4_;
        fVar77 = auVar136._4_4_ + auVar110._4_4_;
        fVar121 = fVar125 + fVar77;
        uVar162 = CONCAT44(fVar125 + fVar77,fVar121);
        if (fVar121 <= 0.0) {
          lVar35 = *(long *)(param_1 + 0x10);
          fVar121 = (float)*(undefined8 *)(lVar35 + 0x130) - *(float *)(lVar35 + 0x480);
          uVar44 = SUB41(fVar121,0);
          uVar46 = (undefined1)((uint)fVar121 >> 8);
          uVar48 = (undefined1)((uint)fVar121 >> 0x10);
          uVar50 = (undefined1)((uint)fVar121 >> 0x18);
          fVar125 = (float)((ulong)*(undefined8 *)(lVar35 + 0x130) >> 0x20) -
                    *(float *)(lVar35 + 0x484);
          uVar52 = SUB41(fVar125,0);
          uVar54 = (undefined1)((uint)fVar125 >> 8);
          uVar56 = (undefined1)((uint)fVar125 >> 0x10);
          uVar58 = (undefined1)((uint)fVar125 >> 0x18);
          fVar77 = (float)*(undefined8 *)(lVar35 + 0x138) - *(float *)(lVar35 + 0x488);
          uVar60 = SUB41(fVar77,0);
          uVar62 = (undefined1)((uint)fVar77 >> 8);
          uVar64 = (undefined1)((uint)fVar77 >> 0x10);
          uVar66 = (undefined1)((uint)fVar77 >> 0x18);
          fVar124 = (float)((ulong)*(undefined8 *)(lVar35 + 0x138) >> 0x20) -
                    *(float *)(lVar35 + 0x48c);
          uVar68 = SUB41(fVar124,0);
          uVar70 = (undefined1)((uint)fVar124 >> 8);
          uVar72 = (undefined1)((uint)fVar124 >> 0x10);
          uVar74 = (undefined1)((uint)fVar124 >> 0x18);
          auVar111._0_4_ = fVar121 * fVar121;
          auVar111._4_4_ = fVar125 * fVar125;
          auVar111._8_4_ = fVar77 * fVar77;
          auVar111._12_4_ = fVar124 * fVar124;
          auVar136 = NEON_ext(auVar111,auVar111,8,1);
          fVar125 = auVar136._0_4_ + auVar111._0_4_;
          fVar77 = auVar136._4_4_ + auVar111._4_4_;
          fVar121 = fVar125 + fVar77;
          uVar162 = CONCAT44(fVar125 + fVar77,fVar121);
          if (fVar121 <= 0.0) {
            uVar162 = *(undefined8 *)(lVar35 + 0x110);
            *(undefined8 *)(pfVar40 + 10) = *(undefined8 *)(lVar35 + 0x118);
            *(undefined8 *)pfVar43 = uVar162;
            goto LAB_71005ee78c;
          }
        }
        auVar112._8_8_ = uVar162;
        auVar112._0_8_ = uVar162;
        auVar136 = NEON_frsqrte(auVar112,4);
        fVar121 = (float)uVar162;
        auVar189._0_4_ = fVar121 * auVar136._0_4_;
        fVar125 = (float)((ulong)uVar162 >> 0x20);
        auVar189._4_4_ = fVar125 * auVar136._4_4_;
        auVar189._8_4_ = fVar121 * auVar136._8_4_;
        auVar189._12_4_ = fVar125 * auVar136._12_4_;
        auVar214 = NEON_frsqrts(auVar136,auVar189,4);
        auVar148._0_4_ = auVar136._0_4_ * auVar214._0_4_;
        auVar148._4_4_ = auVar136._4_4_ * auVar214._4_4_;
        auVar148._8_4_ = auVar136._8_4_ * auVar214._8_4_;
        auVar148._12_4_ = auVar136._12_4_ * auVar214._12_4_;
        auVar190._0_4_ = fVar121 * auVar148._0_4_;
        auVar190._4_4_ = fVar125 * auVar148._4_4_;
        auVar190._8_4_ = fVar121 * auVar148._8_4_;
        auVar190._12_4_ = fVar125 * auVar148._12_4_;
        iVar127 = -(uint)(fVar121 == 0.0);
        iVar128 = -(uint)(fVar125 == 0.0);
        iVar155 = -(uint)(fVar121 == 0.0);
        iVar156 = -(uint)(fVar125 == 0.0);
        auVar136 = NEON_frsqrts(auVar148,auVar190,4);
        fVar121 = (float)CONCAT13(uVar50,CONCAT12(uVar48,CONCAT11(uVar46,uVar44))) *
                  auVar148._0_4_ * auVar136._0_4_;
        fVar125 = (float)CONCAT13(uVar58,CONCAT12(uVar56,CONCAT11(uVar54,uVar52))) *
                  auVar148._4_4_ * auVar136._4_4_;
        fVar77 = (float)CONCAT13(uVar66,CONCAT12(uVar64,CONCAT11(uVar62,uVar60))) *
                 auVar148._8_4_ * auVar136._8_4_;
        fVar124 = (float)CONCAT13(uVar74,CONCAT12(uVar72,CONCAT11(uVar70,uVar68))) *
                  auVar148._12_4_ * auVar136._12_4_;
        *(ulong *)(pfVar40 + 10) =
             CONCAT17((byte)((uint)fVar124 >> 0x18) & ~(byte)((uint)iVar156 >> 0x18),
                      CONCAT16((byte)((uint)fVar124 >> 0x10) & ~(byte)((uint)iVar156 >> 0x10),
                               CONCAT15((byte)((uint)fVar124 >> 8) & ~(byte)((uint)iVar156 >> 8),
                                        CONCAT14(SUB41(fVar124,0) & ~(byte)iVar156,
                                                 CONCAT13((byte)((uint)fVar77 >> 0x18) &
                                                          ~(byte)((uint)iVar155 >> 0x18),
                                                          CONCAT12((byte)((uint)fVar77 >> 0x10) &
                                                                   ~(byte)((uint)iVar155 >> 0x10),
                                                                   CONCAT11((byte)((uint)fVar77 >> 8
                                                                                  ) & ~(byte)((uint)
                                                  iVar155 >> 8),SUB41(fVar77,0) & ~(byte)iVar155))))
                                       )));
        *(ulong *)(pfVar40 + 8) =
             CONCAT17((byte)((uint)fVar125 >> 0x18) & ~(byte)((uint)iVar128 >> 0x18),
                      CONCAT16((byte)((uint)fVar125 >> 0x10) & ~(byte)((uint)iVar128 >> 0x10),
                               CONCAT15((byte)((uint)fVar125 >> 8) & ~(byte)((uint)iVar128 >> 8),
                                        CONCAT14(SUB41(fVar125,0) & ~(byte)iVar128,
                                                 CONCAT13((byte)((uint)fVar121 >> 0x18) &
                                                          ~(byte)((uint)iVar127 >> 0x18),
                                                          CONCAT12((byte)((uint)fVar121 >> 0x10) &
                                                                   ~(byte)((uint)iVar127 >> 0x10),
                                                                   CONCAT11((byte)((uint)fVar121 >>
                                                                                  8) &
                                                                            ~(byte)((uint)iVar127 >>
                                                                                   8),
                                                                            SUB41(fVar121,0) &
                                                                            ~(byte)iVar127)))))));
        *(undefined8 *)(pfVar40 + 0xc) = *(undefined8 *)pfVar43;
        *(undefined8 *)(pfVar40 + 0xe) = *(undefined8 *)(pfVar40 + 10);
      }
      else {
        fVar121 = (float)*(undefined8 *)pfVar40 - *pfVar43;
        fVar125 = (float)((ulong)*(undefined8 *)pfVar40 >> 0x20) - pfVar43[1];
        fVar77 = (float)*(undefined8 *)(pfVar40 + 2) - pfVar43[2];
        fVar124 = (float)((ulong)*(undefined8 *)(pfVar40 + 2) >> 0x20) - pfVar43[3];
        pfVar36 = pfVar40 + 8;
        *(ulong *)(pfVar40 + 10) =
             CONCAT17((char)((uint)fVar124 >> 0x18),
                      CONCAT16((char)((uint)fVar124 >> 0x10),
                               CONCAT15((char)((uint)fVar124 >> 8),CONCAT14(SUB41(fVar124,0),fVar77)
                                       )));
        *(ulong *)pfVar36 =
             CONCAT17((char)((uint)fVar125 >> 0x18),
                      CONCAT16((char)((uint)fVar125 >> 0x10),
                               CONCAT15((char)((uint)fVar125 >> 8),
                                        CONCAT14(SUB41(fVar125,0),fVar121))));
        fVar121 = fVar121 * fVar121;
        fVar125 = fVar125 * fVar125;
        uVar44 = (undefined1)((uint)fVar125 >> 8);
        uVar46 = (undefined1)((uint)fVar125 >> 0x10);
        uVar48 = (undefined1)((uint)fVar125 >> 0x18);
        fVar77 = fVar77 * fVar77;
        uVar50 = (undefined1)((uint)fVar77 >> 8);
        uVar52 = (undefined1)((uint)fVar77 >> 0x10);
        uVar54 = (undefined1)((uint)fVar77 >> 0x18);
        fVar124 = fVar124 * fVar124;
        uVar56 = (undefined1)((uint)fVar124 >> 8);
        uVar58 = (undefined1)((uint)fVar124 >> 0x10);
        uVar60 = (undefined1)((uint)fVar124 >> 0x18);
        auVar28[4] = SUB41(fVar125,0);
        auVar28._0_4_ = fVar121;
        auVar28[5] = uVar44;
        auVar28[6] = uVar46;
        auVar28[7] = uVar48;
        auVar28[8] = SUB41(fVar77,0);
        auVar28[9] = uVar50;
        auVar28[10] = uVar52;
        auVar28[0xb] = uVar54;
        auVar28[0xc] = SUB41(fVar124,0);
        auVar28[0xd] = uVar56;
        auVar28[0xe] = uVar58;
        auVar28[0xf] = uVar60;
        auVar29[4] = SUB41(fVar125,0);
        auVar29._0_4_ = fVar121;
        auVar29[5] = uVar44;
        auVar29[6] = uVar46;
        auVar29[7] = uVar48;
        auVar29[8] = SUB41(fVar77,0);
        auVar29[9] = uVar50;
        auVar29[10] = uVar52;
        auVar29[0xb] = uVar54;
        auVar29[0xc] = SUB41(fVar124,0);
        auVar29[0xd] = uVar56;
        auVar29[0xe] = uVar58;
        auVar29[0xf] = uVar60;
        auVar136 = NEON_ext(auVar28,auVar29,8,1);
        if (1e-05 <= auVar136._0_4_ + fVar121 + auVar136._4_4_ + fVar125) {
          iVar127 = *(int *)(param_2 + 0x80);
        }
        else {
          *(undefined8 *)(pfVar40 + 10) = *(undefined8 *)(pfVar43 + 10);
          *(undefined8 *)pfVar36 = *(undefined8 *)(pfVar43 + 8);
          iVar127 = *(int *)(param_2 + 0x80);
        }
        if (iVar127 == 2) {
          *(undefined8 *)(pfVar43 + 10) = *(undefined8 *)(pfVar40 + 10);
          *(undefined8 *)(pfVar43 + 8) = *(undefined8 *)pfVar36;
          iVar127 = *(int *)(param_2 + 0x80);
        }
        bVar75 = 0;
        bVar73 = 0;
        bVar71 = 0;
        bVar69 = 0;
        bVar67 = 0;
        bVar65 = 0;
        bVar63 = 0;
        bVar61 = 0;
        bVar59 = 0;
        bVar57 = 0;
        bVar55 = 0;
        bVar53 = 0;
        bVar51 = 0;
        bVar49 = 0;
        bVar47 = 0;
        bVar45 = 0;
        if (0 < iVar127) {
          bVar75 = 0;
          bVar73 = 0;
          bVar71 = 0;
          bVar69 = 0;
          bVar67 = 0;
          bVar65 = 0;
          bVar63 = 0;
          bVar61 = 0;
          bVar59 = 0;
          bVar57 = 0;
          bVar55 = 0;
          bVar53 = 0;
          bVar51 = 0;
          bVar49 = 0;
          bVar47 = 0;
          bVar45 = 0;
          pfVar36 = pfVar40;
          do {
            fVar125 = (float)iVar127;
            iVar127 = iVar127 + -1;
            pfVar1 = pfVar36 + 8;
            pfVar31 = pfVar36 + 9;
            pfVar32 = pfVar36 + 10;
            pfVar33 = pfVar36 + 0xb;
            pfVar36 = *(float **)(pfVar36 + 0x14);
            fVar121 = (float)CONCAT13(bVar51,CONCAT12(bVar49,CONCAT11(bVar47,bVar45))) +
                      *pfVar1 * fVar125;
            bVar45 = SUB41(fVar121,0);
            bVar47 = (byte)((uint)fVar121 >> 8);
            bVar49 = (byte)((uint)fVar121 >> 0x10);
            bVar51 = (byte)((uint)fVar121 >> 0x18);
            fVar121 = (float)CONCAT13(bVar59,CONCAT12(bVar57,CONCAT11(bVar55,bVar53))) +
                      *pfVar31 * fVar125;
            bVar53 = SUB41(fVar121,0);
            bVar55 = (byte)((uint)fVar121 >> 8);
            bVar57 = (byte)((uint)fVar121 >> 0x10);
            bVar59 = (byte)((uint)fVar121 >> 0x18);
            fVar121 = (float)CONCAT13(bVar67,CONCAT12(bVar65,CONCAT11(bVar63,bVar61))) +
                      *pfVar32 * fVar125;
            bVar61 = SUB41(fVar121,0);
            bVar63 = (byte)((uint)fVar121 >> 8);
            bVar65 = (byte)((uint)fVar121 >> 0x10);
            bVar67 = (byte)((uint)fVar121 >> 0x18);
            fVar121 = (float)CONCAT13(bVar75,CONCAT12(bVar73,CONCAT11(bVar71,bVar69))) +
                      *pfVar33 * fVar125;
            bVar69 = SUB41(fVar121,0);
            bVar71 = (byte)((uint)fVar121 >> 8);
            bVar73 = (byte)((uint)fVar121 >> 0x10);
            bVar75 = (byte)((uint)fVar121 >> 0x18);
          } while (iVar127 != 0);
        }
        auVar108._0_4_ =
             (float)CONCAT13(bVar51,CONCAT12(bVar49,CONCAT11(bVar47,bVar45))) *
             (float)CONCAT13(bVar51,CONCAT12(bVar49,CONCAT11(bVar47,bVar45)));
        auVar108._4_4_ =
             (float)CONCAT13(bVar59,CONCAT12(bVar57,CONCAT11(bVar55,bVar53))) *
             (float)CONCAT13(bVar59,CONCAT12(bVar57,CONCAT11(bVar55,bVar53)));
        auVar108._8_4_ =
             (float)CONCAT13(bVar67,CONCAT12(bVar65,CONCAT11(bVar63,bVar61))) *
             (float)CONCAT13(bVar67,CONCAT12(bVar65,CONCAT11(bVar63,bVar61)));
        auVar108._12_4_ =
             (float)CONCAT13(bVar75,CONCAT12(bVar73,CONCAT11(bVar71,bVar69))) *
             (float)CONCAT13(bVar75,CONCAT12(bVar73,CONCAT11(bVar71,bVar69)));
        auVar136 = NEON_ext(auVar108,auVar108,8,1);
        fVar125 = auVar136._0_4_ + auVar108._0_4_;
        fVar77 = auVar136._4_4_ + auVar108._4_4_;
        fVar121 = fVar125 + fVar77;
        fVar125 = fVar125 + fVar77;
        if (0.0 < fVar121) {
          auVar109._8_8_ = CONCAT44(fVar125,fVar121);
          auVar109._0_8_ = CONCAT44(fVar125,fVar121);
          auVar136 = NEON_frsqrte(auVar109,4);
          auVar187._0_4_ = fVar121 * auVar136._0_4_;
          auVar187._4_4_ = fVar125 * auVar136._4_4_;
          auVar187._8_4_ = fVar121 * auVar136._8_4_;
          auVar187._12_4_ = fVar125 * auVar136._12_4_;
          auVar214 = NEON_frsqrts(auVar136,auVar187,4);
          auVar147._0_4_ = auVar136._0_4_ * auVar214._0_4_;
          auVar147._4_4_ = auVar136._4_4_ * auVar214._4_4_;
          auVar147._8_4_ = auVar136._8_4_ * auVar214._8_4_;
          auVar147._12_4_ = auVar136._12_4_ * auVar214._12_4_;
          auVar188._0_4_ = fVar121 * auVar147._0_4_;
          auVar188._4_4_ = fVar125 * auVar147._4_4_;
          auVar188._8_4_ = fVar121 * auVar147._8_4_;
          auVar188._12_4_ = fVar125 * auVar147._12_4_;
          iVar127 = -(uint)(fVar121 == 0.0);
          iVar128 = -(uint)(fVar125 == 0.0);
          iVar155 = -(uint)(fVar121 == 0.0);
          iVar156 = -(uint)(fVar125 == 0.0);
          auVar136 = NEON_frsqrts(auVar147,auVar188,4);
          fVar121 = (float)CONCAT13(bVar51,CONCAT12(bVar49,CONCAT11(bVar47,bVar45))) *
                    auVar147._0_4_ * auVar136._0_4_;
          fVar125 = (float)CONCAT13(bVar59,CONCAT12(bVar57,CONCAT11(bVar55,bVar53))) *
                    auVar147._4_4_ * auVar136._4_4_;
          fVar77 = (float)CONCAT13(bVar67,CONCAT12(bVar65,CONCAT11(bVar63,bVar61))) *
                   auVar147._8_4_ * auVar136._8_4_;
          fVar124 = (float)CONCAT13(bVar75,CONCAT12(bVar73,CONCAT11(bVar71,bVar69))) *
                    auVar147._12_4_ * auVar136._12_4_;
          bVar45 = SUB41(fVar121,0) & ~(byte)iVar127;
          bVar47 = (byte)((uint)fVar121 >> 8) & ~(byte)((uint)iVar127 >> 8);
          bVar49 = (byte)((uint)fVar121 >> 0x10) & ~(byte)((uint)iVar127 >> 0x10);
          bVar51 = (byte)((uint)fVar121 >> 0x18) & ~(byte)((uint)iVar127 >> 0x18);
          bVar53 = SUB41(fVar125,0) & ~(byte)iVar128;
          bVar55 = (byte)((uint)fVar125 >> 8) & ~(byte)((uint)iVar128 >> 8);
          bVar57 = (byte)((uint)fVar125 >> 0x10) & ~(byte)((uint)iVar128 >> 0x10);
          bVar59 = (byte)((uint)fVar125 >> 0x18) & ~(byte)((uint)iVar128 >> 0x18);
          bVar61 = SUB41(fVar77,0) & ~(byte)iVar155;
          bVar63 = (byte)((uint)fVar77 >> 8) & ~(byte)((uint)iVar155 >> 8);
          bVar65 = (byte)((uint)fVar77 >> 0x10) & ~(byte)((uint)iVar155 >> 0x10);
          bVar67 = (byte)((uint)fVar77 >> 0x18) & ~(byte)((uint)iVar155 >> 0x18);
          bVar69 = SUB41(fVar124,0) & ~(byte)iVar156;
          bVar71 = (byte)((uint)fVar124 >> 8) & ~(byte)((uint)iVar156 >> 8);
          bVar73 = (byte)((uint)fVar124 >> 0x10) & ~(byte)((uint)iVar156 >> 0x10);
          bVar75 = (byte)((uint)fVar124 >> 0x18) & ~(byte)((uint)iVar156 >> 0x18);
        }
        *(ulong *)(pfVar40 + 0xe) =
             CONCAT17(bVar75,CONCAT16(bVar73,CONCAT15(bVar71,CONCAT14(bVar69,CONCAT13(bVar67,
                                                  CONCAT12(bVar65,CONCAT11(bVar63,bVar61)))))));
        *(ulong *)(pfVar40 + 0xc) =
             CONCAT17(bVar59,CONCAT16(bVar57,CONCAT15(bVar55,CONCAT14(bVar53,CONCAT13(bVar51,
                                                  CONCAT12(bVar49,CONCAT11(bVar47,bVar45)))))));
        if (*(int *)(param_2 + 0x80) == 2) {
          *(undefined8 *)(pfVar43 + 0xe) = *(undefined8 *)(pfVar40 + 0xe);
          *(undefined8 *)(pfVar43 + 0xc) = *(undefined8 *)(pfVar40 + 0xc);
        }
      }
LAB_71005ee78c:
      fVar121 = (float)*(undefined8 *)(pfVar40 + 0xc);
      auVar113._0_4_ = fVar121 * fVar121;
      fVar125 = (float)((ulong)*(undefined8 *)(pfVar40 + 0xc) >> 0x20);
      auVar113._4_4_ = fVar125 * fVar125;
      fVar77 = (float)*(undefined8 *)(pfVar40 + 0xe);
      auVar113._8_4_ = fVar77 * fVar77;
      fVar124 = (float)((ulong)*(undefined8 *)(pfVar40 + 0xe) >> 0x20);
      auVar113._12_4_ = fVar124 * fVar124;
      auVar136 = NEON_ext(auVar113,auVar113,8,1);
      fVar78 = auVar136._0_4_ + auVar113._0_4_;
      fVar120 = auVar136._4_4_ + auVar113._4_4_;
      fVar199 = fVar78 + fVar120;
      fVar78 = fVar78 + fVar120;
      if (fVar199 <= 0.0) {
        pfVar40[0xe] = 0.0;
        pfVar40[0xf] = 0.0;
        pfVar40[0xc] = 0.0;
        pfVar40[0xd] = 1.0;
        iVar127 = *(int *)(param_2 + 0x80);
      }
      else {
        auVar114._8_8_ = CONCAT44(fVar78,fVar199);
        auVar114._0_8_ = CONCAT44(fVar78,fVar199);
        auVar136 = NEON_frsqrte(auVar114,4);
        auVar191._0_4_ = fVar199 * auVar136._0_4_;
        auVar191._4_4_ = fVar78 * auVar136._4_4_;
        auVar191._8_4_ = fVar199 * auVar136._8_4_;
        auVar191._12_4_ = fVar78 * auVar136._12_4_;
        auVar214 = NEON_frsqrts(auVar136,auVar191,4);
        auVar149._0_4_ = auVar136._0_4_ * auVar214._0_4_;
        auVar149._4_4_ = auVar136._4_4_ * auVar214._4_4_;
        auVar149._8_4_ = auVar136._8_4_ * auVar214._8_4_;
        auVar149._12_4_ = auVar136._12_4_ * auVar214._12_4_;
        auVar192._0_4_ = fVar199 * auVar149._0_4_;
        auVar192._4_4_ = fVar78 * auVar149._4_4_;
        auVar192._8_4_ = fVar199 * auVar149._8_4_;
        auVar192._12_4_ = fVar78 * auVar149._12_4_;
        iVar127 = -(uint)(fVar199 == 0.0);
        iVar128 = -(uint)(fVar78 == 0.0);
        iVar155 = -(uint)(fVar199 == 0.0);
        iVar156 = -(uint)(fVar78 == 0.0);
        auVar136 = NEON_frsqrts(auVar149,auVar192,4);
        fVar121 = fVar121 * auVar149._0_4_ * auVar136._0_4_;
        fVar125 = fVar125 * auVar149._4_4_ * auVar136._4_4_;
        fVar77 = fVar77 * auVar149._8_4_ * auVar136._8_4_;
        fVar124 = fVar124 * auVar149._12_4_ * auVar136._12_4_;
        *(ulong *)(pfVar40 + 0xe) =
             CONCAT17((byte)((uint)fVar124 >> 0x18) & ~(byte)((uint)iVar156 >> 0x18),
                      CONCAT16((byte)((uint)fVar124 >> 0x10) & ~(byte)((uint)iVar156 >> 0x10),
                               CONCAT15((byte)((uint)fVar124 >> 8) & ~(byte)((uint)iVar156 >> 8),
                                        CONCAT14(SUB41(fVar124,0) & ~(byte)iVar156,
                                                 CONCAT13((byte)((uint)fVar77 >> 0x18) &
                                                          ~(byte)((uint)iVar155 >> 0x18),
                                                          CONCAT12((byte)((uint)fVar77 >> 0x10) &
                                                                   ~(byte)((uint)iVar155 >> 0x10),
                                                                   CONCAT11((byte)((uint)fVar77 >> 8
                                                                                  ) & ~(byte)((uint)
                                                  iVar155 >> 8),SUB41(fVar77,0) & ~(byte)iVar155))))
                                       )));
        *(ulong *)(pfVar40 + 0xc) =
             CONCAT17((byte)((uint)fVar125 >> 0x18) & ~(byte)((uint)iVar128 >> 0x18),
                      CONCAT16((byte)((uint)fVar125 >> 0x10) & ~(byte)((uint)iVar128 >> 0x10),
                               CONCAT15((byte)((uint)fVar125 >> 8) & ~(byte)((uint)iVar128 >> 8),
                                        CONCAT14(SUB41(fVar125,0) & ~(byte)iVar128,
                                                 CONCAT13((byte)((uint)fVar121 >> 0x18) &
                                                          ~(byte)((uint)iVar127 >> 0x18),
                                                          CONCAT12((byte)((uint)fVar121 >> 0x10) &
                                                                   ~(byte)((uint)iVar127 >> 0x10),
                                                                   CONCAT11((byte)((uint)fVar121 >>
                                                                                  8) &
                                                                            ~(byte)((uint)iVar127 >>
                                                                                   8),
                                                                            SUB41(fVar121,0) &
                                                                            ~(byte)iVar127)))))));
        iVar127 = *(int *)(param_2 + 0x80);
      }
      if (1 < iVar127) {
        fVar125 = fVar76 * fVar79;
        fVar121 = *(float *)(param_3 + 0x2c);
        fVar77 = *(float *)(param_3 + 0x30);
        fVar124 = *(float *)(param_3 + 0x34);
        iVar128 = 1;
        do {
          pfVar40 = *(float **)pfVar39;
          iVar128 = iVar128 + 1;
          pfVar39 = pfVar40 + 0x14;
          fVar199 = fVar125 * fVar121 + pfVar40[4] * fVar79;
          fVar78 = fVar125 * fVar77 + pfVar40[5] * fVar79;
          fVar120 = fVar125 * fVar124 + pfVar40[6] * fVar79;
          fVar122 = pfVar40[7] * fVar79 + 0.0;
          pfVar40[4] = pfVar40[2] + fVar120 * fVar76;
          pfVar40[5] = pfVar40[3] + fVar122 * fVar76;
          *pfVar40 = *pfVar40 + fVar199 * fVar76;
          pfVar40[1] = pfVar40[1] + fVar78 * fVar76;
          pfVar40[8] = fVar120;
          pfVar40[9] = fVar122;
          pfVar40[4] = fVar199;
          pfVar40[5] = fVar78;
          iVar127 = *(int *)(param_2 + 0x80);
        } while (iVar128 < iVar127);
      }
    }
  }
  uVar50 = 0;
  uVar48 = 0;
  uVar46 = 0;
  uVar44 = 0;
  if (1 < iVar127) {
    uVar50 = 0;
    uVar48 = 0;
    uVar46 = 0;
    uVar44 = 0;
                    // WARNING: Read-only address (ram,0x007102ec03b0) is written
    iVar127 = iVar127 + -1;
    pfVar39 = *(float **)(*(long *)(param_2 + 0x68) + 0x50);
    fVar79 = *pfVar39;
    fVar121 = pfVar39[1];
    fVar76 = pfVar39[2];
    fVar125 = pfVar39[3];
    do {
      pfVar39 = *(float **)(pfVar39 + 0x14);
      iVar127 = iVar127 + -1;
      fVar79 = fVar79 - *pfVar39;
      fVar121 = fVar121 - pfVar39[1];
      fVar76 = fVar76 - pfVar39[2];
      fVar125 = fVar125 - pfVar39[3];
      auVar115._0_4_ = fVar79 * fVar79;
      auVar115._4_4_ = fVar121 * fVar121;
      auVar115._8_4_ = fVar76 * fVar76;
      auVar115._12_4_ = fVar125 * fVar125;
      auVar136 = NEON_ext(auVar115,auVar115,8,1);
      fVar79 = (float)CONCAT13(uVar50,CONCAT12(uVar48,CONCAT11(uVar46,uVar44))) +
               SQRT(auVar136._0_4_ + auVar115._0_4_ + auVar136._4_4_ + auVar115._4_4_);
      uVar44 = SUB41(fVar79,0);
      uVar46 = (undefined1)((uint)fVar79 >> 8);
      uVar48 = (undefined1)((uint)fVar79 >> 0x10);
      uVar50 = (undefined1)((uint)fVar79 >> 0x18);
      fVar79 = *pfVar39;
      fVar121 = pfVar39[1];
      fVar76 = pfVar39[2];
      fVar125 = pfVar39[3];
    } while (iVar127 != 0);
  }
LAB_71005eebc0:
  *(uint *)(param_2 + 0x9c) = CONCAT13(uVar50,CONCAT12(uVar48,CONCAT11(uVar46,uVar44)));
  return;
}



void FUN_71005eefa8(float param_1,float *param_2,undefined8 *param_3,undefined8 *param_4,int param_5
                   ,int param_6)

{
  undefined8 *puVar1;
  float *pfVar2;
  float *pfVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  float fVar8;
  float fVar9;
  undefined1 auVar10 [16];
  float fVar11;
  float fVar12;
  undefined8 uVar13;
  undefined8 uVar14;
  undefined8 local_50;
  undefined8 uStack_48;
  undefined8 local_40;
  undefined8 uStack_38;
  undefined8 local_30;
  undefined8 uStack_28;
  undefined8 local_20;
  undefined8 local_18;
  
  if (param_5 == 0) {
    local_20 = *param_4;
    local_18 = param_4[1];
    pfVar2 = (float *)param_4[10];
    fVar12 = 1.0 - param_1;
    pfVar3 = *(float **)(pfVar2 + 0x14);
    local_30 = *(undefined8 *)pfVar2;
    uStack_28 = *(undefined8 *)(pfVar2 + 2);
    fVar6 = (float)*param_4;
    fVar4 = (float)((ulong)*param_4 >> 0x20);
    local_50 = CONCAT44((pfVar3[1] - fVar4) * 0.5,(*pfVar3 - fVar6) * 0.5);
    auVar10 = NEON_fmov(0x3e800000,4);
    local_40 = CONCAT44(((pfVar2[1] - fVar4) +
                        (pfVar2[1] - (float)((ulong)*(undefined8 *)pfVar3 >> 0x20))) * auVar10._4_4_
                        ,((*pfVar2 - fVar6) + (*pfVar2 - (float)*(undefined8 *)pfVar3)) *
                         auVar10._0_4_);
    uStack_38 = CONCAT44(((pfVar2[3] - (float)((ulong)param_4[1] >> 0x20)) +
                         (pfVar2[3] - (float)((ulong)*(undefined8 *)(pfVar3 + 2) >> 0x20))) *
                         auVar10._12_4_,
                         ((pfVar2[2] - (float)param_4[1]) +
                         (pfVar2[2] - (float)*(undefined8 *)(pfVar3 + 2))) * auVar10._8_4_);
    uVar13 = CONCAT44((float)((ulong)param_4[4] >> 0x20) * fVar12 + pfVar2[9] * param_1,
                      (float)param_4[4] * fVar12 + pfVar2[8] * param_1);
    uVar14 = CONCAT44((float)((ulong)param_4[5] >> 0x20) * fVar12 + pfVar2[0xb] * param_1,
                      (float)param_4[5] * fVar12 + pfVar2[10] * param_1);
  }
  else if (param_6 + -1 == param_5) {
    puVar1 = (undefined8 *)param_4[0xb];
    local_30 = *param_4;
    uStack_28 = param_4[1];
    local_20 = *puVar1;
    local_18 = puVar1[1];
    pfVar2 = (float *)puVar1[0xb];
    fVar6 = (float)*param_4;
    fVar4 = (float)((ulong)*param_4 >> 0x20);
    fVar12 = (float)param_4[1];
    fVar5 = (float)((ulong)param_4[1] >> 0x20);
    local_40 = CONCAT44((fVar4 - (float)((ulong)*(undefined8 *)pfVar2 >> 0x20)) * 0.5,
                        (fVar6 - (float)*(undefined8 *)pfVar2) * 0.5);
    uStack_38 = CONCAT44((fVar5 - (float)((ulong)*(undefined8 *)(pfVar2 + 2) >> 0x20)) * 0.5,
                         (fVar12 - (float)*(undefined8 *)(pfVar2 + 2)) * 0.5);
    fVar11 = (float)*puVar1;
    fVar7 = (float)((ulong)*puVar1 >> 0x20);
    fVar8 = (float)puVar1[1];
    fVar9 = (float)((ulong)puVar1[1] >> 0x20);
    auVar10 = NEON_fmov(0xbe800000,4);
    local_50 = CONCAT44(((fVar7 - fVar4) + (fVar7 - pfVar2[1])) * auVar10._4_4_,
                        ((fVar11 - fVar6) + (fVar11 - *pfVar2)) * auVar10._0_4_);
    uStack_48 = CONCAT44(((fVar9 - fVar5) + (fVar9 - pfVar2[3])) * auVar10._12_4_,
                         ((fVar8 - fVar12) + (fVar8 - pfVar2[2])) * auVar10._8_4_);
    uVar13 = CONCAT44(*(float *)((long)puVar1 + 0x24) * 0.0 + *(float *)((long)param_4 + 0x24),
                      *(float *)(puVar1 + 4) * 0.0 + *(float *)(param_4 + 4));
    uVar14 = CONCAT44(*(float *)((long)puVar1 + 0x2c) * 0.0 + *(float *)((long)param_4 + 0x2c),
                      *(float *)(puVar1 + 5) * 0.0 + *(float *)(param_4 + 5));
    param_1 = 1.0;
  }
  else {
    pfVar2 = (float *)param_4[10];
    if (param_6 + -2 == param_5) {
      puVar1 = *(undefined8 **)(pfVar2 + 0x16);
      local_18 = puVar1[1];
      pfVar3 = (float *)puVar1[0xb];
      local_20 = *puVar1;
      local_30 = *(undefined8 *)pfVar2;
      uStack_28 = *(undefined8 *)(pfVar2 + 2);
      local_40 = CONCAT44(((float)((ulong)*(undefined8 *)pfVar2 >> 0x20) - pfVar3[1]) * 0.5,
                          ((float)*(undefined8 *)pfVar2 - *pfVar3) * 0.5);
      uStack_38 = CONCAT44(((float)((ulong)*(undefined8 *)(pfVar2 + 2) >> 0x20) - pfVar3[3]) * 0.5,
                           ((float)*(undefined8 *)(pfVar2 + 2) - pfVar3[2]) * 0.5);
      fVar6 = (float)*puVar1;
      fVar4 = (float)((ulong)*puVar1 >> 0x20);
      fVar12 = (float)puVar1[1];
      fVar5 = (float)((ulong)puVar1[1] >> 0x20);
      fVar11 = 1.0 - param_1;
      auVar10 = NEON_fmov(0xbe800000,4);
      local_50 = CONCAT44(((fVar4 - pfVar2[1]) +
                          (fVar4 - (float)((ulong)*(undefined8 *)pfVar3 >> 0x20))) * auVar10._4_4_,
                          ((fVar6 - *pfVar2) + (fVar6 - (float)*(undefined8 *)pfVar3)) *
                          auVar10._0_4_);
      uStack_48 = CONCAT44(((fVar5 - pfVar2[3]) +
                           (fVar5 - (float)((ulong)*(undefined8 *)(pfVar3 + 2) >> 0x20))) *
                           auVar10._12_4_,
                           ((fVar12 - pfVar2[2]) + (fVar12 - (float)*(undefined8 *)(pfVar3 + 2))) *
                           auVar10._8_4_);
      uVar13 = CONCAT44((float)((ulong)puVar1[4] >> 0x20) * fVar11 + pfVar2[9] * param_1,
                        (float)puVar1[4] * fVar11 + pfVar2[8] * param_1);
      uVar14 = CONCAT44((float)((ulong)puVar1[5] >> 0x20) * fVar11 + pfVar2[0xb] * param_1,
                        (float)puVar1[5] * fVar11 + pfVar2[10] * param_1);
    }
    else {
      local_20 = *param_4;
      local_18 = param_4[1];
      local_30 = *(undefined8 *)pfVar2;
      uStack_28 = *(undefined8 *)(pfVar2 + 2);
      uStack_38 = CONCAT44(((float)((ulong)*(undefined8 *)(pfVar2 + 2) >> 0x20) -
                           *(float *)(param_4[0xb] + 0xc)) * 0.5,
                           ((float)*(undefined8 *)(pfVar2 + 2) - *(float *)(param_4[0xb] + 8)) * 0.5
                          );
      fVar6 = 1.0 - param_1;
      uVar14 = (*(undefined8 **)(pfVar2 + 0x14))[1];
      uVar13 = **(undefined8 **)(pfVar2 + 0x14);
      local_40 = CONCAT44(((float)((ulong)uVar14 >> 0x20) - (float)((ulong)param_4[1] >> 0x20)) *
                          0.5,((float)uVar14 - (float)param_4[1]) * 0.5);
      local_50 = CONCAT44(((float)((ulong)uVar13 >> 0x20) - (float)((ulong)*param_4 >> 0x20)) * 0.5,
                          ((float)uVar13 - (float)*param_4) * 0.5);
      uVar13 = CONCAT44((float)((ulong)param_4[4] >> 0x20) * fVar6 +
                        (float)((ulong)*(undefined8 *)(pfVar2 + 8) >> 0x20) * param_1,
                        (float)param_4[4] * fVar6 + (float)*(undefined8 *)(pfVar2 + 8) * param_1);
      uVar14 = CONCAT44((float)((ulong)param_4[5] >> 0x20) * fVar6 +
                        (float)((ulong)*(undefined8 *)(pfVar2 + 10) >> 0x20) * param_1,
                        (float)param_4[5] * fVar6 + (float)*(undefined8 *)(pfVar2 + 10) * param_1);
    }
  }
  param_3[1] = uVar14;
  *param_3 = uVar13;
  FUN_71005dee80(param_1,param_2,&local_20,&local_40,&local_30,&local_50);
  return;
}



int FUN_71005ef1b0(long param_1)

{
  float fVar1;
  
  fVar1 = *(float *)(param_1 + 0x2c);
  if (fVar1 <= 1.0) {
    fVar1 = 1.0;
  }
  return (int)(*(float *)(*(long *)(*(long *)(param_1 + 0x40) + 0x1f8) + 0xc) * fVar1);
}



int FUN_71005ef1e0(long param_1)

{
  int iVar1;
  long lVar2;
  
  iVar1 = *(int *)(param_1 + 0xa0);
  for (lVar2 = *(long *)(*(long *)(param_1 + 0x3a8) + 0x40); lVar2 != 0;
      lVar2 = *(long *)(lVar2 + 0x78)) {
    iVar1 = iVar1 + 1;
  }
  return iVar1;
}



void FUN_71005ef380(long param_1,long *param_2,byte param_3,undefined8 param_4,long *param_5,
                   int *param_6,undefined8 param_7,undefined8 param_8)

{
  ulong uVar1;
  int iVar2;
  long lVar3;
  long lVar4;
  undefined8 *puVar5;
  long *plVar6;
  long lVar7;
  long lVar8;
  long lVar9;
  long local_70;
  undefined8 uStack_68;
  
  if (param_3 == 8) {
    plVar6 = (long *)0x0;
  }
  else {
    plVar6 = *(long **)(param_2[8] + (ulong)param_3 * 8 + 0x10);
  }
  lVar7 = param_2[0x75];
  lVar8 = *(long *)(param_2[8] + 0x1f8);
  lVar9 = param_5[3];
  uVar1 = FUN_71005ec12c(param_1,param_2,param_3,plVar6,param_4,param_5,param_6);
  if ((uVar1 & 1) != 0) {
    if (*(char *)((long)plVar6 + 0x45) != -1) {
      lVar3 = param_2[0xcb];
      uStack_68 = *(undefined8 *)(lVar3 + 0x10);
      local_70 = ((*(long *)(lVar7 + 0x38) +
                  *(long *)(lVar7 + 0x50) * (ulong)*(byte *)(lVar7 + 0x7c)) -
                 *(long *)(lVar3 + 0x1a0)) + *(long *)(lVar3 + 8);
      FUN_71005fd540(param_1,(int)*(char *)((long)plVar6 + 0x45),0,&local_70,*(long *)(lVar7 + 0x50)
                    );
    }
    for (puVar5 = *(undefined8 **)(lVar7 + 0x40); puVar5 != (undefined8 *)0x0;
        puVar5 = (undefined8 *)puVar5[0xf]) {
      if (0 < *(int *)(puVar5 + 0x11)) {
        FUN_71005ef864(param_1,lVar9,param_2,(long)plVar6,lVar8,lVar7,puVar5,param_7,param_8);
      }
    }
    iVar2 = (int)param_2[0x13];
    if (0 < iVar2) {
      lVar3 = 0;
      lVar4 = 0x18;
      do {
        puVar5 = *(undefined8 **)(param_2[0xc] + lVar4);
        if (((puVar5 != (undefined8 *)0x0) && (*(char *)((long)puVar5 + 0xa4) != '\0')) &&
           (0 < *(int *)(puVar5 + 0x11))) {
          FUN_71005ef864(param_1,lVar9,param_2,(long)plVar6,lVar8,lVar7,puVar5,param_7,param_8);
          iVar2 = (int)param_2[0x13];
        }
        lVar3 = lVar3 + 1;
        lVar4 = lVar4 + 0x20;
      } while (lVar3 < iVar2);
    }
    FUN_71005c9f28((long)param_2,param_1,param_4,param_5);
  }
  return;
}



undefined4 FUN_71005ef540(uint param_1)

{
  if (4 < param_1) {
    param_1 = 5;
  }
  return *(undefined4 *)(&DAT_710329b63c + (ulong)param_1 * 4);
}



bool FUN_71005ef5e0(undefined8 *param_1)

{
  short *psVar1;
  int iVar2;
  uint uVar3;
  ulong uVar4;
  uint uVar5;
  short sVar6;
  int iVar7;
  short sVar8;
  bool bVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  long lVar13;
  ulong uVar14;
  long lVar15;
  long lVar16;
  uint uVar17;
  ulong uVar18;
  
  iVar11 = *(int *)(param_1 + 5);
  lVar16 = *(long *)*param_1;
  lVar13 = *(long *)(((long *)*param_1)[1] + 0x40);
  iVar12 = *(int *)(lVar16 + 0x98);
  lVar15 = *(long *)(*(long *)(lVar16 + 0x40) + 0x1f8);
  uVar5 = *(uint *)(lVar15 + 0x58);
  if (4 < uVar5) {
    uVar5 = 5;
  }
  uVar5 = *(uint *)(&DAT_710329b63c + (ulong)uVar5 * 4);
  iVar2 = uVar5 + 1;
  uVar18 = (lVar13 + ((long)iVar11 + -1) * (long)(iVar2 * 2 + 2) * 2) - 1U & -lVar13;
  iVar10 = FUN_71005ec04c(lVar16,(int)*(float *)(lVar15 + 0xc));
  lVar16 = *(long *)(((long *)*param_1)[1] + 0x40);
  uVar14 = (lVar16 + (long)iVar11 * ((long)iVar12 + (long)iVar10) * 0x60) - 1U & -lVar16;
  *(undefined4 *)((long)param_1 + 0x2c) = 1;
  param_1[3] = uVar14;
  param_1[4] = uVar18;
  lVar13 = *(long *)*param_1;
  lVar15 = *(long *)(lVar13 + 0x3a8);
  lVar16 = *(long *)(lVar13 + 0x658);
  lVar13 = uVar14 * *(byte *)(lVar13 + 0x710);
  uVar14 = lVar13 + uVar18;
  *(int *)(lVar15 + 0x2c) = (int)uVar14;
  uVar14 = FUN_71005cedd0(lVar16,uVar14 & 0xffffffff,*(long *)(lVar16 + 0x1d8));
  *(ulong *)(lVar15 + 0x20) = uVar14;
  if (uVar14 != 0) {
    iVar11 = (int)*(undefined8 *)(*(long *)(*(long *)*param_1 + 0x658) + 0x1d8);
    uVar3 = ((int)lVar13 + iVar11) - 1U & -iVar11;
    bVar9 = uVar3 <= *(uint *)(lVar15 + 0x2c);
    uVar17 = 0;
    if (bVar9) {
      uVar17 = uVar3;
    }
    *(uint *)(lVar15 + 0x28) = uVar17;
    uVar4 = 0;
    if (bVar9) {
      uVar4 = uVar14;
    }
    param_1[1] = uVar4;
    if (uVar18 == 0) {
      lVar16 = param_1[2];
    }
    else {
      uVar17 = *(uint *)(lVar15 + 0x28);
      uVar3 = uVar17 + (((int)uVar18 + iVar11) - 1U & -iVar11);
      if (*(uint *)(lVar15 + 0x2c) < uVar3) {
        lVar16 = 0;
      }
      else {
        *(uint *)(lVar15 + 0x28) = uVar3;
        lVar16 = *(long *)(lVar15 + 0x20) + (ulong)uVar17;
      }
      param_1[2] = lVar16;
    }
    thunk_EXT_FUN_02e95df0(lVar16,0,uVar18);
    if (1 < *(int *)(param_1 + 5)) {
      iVar12 = 0;
      iVar11 = 3;
      uVar3 = (uVar5 & ((int)uVar5 >> 0x1f ^ 0xffffffffU)) + 1;
      lVar13 = 0;
      uVar17 = uVar5;
      do {
        uVar18 = 0;
        iVar10 = iVar11;
        do {
          iVar7 = iVar10;
          sVar6 = (short)iVar12 + (short)uVar18;
          *(short *)(lVar16 + (long)(iVar7 + -3) * 2) = sVar6;
          sVar8 = (short)uVar17 + (short)uVar18;
          uVar18 = uVar18 + 2;
          *(short *)(lVar16 + (long)(iVar7 + -2) * 2) = sVar8 + 1;
          *(short *)(lVar16 + (long)(iVar7 + -1) * 2) = sVar6 + 1;
          *(short *)(lVar16 + (long)iVar7 * 2) = sVar8 + 2;
          iVar10 = iVar7 + 4;
        } while (((ulong)uVar3 & 0xfffffffe) != uVar18);
        if ((uVar3 & 1) != 0) {
          *(short *)(lVar16 + (long)(iVar7 + 1) * 2) = (short)iVar12 + (short)uVar18;
          *(short *)(lVar16 + (long)(iVar7 + 2) * 2) = (short)uVar17 + (short)uVar18 + 1;
        }
        lVar15 = lVar13 + 1;
        uVar17 = uVar17 + iVar2;
        sVar6 = (short)lVar15 * (short)iVar2;
        iVar12 = iVar12 + iVar2;
        iVar11 = iVar11 + uVar5 * 2 + 4;
        psVar1 = (short *)(lVar16 + (long)(((int)lVar13 + iVar2 * (int)lVar15) * 2) * 2);
        *psVar1 = (short)uVar5 + sVar6;
        psVar1[1] = sVar6;
        lVar13 = lVar15;
      } while (lVar15 < (long)*(int *)(param_1 + 5) + -1);
    }
  }
  return uVar14 != 0;
}



void FUN_71005ef864(long param_1,long param_2,undefined8 param_3,long param_4,long param_5,
                   long param_6,undefined8 *param_7,undefined8 param_8,undefined8 param_9)

{
  undefined8 uVar1;
  undefined8 uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  char cVar8;
  undefined8 *puVar9;
  undefined8 uVar10;
  undefined8 uVar11;
  undefined8 uVar12;
  undefined8 uVar13;
  undefined8 uVar14;
  undefined8 uVar15;
  undefined8 uVar16;
  undefined8 uVar17;
  undefined8 uVar18;
  undefined8 uVar19;
  undefined4 uVar20;
  undefined4 uVar21;
  undefined4 uVar22;
  undefined4 uVar23;
  long local_90 [2];
  
  uVar18 = param_7[1];
  uVar16 = *param_7;
  uVar13 = param_7[3];
  uVar10 = param_7[2];
  uVar1 = *(undefined8 *)(param_6 + 0x10);
  uVar2 = *(undefined8 *)(param_6 + 0x18);
  uVar23 = *(undefined4 *)(param_7 + 0x12);
  uVar22 = *(undefined4 *)((long)param_7 + 0x94);
  uVar20 = *(undefined4 *)(param_5 + 0x5c);
  uVar14 = param_7[5];
  uVar11 = param_7[4];
  uVar19 = param_7[0xb];
  uVar17 = param_7[10];
  uVar21 = *(undefined4 *)((long)param_7 + 0x9c);
  iVar3 = *(int *)(param_7 + 0x10);
  iVar4 = *(int *)(param_5 + 0x1c);
  local_90[0] = 0;
  local_90[1] = 0;
  uVar15 = param_7[7];
  uVar12 = param_7[6];
  iVar5 = *(int *)((long)param_7 + 0x8c);
  iVar6 = *(int *)(param_6 + 100);
  iVar7 = *(int *)(param_5 + 0x58);
  puVar9 = (undefined8 *)FUN_71005fb2f4(param_2,local_90,0x80);
  if (puVar9 == (undefined8 *)0x0) {
    ret_71005DEE40();
  }
  else {
    *(undefined4 *)((long)puVar9 + 100) = uVar20;
    *(undefined4 *)(puVar9 + 0xd) = uVar21;
    *(undefined4 *)((long)puVar9 + 0x6c) = 0;
    *(float *)((long)puVar9 + 0x5c) = (float)iVar6;
    *(float *)(puVar9 + 0xc) = (float)iVar7;
    puVar9[1] = uVar14;
    *puVar9 = uVar11;
    puVar9[2] = uVar1;
    puVar9[3] = uVar2;
    *(undefined4 *)(puVar9 + 8) = uVar23;
    *(float *)((long)puVar9 + 0x44) = (float)(iVar3 + iVar4 * (iVar3 + -1));
    *(float *)(puVar9 + 9) = (float)iVar5;
    *(undefined4 *)((long)puVar9 + 0x4c) = uVar22;
    puVar9[10] = uVar17;
    *(int *)(puVar9 + 0xb) = (int)uVar19;
    puVar9[5] = uVar18;
    puVar9[4] = uVar16;
    puVar9[7] = uVar13;
    puVar9[6] = uVar10;
    puVar9[0xf] = uVar15;
    puVar9[0xe] = uVar12;
    cVar8 = *(char *)(param_4 + 0x7f);
    if (*(char *)(param_4 + 0x3d) != -1) {
      FUN_71005fd4d4(param_1,(int)*(char *)(param_4 + 0x3d),0,local_90,0x80);
    }
    if (cVar8 != -1) {
      FUN_71005fd4d4(param_1,(int)cVar8,4,local_90,0x80);
    }
    ret_71005FB3B0();
    FUN_71005fc404(param_1,4,1,param_8,*(undefined4 *)(param_7 + 0x11),0);
    if (*(char *)(param_5 + 2) == '\x01') {
      FUN_71005fc404(param_1,4,1,param_9,*(undefined4 *)(param_7 + 0x11),0);
    }
  }
  return;
}



void FUN_71005efa20(long *param_1,long param_2)

{
  long lVar1;
  long lVar2;
  undefined4 uVar3;
  
  param_1[2] = 0;
  param_1[3] = 0;
  lVar2 = DAT_7103a6fc00;
  lVar1 = DAT_7103a6fbf8;
  param_1[4] = 0;
  param_1[5] = 0;
  param_1[6] = 0;
  param_1[7] = 0x10000;
  param_1[0x133] = 0;
  param_1[0x134] = 0;
  *param_1 = lVar1 + 0x10;
  param_1[1] = lVar2 + 0x10;
  param_1[8] = 0x100000;
  param_1[9] = 0x2000000040;
  param_1[10] = 0x2000000020;
  param_1[0xb] = 8;
  param_1[0xc] = 0x100000400;
  param_1[0xd] = 0x100000000000001;
  *(undefined1 *)(param_1 + 0xe) = 1;
  lVar1 = DAT_7103a6fa30 + 0x10;
  param_1[0x137] = lVar1;
  lVar2 = DAT_7103a6fa38 + 0x10;
  param_1[0x138] = lVar2;
  thunk_EXT_FUN_02e95df0(param_1 + 0x139,0,0);
  param_1[0x13f] = 0;
  param_1[0x13e] = 0;
  param_1[0x13d] = 0;
  param_1[0x140] = lVar1;
  param_1[0x141] = lVar2;
  thunk_EXT_FUN_02e95df0(param_1 + 0x142,0,0);
  param_1[0x148] = 0;
  param_1[0x147] = 0;
  param_1[0x146] = 0;
  FUN_71005f6fa4(param_1 + 0x149);
  FUN_71005f71d8(param_1 + 0x14d);
  param_1[0x18d] = 0;
  param_1[0x18c] = 0;
  param_1[0x18b] = 0;
  param_1[0x18e] = lVar2;
  thunk_EXT_FUN_02e95df0(param_1 + 399,0,0);
  param_1[0x194] = 0;
  param_1[0x193] = 0;
  param_1[0x195] = lVar2;
  thunk_EXT_FUN_02e95df0(param_1 + 0x196,0,0);
  param_1[0x19b] = 0;
  param_1[0x19a] = 0;
  param_1[0x19c] = lVar2;
  thunk_EXT_FUN_02e95df0(param_1 + 0x19d,0,0);
  param_1[0x1a2] = 0;
  lVar1 = DAT_7103a6f9e0;
  param_1[0x1a1] = 0;
  param_1[0x1a4] = 0;
  param_1[0x1a5] = 0;
  param_1[0x1a3] = lVar1 + 0x10;
  FUN_71005fc110(param_1 + 0x1a6);
  FUN_71005fd8a4(param_1 + 0x1af);
  *(undefined4 *)(param_1 + 0x1df) = 0;
  param_1[0x1d3] = (long)(param_1 + 0x1d3);
  param_1[0x1d4] = (long)(param_1 + 0x1d3);
  param_1[0x1d5] = (long)(param_1 + 0x1d5);
  param_1[0x1d6] = (long)(param_1 + 0x1d5);
  param_1[0x1d7] = 0;
  param_1[0x1d8] = 0;
  param_1[0x1d9] = 0;
  param_1[0x1e1] = lVar2;
  thunk_EXT_FUN_02e95df0(param_1 + 0x1e2,0,0);
  param_1[0x1e6] = lVar2;
  thunk_EXT_FUN_02e95df0(param_1 + 0x1e7,0,0);
  lVar1 = DAT_7103a6fc08;
  *(undefined2 *)(param_1 + 0x1ec) = 0;
  param_1[0x1eb] = lVar1 + 0x10;
  FUN_71005ea1d8(param_1 + 0x1ed);
  FUN_71005ec220(param_1 + 0x1f8);
  param_1[0x211] = 0;
  param_1[0x210] = 0;
  param_1[0x20f] = 0;
  param_1[0x20e] = 0;
  *(undefined1 *)(param_1 + 0x212) = 0;
  *(undefined1 *)(param_1 + 0x221) = 0;
  *(undefined1 *)(param_1 + 0x3f2) = 0;
  *(undefined1 *)(param_1 + 0x230) = 0;
  *(undefined1 *)(param_1 + 0x23f) = 0;
  *(undefined1 *)(param_1 + 0x24e) = 0;
  *(undefined1 *)(param_1 + 0x25d) = 0;
  *(undefined1 *)(param_1 + 0x26c) = 0;
  *(undefined1 *)(param_1 + 0x27b) = 0;
  *(undefined1 *)(param_1 + 0x28a) = 0;
  *(undefined1 *)(param_1 + 0x299) = 0;
  *(undefined1 *)(param_1 + 0x2a8) = 0;
  *(undefined1 *)(param_1 + 0x2b7) = 0;
  *(undefined1 *)(param_1 + 0x2c6) = 0;
  *(undefined1 *)(param_1 + 0x2d5) = 0;
  *(undefined1 *)(param_1 + 0x2e4) = 0;
  *(undefined1 *)(param_1 + 0x2f3) = 0;
  *(undefined1 *)(param_1 + 0x302) = 0;
  *(undefined1 *)(param_1 + 0x311) = 0;
  *(undefined1 *)(param_1 + 800) = 0;
  *(undefined1 *)(param_1 + 0x32f) = 0;
  *(undefined1 *)(param_1 + 0x33e) = 0;
  *(undefined1 *)(param_1 + 0x34d) = 0;
  *(undefined1 *)(param_1 + 0x35c) = 0;
  *(undefined1 *)(param_1 + 0x36b) = 0;
  *(undefined1 *)(param_1 + 0x37a) = 0;
  *(undefined1 *)(param_1 + 0x389) = 0;
  *(undefined1 *)(param_1 + 0x398) = 0;
  *(undefined1 *)(param_1 + 0x3a7) = 0;
  *(undefined1 *)(param_1 + 0x3b6) = 0;
  *(undefined1 *)(param_1 + 0x3c5) = 0;
  *(undefined1 *)(param_1 + 0x3d4) = 0;
  *(undefined1 *)(param_1 + 0x3e3) = 0;
  *(undefined1 *)(param_1 + 0x401) = 0;
  *(undefined1 *)(param_1 + 0x410) = 0;
  *(undefined1 *)(param_1 + 0x41f) = 0;
  *(undefined1 *)(param_1 + 0x42e) = 0;
  *(undefined1 *)(param_1 + 0x43d) = 0;
  *(undefined1 *)(param_1 + 0x44c) = 0;
  *(undefined1 *)(param_1 + 0x45b) = 0;
  *(undefined1 *)(param_1 + 0x46a) = 0;
  *(undefined1 *)(param_1 + 0x479) = 0;
  *(undefined1 *)(param_1 + 0x488) = 0;
  *(undefined1 *)(param_1 + 0x497) = 0;
  *(undefined1 *)(param_1 + 0x4a6) = 0;
  param_1[0x20d] = 0;
  *(undefined1 *)(param_1 + 0x4b5) = 0;
  param_1[0x20c] = 0;
  param_1[0x20b] = 0;
  param_1[0x20a] = 0;
  *(undefined1 *)(param_1 + 0x4c4) = 0;
  param_1[0x209] = 0;
  param_1[0x208] = 0;
  param_1[0x207] = 0;
  *(undefined1 *)(param_1 + 0x4d3) = 0;
  param_1[0x206] = 0;
  param_1[0x205] = 0;
  param_1[0x204] = 0;
  *(undefined1 *)(param_1 + 0x4e2) = 0;
  param_1[0x213] = 0;
  param_1[0x214] = 0;
  param_1[0x215] = 0;
  *(undefined1 *)(param_1 + 0x4f1) = 0;
  param_1[0x216] = 0;
  param_1[0x217] = 0;
  param_1[0x218] = 0;
  *(undefined1 *)(param_1 + 0x500) = 0;
  param_1[0x219] = 0;
  param_1[0x21a] = 0;
  param_1[0x21b] = 0;
  *(undefined1 *)(param_1 + 0x50f) = 0;
  param_1[0x21c] = 0;
  param_1[0x21d] = 0;
  param_1[0x21e] = 0;
  *(undefined1 *)(param_1 + 0x51e) = 0;
  param_1[0x21f] = 0;
  param_1[0x220] = 0;
  param_1[0x22f] = 0;
  *(undefined1 *)(param_1 + 0x52d) = 0;
  param_1[0x22e] = 0;
  param_1[0x22d] = 0;
  param_1[0x22c] = 0;
  *(undefined1 *)(param_1 + 0x53c) = 0;
  param_1[0x22b] = 0;
  param_1[0x22a] = 0;
  param_1[0x229] = 0;
  *(undefined1 *)(param_1 + 0x54b) = 0;
  param_1[0x228] = 0;
  param_1[0x227] = 0;
  param_1[0x226] = 0;
  *(undefined1 *)(param_1 + 0x55a) = 0;
  param_1[0x225] = 0;
  param_1[0x224] = 0;
  param_1[0x223] = 0;
  *(undefined1 *)(param_1 + 0x569) = 0;
  param_1[0x222] = 0;
  param_1[0x23e] = 0;
  param_1[0x23d] = 0;
  *(undefined1 *)(param_1 + 0x578) = 0;
  param_1[0x23c] = 0;
  param_1[0x23b] = 0;
  param_1[0x23a] = 0;
  *(undefined1 *)(param_1 + 0x587) = 0;
  param_1[0x239] = 0;
  param_1[0x238] = 0;
  param_1[0x237] = 0;
  *(undefined1 *)(param_1 + 0x596) = 0;
  param_1[0x236] = 0;
  param_1[0x235] = 0;
  param_1[0x234] = 0;
  *(undefined1 *)(param_1 + 0x5a5) = 0;
  param_1[0x233] = 0;
  param_1[0x232] = 0;
  param_1[0x231] = 0;
  *(undefined1 *)(param_1 + 0x5b4) = 0;
  param_1[0x24d] = 0;
  param_1[0x24c] = 0;
  param_1[0x24b] = 0;
  *(undefined1 *)(param_1 + 0x5c3) = 0;
  param_1[0x24a] = 0;
  param_1[0x249] = 0;
  param_1[0x248] = 0;
  *(undefined1 *)(param_1 + 0x5d2) = 0;
  param_1[0x247] = 0;
  param_1[0x246] = 0;
  param_1[0x245] = 0;
  param_1[0x244] = 0;
  param_1[0x243] = 0;
  param_1[0x242] = 0;
  param_1[0x241] = 0;
  param_1[0x240] = 0;
  param_1[0x24f] = 0;
  param_1[0x250] = 0;
  param_1[0x251] = 0;
  param_1[0x252] = 0;
  param_1[0x253] = 0;
  param_1[0x254] = 0;
  param_1[0x255] = 0;
  param_1[0x256] = 0;
  param_1[599] = 0;
  param_1[600] = 0;
  param_1[0x259] = 0;
  param_1[0x25a] = 0;
  param_1[0x25b] = 0;
  param_1[0x25c] = 0;
  param_1[0x26b] = 0;
  param_1[0x26a] = 0;
  param_1[0x269] = 0;
  param_1[0x268] = 0;
  param_1[0x267] = 0;
  param_1[0x266] = 0;
  param_1[0x265] = 0;
  param_1[0x264] = 0;
  param_1[0x263] = 0;
  param_1[0x262] = 0;
  param_1[0x261] = 0;
  param_1[0x260] = 0;
  param_1[0x25f] = 0;
  param_1[0x25e] = 0;
  param_1[0x27a] = 0;
  param_1[0x279] = 0;
  param_1[0x278] = 0;
  param_1[0x277] = 0;
  param_1[0x276] = 0;
  param_1[0x275] = 0;
  param_1[0x274] = 0;
  param_1[0x273] = 0;
  param_1[0x272] = 0;
  param_1[0x271] = 0;
  param_1[0x270] = 0;
  param_1[0x26f] = 0;
  param_1[0x26e] = 0;
  param_1[0x26d] = 0;
  param_1[0x289] = 0;
  param_1[0x288] = 0;
  param_1[0x287] = 0;
  param_1[0x286] = 0;
  param_1[0x285] = 0;
  param_1[0x284] = 0;
  param_1[0x283] = 0;
  param_1[0x282] = 0;
  param_1[0x281] = 0;
  param_1[0x280] = 0;
  param_1[0x27f] = 0;
  param_1[0x27e] = 0;
  param_1[0x27d] = 0;
  param_1[0x27c] = 0;
  param_1[0x298] = 0;
  param_1[0x297] = 0;
  param_1[0x296] = 0;
  param_1[0x295] = 0;
  param_1[0x294] = 0;
  param_1[0x293] = 0;
  param_1[0x292] = 0;
  param_1[0x291] = 0;
  param_1[0x290] = 0;
  param_1[0x28f] = 0;
  param_1[0x28e] = 0;
  param_1[0x28d] = 0;
  param_1[0x28c] = 0;
  param_1[0x28b] = 0;
  param_1[0x2a7] = 0;
  param_1[0x2a6] = 0;
  param_1[0x2a5] = 0;
  param_1[0x2a4] = 0;
  param_1[0x2a3] = 0;
  param_1[0x2a2] = 0;
  param_1[0x2a1] = 0;
  param_1[0x2a0] = 0;
  param_1[0x29f] = 0;
  param_1[0x29e] = 0;
  param_1[0x29d] = 0;
  param_1[0x29c] = 0;
  param_1[0x29b] = 0;
  param_1[0x29a] = 0;
  param_1[0x2b6] = 0;
  param_1[0x2b5] = 0;
  param_1[0x2b4] = 0;
  param_1[0x2b3] = 0;
  param_1[0x2b2] = 0;
  param_1[0x2b1] = 0;
  param_1[0x2b0] = 0;
  param_1[0x2af] = 0;
  param_1[0x2ae] = 0;
  param_1[0x2ad] = 0;
  param_1[0x2ac] = 0;
  param_1[0x2ab] = 0;
  param_1[0x2aa] = 0;
  param_1[0x2a9] = 0;
  param_1[0x2c5] = 0;
  param_1[0x2c4] = 0;
  param_1[0x2c3] = 0;
  param_1[0x2c2] = 0;
  param_1[0x2c1] = 0;
  param_1[0x2c0] = 0;
  param_1[0x2bf] = 0;
  param_1[0x2be] = 0;
  param_1[0x2bd] = 0;
  param_1[700] = 0;
  param_1[699] = 0;
  param_1[0x2ba] = 0;
  param_1[0x2b9] = 0;
  param_1[0x2b8] = 0;
  param_1[0x2d4] = 0;
  param_1[0x2d3] = 0;
  param_1[0x2d2] = 0;
  param_1[0x2d1] = 0;
  param_1[0x2d0] = 0;
  param_1[0x4c9] = 0;
  param_1[0x4c8] = 0;
  param_1[0x4c7] = 0;
  param_1[0x4cc] = 0;
  param_1[0x4cb] = 0;
  param_1[0x4ca] = 0;
  param_1[0x4cf] = 0;
  param_1[0x4ce] = 0;
  param_1[0x4cd] = 0;
  param_1[0x4d2] = 0;
  param_1[0x4d1] = 0;
  param_1[0x4d0] = 0;
  param_1[0x2cf] = 0;
  param_1[0x4b7] = 0;
  param_1[0x4b6] = 0;
  param_1[0x4ba] = 0;
  param_1[0x4b9] = 0;
  param_1[0x4b8] = 0;
  param_1[0x4bd] = 0;
  param_1[0x4bc] = 0;
  param_1[0x4bb] = 0;
  param_1[0x4c0] = 0;
  param_1[0x4bf] = 0;
  param_1[0x4be] = 0;
  param_1[0x4c3] = 0;
  param_1[0x4c2] = 0;
  param_1[0x4c1] = 0;
  param_1[0x2ce] = 0;
  param_1[0x4a8] = 0;
  param_1[0x4a7] = 0;
  param_1[0x4ab] = 0;
  param_1[0x4aa] = 0;
  param_1[0x4a9] = 0;
  param_1[0x4ae] = 0;
  param_1[0x4ad] = 0;
  param_1[0x4ac] = 0;
  param_1[0x4b1] = 0;
  param_1[0x4b0] = 0;
  param_1[0x4af] = 0;
  param_1[0x4b4] = 0;
  param_1[0x4b3] = 0;
  param_1[0x4b2] = 0;
  param_1[0x2cd] = 0;
  param_1[0x499] = 0;
  param_1[0x498] = 0;
  param_1[0x49c] = 0;
  param_1[0x49b] = 0;
  param_1[0x49a] = 0;
  param_1[0x49f] = 0;
  param_1[0x49e] = 0;
  param_1[0x49d] = 0;
  param_1[0x4a2] = 0;
  param_1[0x4a1] = 0;
  param_1[0x4a0] = 0;
  param_1[0x4a5] = 0;
  param_1[0x4a4] = 0;
  param_1[0x4a3] = 0;
  param_1[0x2cc] = 0;
  param_1[0x48a] = 0;
  param_1[0x489] = 0;
  param_1[0x48d] = 0;
  param_1[0x48c] = 0;
  param_1[0x48b] = 0;
  param_1[0x490] = 0;
  param_1[0x48f] = 0;
  param_1[0x48e] = 0;
  param_1[0x493] = 0;
  param_1[0x492] = 0;
  param_1[0x491] = 0;
  param_1[0x2fa] = 0;
  param_1[0x2f7] = 0;
  param_1[0x2f6] = 0;
  param_1[0x2fb] = 0;
  param_1[0x2f5] = 0;
  param_1[0x2f4] = 0;
  param_1[0x2f8] = 0;
  param_1[0x30f] = 0;
  param_1[0x30e] = 0;
  param_1[0x2eb] = 0;
  param_1[0x30c] = 0;
  param_1[0x30b] = 0;
  param_1[0x310] = 0;
  param_1[0x309] = 0;
  param_1[0x308] = 0;
  param_1[0x30d] = 0;
  param_1[0x306] = 0;
  param_1[0x305] = 0;
  param_1[0x30a] = 0;
  param_1[0x304] = 0;
  param_1[0x303] = 0;
  param_1[0x307] = 0;
  param_1[0x31e] = 0;
  param_1[0x31d] = 0;
  param_1[0x2ec] = 0;
  param_1[0x31b] = 0;
  param_1[0x31a] = 0;
  param_1[799] = 0;
  param_1[0x318] = 0;
  param_1[0x317] = 0;
  param_1[0x31c] = 0;
  param_1[0x315] = 0;
  param_1[0x314] = 0;
  param_1[0x319] = 0;
  param_1[0x313] = 0;
  param_1[0x312] = 0;
  param_1[0x316] = 0;
  param_1[0x32d] = 0;
  param_1[0x32c] = 0;
  param_1[0x2ed] = 0;
  param_1[0x32a] = 0;
  param_1[0x329] = 0;
  param_1[0x32e] = 0;
  param_1[0x327] = 0;
  param_1[0x326] = 0;
  param_1[0x32b] = 0;
  param_1[0x324] = 0;
  param_1[0x323] = 0;
  param_1[0x328] = 0;
  param_1[0x322] = 0;
  param_1[0x321] = 0;
  param_1[0x325] = 0;
  param_1[0x33c] = 0;
  param_1[0x33b] = 0;
  param_1[0x2ee] = 0;
  param_1[0x339] = 0;
  param_1[0x338] = 0;
  param_1[0x33d] = 0;
  param_1[0x336] = 0;
  param_1[0x335] = 0;
  param_1[0x33a] = 0;
  param_1[0x333] = 0;
  param_1[0x332] = 0;
  param_1[0x337] = 0;
  param_1[0x331] = 0;
  param_1[0x330] = 0;
  param_1[0x334] = 0;
  param_1[0x34b] = 0;
  param_1[0x34a] = 0;
  param_1[0x2ef] = 0;
  param_1[0x348] = 0;
  param_1[0x347] = 0;
  param_1[0x34c] = 0;
  param_1[0x345] = 0;
  param_1[0x344] = 0;
  param_1[0x349] = 0;
  param_1[0x342] = 0;
  param_1[0x341] = 0;
  param_1[0x346] = 0;
  param_1[0x340] = 0;
  param_1[0x33f] = 0;
  param_1[0x343] = 0;
  param_1[0x35a] = 0;
  param_1[0x359] = 0;
  param_1[0x2f0] = 0;
  param_1[0x357] = 0;
  param_1[0x356] = 0;
  param_1[0x35b] = 0;
  param_1[0x354] = 0;
  param_1[0x353] = 0;
  param_1[0x358] = 0;
  param_1[0x351] = 0;
  param_1[0x350] = 0;
  param_1[0x355] = 0;
  param_1[0x34f] = 0;
  param_1[0x34e] = 0;
  param_1[0x352] = 0;
  param_1[0x369] = 0;
  param_1[0x368] = 0;
  param_1[0x2f1] = 0;
  param_1[0x366] = 0;
  param_1[0x365] = 0;
  param_1[0x36a] = 0;
  param_1[0x363] = 0;
  param_1[0x362] = 0;
  param_1[0x367] = 0;
  param_1[0x360] = 0;
  param_1[0x35f] = 0;
  param_1[0x364] = 0;
  param_1[0x35e] = 0;
  param_1[0x35d] = 0;
  param_1[0x361] = 0;
  param_1[0x378] = 0;
  param_1[0x377] = 0;
  param_1[0x2f2] = 0;
  param_1[0x375] = 0;
  param_1[0x374] = 0;
  param_1[0x379] = 0;
  param_1[0x372] = 0;
  param_1[0x371] = 0;
  param_1[0x376] = 0;
  param_1[0x36f] = 0;
  param_1[0x36e] = 0;
  param_1[0x373] = 0;
  param_1[0x36d] = 0;
  param_1[0x36c] = 0;
  param_1[0x370] = 0;
  param_1[0x387] = 0;
  param_1[0x386] = 0;
  param_1[0x2d6] = 0;
  param_1[900] = 0;
  param_1[899] = 0;
  param_1[0x388] = 0;
  param_1[0x381] = 0;
  param_1[0x380] = 0;
  param_1[0x385] = 0;
  param_1[0x37e] = 0;
  param_1[0x37d] = 0;
  param_1[0x382] = 0;
  param_1[0x37c] = 0;
  param_1[0x37b] = 0;
  param_1[0x37f] = 0;
  param_1[0x396] = 0;
  param_1[0x395] = 0;
  param_1[0x2d7] = 0;
  param_1[0x393] = 0;
  param_1[0x392] = 0;
  param_1[0x397] = 0;
  param_1[0x390] = 0;
  param_1[0x38f] = 0;
  param_1[0x394] = 0;
  param_1[0x38d] = 0;
  param_1[0x38c] = 0;
  param_1[0x391] = 0;
  param_1[0x38b] = 0;
  param_1[0x38a] = 0;
  param_1[0x38e] = 0;
  param_1[0x3a5] = 0;
  param_1[0x3a4] = 0;
  param_1[0x2d8] = 0;
  param_1[0x3a2] = 0;
  param_1[0x3a1] = 0;
  param_1[0x3a6] = 0;
  param_1[0x39f] = 0;
  param_1[0x39e] = 0;
  param_1[0x3a3] = 0;
  param_1[0x39c] = 0;
  param_1[0x39b] = 0;
  param_1[0x3a0] = 0;
  param_1[0x39a] = 0;
  param_1[0x399] = 0;
  param_1[0x39d] = 0;
  param_1[0x3b4] = 0;
  param_1[0x3b3] = 0;
  param_1[0x2d9] = 0;
  param_1[0x3b1] = 0;
  param_1[0x3b0] = 0;
  param_1[0x3b5] = 0;
  param_1[0x3ae] = 0;
  param_1[0x3ad] = 0;
  param_1[0x3b2] = 0;
  param_1[0x3ab] = 0;
  param_1[0x3aa] = 0;
  param_1[0x3af] = 0;
  param_1[0x3a9] = 0;
  param_1[0x3a8] = 0;
  param_1[0x3ac] = 0;
  param_1[0x3c3] = 0;
  param_1[0x3c2] = 0;
  param_1[0x2da] = 0;
  param_1[0x3c0] = 0;
  param_1[0x3bf] = 0;
  param_1[0x3c4] = 0;
  param_1[0x3bd] = 0;
  param_1[0x3bc] = 0;
  param_1[0x3c1] = 0;
  param_1[0x3ba] = 0;
  param_1[0x3b9] = 0;
  param_1[0x3be] = 0;
  param_1[0x3b8] = 0;
  param_1[0x3b7] = 0;
  param_1[0x3bb] = 0;
  param_1[0x3d2] = 0;
  param_1[0x3d1] = 0;
  param_1[0x2db] = 0;
  param_1[0x3cf] = 0;
  param_1[0x3ce] = 0;
  param_1[0x3d3] = 0;
  param_1[0x3cc] = 0;
  param_1[0x3cb] = 0;
  param_1[0x3d0] = 0;
  param_1[0x3c9] = 0;
  param_1[0x3c8] = 0;
  param_1[0x3cd] = 0;
  param_1[0x3c7] = 0;
  param_1[0x3c6] = 0;
  param_1[0x3ca] = 0;
  param_1[0x3e1] = 0;
  param_1[0x3e0] = 0;
  param_1[0x2dc] = 0;
  param_1[0x3de] = 0;
  param_1[0x3dd] = 0;
  param_1[0x3e2] = 0;
  param_1[0x3db] = 0;
  param_1[0x3da] = 0;
  param_1[0x3df] = 0;
  param_1[0x3d8] = 0;
  param_1[0x3d7] = 0;
  param_1[0x3dc] = 0;
  param_1[0x3d6] = 0;
  param_1[0x3d5] = 0;
  param_1[0x3d9] = 0;
  param_1[0x3f0] = 0;
  param_1[0x3ef] = 0;
  param_1[0x2dd] = 0;
  param_1[0x3ed] = 0;
  param_1[0x3ec] = 0;
  param_1[0x3f1] = 0;
  param_1[0x3ea] = 0;
  param_1[0x3e9] = 0;
  param_1[0x3ee] = 0;
  param_1[999] = 0;
  param_1[0x3e6] = 0;
  param_1[0x3eb] = 0;
  param_1[0x3e5] = 0;
  param_1[0x3e4] = 0;
  param_1[1000] = 0;
  param_1[0x3ff] = 0;
  param_1[0x3fe] = 0;
  param_1[0x2de] = 0;
  param_1[0x3fc] = 0;
  param_1[0x3fb] = 0;
  param_1[0x400] = 0;
  param_1[0x3f9] = 0;
  param_1[0x3f8] = 0;
  param_1[0x3fd] = 0;
  param_1[0x3f6] = 0;
  param_1[0x3f5] = 0;
  param_1[0x3fa] = 0;
  param_1[0x3f4] = 0;
  param_1[0x3f3] = 0;
  param_1[0x3f7] = 0;
  param_1[0x40e] = 0;
  param_1[0x40d] = 0;
  param_1[0x2df] = 0;
  param_1[0x40b] = 0;
  param_1[0x40a] = 0;
  param_1[0x40f] = 0;
  param_1[0x408] = 0;
  param_1[0x407] = 0;
  param_1[0x40c] = 0;
  param_1[0x405] = 0;
  param_1[0x404] = 0;
  param_1[0x409] = 0;
  param_1[0x403] = 0;
  param_1[0x402] = 0;
  param_1[0x406] = 0;
  param_1[0x41d] = 0;
  param_1[0x41c] = 0;
  param_1[0x2e0] = 0;
  param_1[0x41a] = 0;
  param_1[0x419] = 0;
  param_1[0x41e] = 0;
  param_1[0x417] = 0;
  param_1[0x416] = 0;
  param_1[0x41b] = 0;
  param_1[0x414] = 0;
  param_1[0x413] = 0;
  param_1[0x418] = 0;
  param_1[0x412] = 0;
  param_1[0x411] = 0;
  param_1[0x415] = 0;
  param_1[0x42c] = 0;
  param_1[0x42b] = 0;
  param_1[0x2e1] = 0;
  param_1[0x429] = 0;
  param_1[0x428] = 0;
  param_1[0x42d] = 0;
  param_1[0x426] = 0;
  param_1[0x425] = 0;
  param_1[0x42a] = 0;
  param_1[0x423] = 0;
  param_1[0x422] = 0;
  param_1[0x427] = 0;
  param_1[0x421] = 0;
  param_1[0x420] = 0;
  param_1[0x424] = 0;
  param_1[0x43b] = 0;
  param_1[0x43a] = 0;
  param_1[0x2e2] = 0;
  param_1[0x438] = 0;
  param_1[0x437] = 0;
  param_1[0x43c] = 0;
  param_1[0x435] = 0;
  param_1[0x434] = 0;
  param_1[0x439] = 0;
  param_1[0x432] = 0;
  param_1[0x431] = 0;
  param_1[0x436] = 0;
  param_1[0x430] = 0;
  param_1[0x42f] = 0;
  param_1[0x433] = 0;
  param_1[0x44a] = 0;
  param_1[0x449] = 0;
  param_1[0x2e3] = 0;
  param_1[0x447] = 0;
  param_1[0x446] = 0;
  param_1[1099] = 0;
  param_1[0x444] = 0;
  param_1[0x443] = 0;
  param_1[0x448] = 0;
  param_1[0x441] = 0;
  param_1[0x440] = 0;
  param_1[0x445] = 0;
  param_1[0x43f] = 0;
  param_1[0x43e] = 0;
  param_1[0x442] = 0;
  param_1[0x459] = 0;
  param_1[0x458] = 0;
  param_1[0x2c7] = 0;
  param_1[0x456] = 0;
  param_1[0x455] = 0;
  param_1[0x45a] = 0;
  param_1[0x453] = 0;
  param_1[0x452] = 0;
  param_1[0x457] = 0;
  param_1[0x450] = 0;
  param_1[0x44f] = 0;
  param_1[0x454] = 0;
  param_1[0x44e] = 0;
  param_1[0x44d] = 0;
  param_1[0x451] = 0;
  param_1[0x468] = 0;
  param_1[0x467] = 0;
  param_1[0x2c8] = 0;
  param_1[0x465] = 0;
  param_1[0x464] = 0;
  param_1[0x469] = 0;
  param_1[0x462] = 0;
  param_1[0x461] = 0;
  param_1[0x466] = 0;
  param_1[0x45f] = 0;
  param_1[0x45e] = 0;
  param_1[0x463] = 0;
  param_1[0x45d] = 0;
  param_1[0x45c] = 0;
  param_1[0x460] = 0;
  param_1[0x477] = 0;
  param_1[0x476] = 0;
  param_1[0x2c9] = 0;
  param_1[0x474] = 0;
  param_1[0x473] = 0;
  param_1[0x478] = 0;
  param_1[0x471] = 0;
  param_1[0x470] = 0;
  param_1[0x475] = 0;
  param_1[0x46e] = 0;
  param_1[0x46d] = 0;
  param_1[0x472] = 0;
  param_1[0x46c] = 0;
  param_1[0x46b] = 0;
  param_1[0x46f] = 0;
  param_1[0x486] = 0;
  param_1[0x485] = 0;
  param_1[0x2ca] = 0;
  param_1[0x483] = 0;
  param_1[0x482] = 0;
  param_1[0x487] = 0;
  param_1[0x480] = 0;
  param_1[0x47f] = 0;
  param_1[0x484] = 0;
  param_1[0x47d] = 0;
  param_1[0x47c] = 0;
  param_1[0x481] = 0;
  param_1[0x47b] = 0;
  param_1[0x47a] = 0;
  param_1[0x47e] = 0;
  param_1[0x495] = 0;
  param_1[0x494] = 0;
  param_1[0x2cb] = 0;
  param_1[0x496] = 0;
  param_1[0x2f9] = 0;
  param_1[0x2fe] = 0;
  param_1[0x2fd] = 0;
  param_1[0x2fc] = 0;
  param_1[0x301] = 0;
  param_1[0x300] = 0;
  param_1[0x2ff] = 0;
  param_1[0x2ea] = 0;
  param_1[0x2e6] = 0;
  param_1[0x2e5] = 0;
  param_1[0x2e9] = 0;
  param_1[0x2e8] = 0;
  param_1[0x2e7] = 0;
  param_1[0x4c6] = 0;
  param_1[0x4c5] = 0;
  param_1[0x4e1] = 0;
  param_1[0x4e0] = 0;
  param_1[0x4df] = 0;
  param_1[0x4de] = 0;
  param_1[0x4dd] = 0;
  param_1[0x4dc] = 0;
  param_1[0x4db] = 0;
  param_1[0x4da] = 0;
  param_1[0x4d9] = 0;
  param_1[0x4d8] = 0;
  param_1[0x4d7] = 0;
  param_1[0x4d6] = 0;
  param_1[0x4d5] = 0;
  param_1[0x4d4] = 0;
  param_1[0x4f0] = 0;
  param_1[0x4ef] = 0;
  param_1[0x4ee] = 0;
  param_1[0x4ed] = 0;
  param_1[0x4ec] = 0;
  param_1[0x4eb] = 0;
  param_1[0x4ea] = 0;
  param_1[0x4e9] = 0;
  param_1[0x4e8] = 0;
  param_1[0x4e7] = 0;
  param_1[0x4e6] = 0;
  param_1[0x4e5] = 0;
  param_1[0x4e4] = 0;
  param_1[0x4e3] = 0;
  param_1[0x4ff] = 0;
  param_1[0x4fe] = 0;
  param_1[0x4fd] = 0;
  param_1[0x4fc] = 0;
  param_1[0x4fb] = 0;
  param_1[0x4fa] = 0;
  param_1[0x4f9] = 0;
  param_1[0x4f8] = 0;
  param_1[0x4f7] = 0;
  param_1[0x4f6] = 0;
  param_1[0x4f5] = 0;
  param_1[0x4f4] = 0;
  param_1[0x4f3] = 0;
  param_1[0x4f2] = 0;
  param_1[0x50e] = 0;
  param_1[0x50d] = 0;
  param_1[0x50c] = 0;
  param_1[0x50b] = 0;
  param_1[0x50a] = 0;
  param_1[0x509] = 0;
  param_1[0x508] = 0;
  param_1[0x507] = 0;
  param_1[0x506] = 0;
  param_1[0x505] = 0;
  param_1[0x504] = 0;
  param_1[0x503] = 0;
  param_1[0x502] = 0;
  param_1[0x501] = 0;
  param_1[0x51d] = 0;
  param_1[0x51c] = 0;
  param_1[0x51b] = 0;
  param_1[0x51a] = 0;
  param_1[0x519] = 0;
  param_1[0x518] = 0;
  param_1[0x517] = 0;
  param_1[0x516] = 0;
  param_1[0x515] = 0;
  param_1[0x514] = 0;
  param_1[0x513] = 0;
  param_1[0x512] = 0;
  param_1[0x511] = 0;
  param_1[0x510] = 0;
  param_1[0x52c] = 0;
  param_1[0x52b] = 0;
  param_1[0x52a] = 0;
  param_1[0x529] = 0;
  param_1[0x528] = 0;
  param_1[0x527] = 0;
  param_1[0x526] = 0;
  param_1[0x525] = 0;
  param_1[0x524] = 0;
  param_1[0x523] = 0;
  param_1[0x522] = 0;
  param_1[0x521] = 0;
  param_1[0x520] = 0;
  param_1[0x51f] = 0;
  param_1[0x53b] = 0;
  param_1[0x53a] = 0;
  param_1[0x539] = 0;
  param_1[0x538] = 0;
  param_1[0x537] = 0;
  param_1[0x536] = 0;
  param_1[0x535] = 0;
  param_1[0x534] = 0;
  param_1[0x533] = 0;
  param_1[0x532] = 0;
  param_1[0x531] = 0;
  param_1[0x530] = 0;
  param_1[0x52f] = 0;
  param_1[0x52e] = 0;
  param_1[0x54a] = 0;
  param_1[0x549] = 0;
  param_1[0x548] = 0;
  param_1[0x547] = 0;
  param_1[0x546] = 0;
  param_1[0x545] = 0;
  param_1[0x544] = 0;
  param_1[0x543] = 0;
  param_1[0x542] = 0;
  param_1[0x541] = 0;
  param_1[0x540] = 0;
  param_1[0x53f] = 0;
  param_1[0x53e] = 0;
  param_1[0x53d] = 0;
  param_1[0x559] = 0;
  param_1[0x558] = 0;
  param_1[0x557] = 0;
  param_1[0x556] = 0;
  param_1[0x555] = 0;
  param_1[0x554] = 0;
  param_1[0x553] = 0;
  param_1[0x552] = 0;
  param_1[0x551] = 0;
  param_1[0x550] = 0;
  param_1[0x54f] = 0;
  param_1[0x54e] = 0;
  param_1[0x54d] = 0;
  param_1[0x54c] = 0;
  param_1[0x568] = 0;
  param_1[0x567] = 0;
  param_1[0x566] = 0;
  param_1[0x565] = 0;
  param_1[0x564] = 0;
  param_1[0x563] = 0;
  param_1[0x562] = 0;
  param_1[0x561] = 0;
  param_1[0x560] = 0;
  param_1[0x55f] = 0;
  param_1[0x55e] = 0;
  param_1[0x55d] = 0;
  param_1[0x55c] = 0;
  param_1[0x55b] = 0;
  param_1[0x577] = 0;
  param_1[0x576] = 0;
  param_1[0x575] = 0;
  param_1[0x574] = 0;
  param_1[0x573] = 0;
  param_1[0x572] = 0;
  param_1[0x571] = 0;
  param_1[0x570] = 0;
  param_1[0x56f] = 0;
  param_1[0x56e] = 0;
  param_1[0x56d] = 0;
  param_1[0x56c] = 0;
  param_1[0x56b] = 0;
  param_1[0x56a] = 0;
  param_1[0x586] = 0;
  param_1[0x585] = 0;
  param_1[0x584] = 0;
  param_1[0x583] = 0;
  param_1[0x582] = 0;
  param_1[0x581] = 0;
  param_1[0x580] = 0;
  param_1[0x57f] = 0;
  param_1[0x57e] = 0;
  param_1[0x57d] = 0;
  param_1[0x57c] = 0;
  param_1[0x57b] = 0;
  param_1[0x57a] = 0;
  param_1[0x579] = 0;
  param_1[0x595] = 0;
  param_1[0x594] = 0;
  param_1[0x593] = 0;
  param_1[0x592] = 0;
  param_1[0x591] = 0;
  param_1[0x590] = 0;
  param_1[0x58f] = 0;
  param_1[0x58e] = 0;
  param_1[0x58d] = 0;
  param_1[0x58c] = 0;
  param_1[0x58b] = 0;
  param_1[0x58a] = 0;
  param_1[0x589] = 0;
  param_1[0x588] = 0;
  param_1[0x5a4] = 0;
  param_1[0x5a3] = 0;
  param_1[0x5a2] = 0;
  param_1[0x5a1] = 0;
  param_1[0x5a0] = 0;
  param_1[0x59f] = 0;
  param_1[0x59e] = 0;
  param_1[0x59d] = 0;
  param_1[0x59c] = 0;
  param_1[0x59b] = 0;
  param_1[0x59a] = 0;
  param_1[0x599] = 0;
  param_1[0x598] = 0;
  param_1[0x597] = 0;
  param_1[0x5b3] = 0;
  param_1[0x5b2] = 0;
  param_1[0x5b1] = 0;
  param_1[0x5b0] = 0;
  param_1[0x5af] = 0;
  param_1[0x5ae] = 0;
  param_1[0x5ad] = 0;
  param_1[0x5ac] = 0;
  param_1[0x5ab] = 0;
  param_1[0x5aa] = 0;
  param_1[0x5a9] = 0;
  param_1[0x5a8] = 0;
  param_1[0x5a7] = 0;
  param_1[0x5a6] = 0;
  param_1[0x5c2] = 0;
  param_1[0x5c1] = 0;
  param_1[0x5c0] = 0;
  param_1[0x5bf] = 0;
  param_1[0x5be] = 0;
  param_1[0x5bd] = 0;
  param_1[0x5bc] = 0;
  param_1[0x5bb] = 0;
  param_1[0x5ba] = 0;
  param_1[0x5b9] = 0;
  param_1[0x5b8] = 0;
  param_1[0x5b7] = 0;
  param_1[0x5b6] = 0;
  param_1[0x5b5] = 0;
  param_1[0x5d1] = 0;
  param_1[0x5d0] = 0;
  param_1[0x5cf] = 0;
  param_1[0x5ce] = 0;
  param_1[0x5cd] = 0;
  param_1[0x5cc] = 0;
  param_1[0x5cb] = 0;
  param_1[0x5ca] = 0;
  param_1[0x5c9] = 0;
  param_1[0x5c8] = 0;
  param_1[0x5c7] = 0;
  param_1[0x5c6] = 0;
  param_1[0x5c5] = 0;
  param_1[0x5c4] = 0;
  thunk_EXT_FUN_02e95df0(param_1 + 0x5d3,0,0x4c8);
  lVar1 = DAT_7103a6fc10;
  param_1[0x66d] = 0;
  param_1[0x66e] = lVar2;
  param_1[0x66c] = lVar1 + 0x10;
  thunk_EXT_FUN_02e95df0(param_1 + 0x66f,0,0);
  *(undefined4 *)((long)param_1 + 0x339c) = 0;
  *(undefined4 *)(param_1 + 0x674) = 0;
  param_1[0x675] = 0;
  param_1[0x677] = 0;
  param_1[0x678] = 0;
  *(undefined4 *)(param_1 + 0x679) = 0;
  uVar3 = *(undefined4 *)(param_2 + 0x5c);
  lVar1 = DAT_7103a6fc18 + 0x10;
  param_1[0x67b] = *(long *)(param_2 + 0x10);
  *(undefined4 *)(param_1 + 0x67c) = uVar3;
  *(undefined4 *)(param_1 + 0x67d) = 0;
  param_1[0x67a] = lVar1;
  *(undefined1 *)((long)param_1 + 0x33ed) = 0;
  uVar3 = 2;
  if (*(char *)(param_2 + 100) != '\0') {
    uVar3 = 3;
  }
  *(undefined4 *)(param_1 + 0x67e) = uVar3;
  thunk_EXT_FUN_02e95df0("SDK MW+Nintendo+NintendoWare_Vfx2-20_5_3-Release");
                    // WARNING: Could not recover jumptable at 0x0071005f0d10. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_1 + 0x10))
            (param_1,*(undefined8 *)(param_2 + 0x10),*(undefined8 *)(param_2 + 0x18),param_2);
  return;
}



void FUN_71005f21a0(long *param_1)

{
  long *plVar1;
  long *plVar2;
  long *plVar3;
  long lVar4;
  int iVar5;
  long lVar6;
  undefined8 uVar7;
  
  *param_1 = DAT_7103a6fbf8 + 0x10;
  FUN_71005f7080(param_1 + 0x149);
  iVar5 = (int)param_1[0x679];
  plVar1 = param_1 + 0x137;
  if (0 < iVar5) {
    lVar6 = 0;
    do {
      lVar4 = *(long *)(param_1[0x675] + lVar6 * 8);
      if (lVar4 != 0) {
        FUN_71005e4d80(lVar4,0,(long *)0x0);
        FUN_71005dee10();
        iVar5 = (int)param_1[0x679];
      }
      lVar6 = lVar6 + 1;
    } while (lVar6 < iVar5);
  }
  (**(code **)(param_1[0x137] + 0x18))(plVar1,param_1[0x675]);
  plVar2 = param_1 + 0x1a3;
  FUN_71005cefc0((long)plVar2,param_1[0x120],0);
  FUN_71005cefc0((long)plVar2,param_1[0x121],0);
  FUN_71005ced60((long)plVar2);
  lVar6 = param_1[0x11a];
  plVar2 = param_1 + 0x142;
  thunk_EXT_FUN_02e95df0(plVar2);
  param_1[0x148] = param_1[0x148] + -1;
  (**(code **)(*(long *)param_1[0x146] + 0x18))((long *)param_1[0x146],lVar6);
  thunk_EXT_FUN_02e95df0(plVar2);
  lVar6 = param_1[0x11b];
  thunk_EXT_FUN_02e95df0(plVar2);
  param_1[0x148] = param_1[0x148] + -1;
  (**(code **)(*(long *)param_1[0x146] + 0x18))((long *)param_1[0x146],lVar6);
  thunk_EXT_FUN_02e95df0(plVar2);
  FUN_71005f7600((long)(param_1 + 0x14d));
  if (param_1[0x117] != 0) {
    ret_71005D807C();
    lVar6 = param_1[0x117];
    thunk_EXT_FUN_02e95df0(param_1 + 0x139);
    param_1[0x13f] = param_1[0x13f] + -1;
    (**(code **)(*(long *)param_1[0x13d] + 0x18))((long *)param_1[0x13d],lVar6);
    thunk_EXT_FUN_02e95df0(param_1 + 0x139);
  }
  if (0 < (int)param_1[0x67f]) {
    lVar4 = 0;
    lVar6 = 0;
    do {
      FUN_71005fb1ec((char *)(param_1[0x13] + lVar4),param_1[0x15],plVar1);
      uVar7 = *(undefined8 *)(param_1[0x13] + lVar4 + 0x808);
      thunk_EXT_FUN_02e95df0(param_1 + 0x139);
      param_1[0x13f] = param_1[0x13f] + -1;
      (**(code **)(*(long *)param_1[0x13d] + 0x18))((long *)param_1[0x13d],uVar7);
      thunk_EXT_FUN_02e95df0(param_1 + 0x139);
      lVar6 = lVar6 + 1;
      lVar4 = lVar4 + 0x828;
    } while (lVar6 < (int)param_1[0x67f]);
  }
  lVar6 = param_1[0x14];
  plVar3 = param_1 + 0x139;
  thunk_EXT_FUN_02e95df0(plVar3);
  param_1[0x13f] = param_1[0x13f] + -1;
  (**(code **)(*(long *)param_1[0x13d] + 0x18))((long *)param_1[0x13d],lVar6);
  thunk_EXT_FUN_02e95df0(plVar3);
  lVar6 = param_1[0x13];
  thunk_EXT_FUN_02e95df0(plVar3);
  param_1[0x13f] = param_1[0x13f] + -1;
  (**(code **)(*(long *)param_1[0x13d] + 0x18))((long *)param_1[0x13d],lVar6);
  thunk_EXT_FUN_02e95df0(plVar3);
  lVar6 = param_1[0x12];
  thunk_EXT_FUN_02e95df0(plVar3);
  param_1[0x13f] = param_1[0x13f] + -1;
  (**(code **)(*(long *)param_1[0x13d] + 0x18))((long *)param_1[0x13d],lVar6);
  thunk_EXT_FUN_02e95df0(plVar3);
  lVar6 = param_1[0x119];
  thunk_EXT_FUN_02e95df0(plVar3);
  param_1[0x13f] = param_1[0x13f] + -1;
  (**(code **)(*(long *)param_1[0x13d] + 0x18))((long *)param_1[0x13d],lVar6);
  thunk_EXT_FUN_02e95df0(plVar3);
  if ((char)param_1[0xe] != '\0') {
    FUN_71005d12c0(param_1[0x15],plVar1);
  }
  if (*(char *)((long)param_1 + 0x6f) != '\0') {
    FUN_71005e4650(plVar1);
  }
  if (param_1[6] == 0) {
    FUN_71005fb830(param_1[0x11f],param_1[0x15],plVar1);
    lVar6 = param_1[0x11f];
    thunk_EXT_FUN_02e95df0(plVar3);
    param_1[0x13f] = param_1[0x13f] + -1;
    (**(code **)(*(long *)param_1[0x13d] + 0x18))((long *)param_1[0x13d],lVar6);
    thunk_EXT_FUN_02e95df0(plVar3);
  }
  FUN_71005ea2f8(param_1 + 0x1ed,param_1 + 0x67a,plVar1);
  FUN_71005ec32c(param_1 + 0x1f8,param_1 + 0x67a,plVar1);
  ret_71005F77E0();
  (**(code **)(param_1[0x137] + 0x18))(plVar1,param_1[0x11d]);
  (**(code **)(param_1[0x137] + 0x18))(plVar1,param_1[0x11c]);
  lVar6 = param_1[0x18b];
  thunk_EXT_FUN_02e95df0(plVar3);
  param_1[0x13f] = param_1[0x13f] + -1;
  (**(code **)(*(long *)param_1[0x13d] + 0x18))((long *)param_1[0x13d],lVar6);
  thunk_EXT_FUN_02e95df0(plVar3);
  lVar6 = param_1[0x118];
  thunk_EXT_FUN_02e95df0(plVar3);
  param_1[0x13f] = param_1[0x13f] + -1;
  (**(code **)(*(long *)param_1[0x13d] + 0x18))((long *)param_1[0x13d],lVar6);
  thunk_EXT_FUN_02e95df0(plVar3);
  lVar6 = param_1[0x16];
  thunk_EXT_FUN_02e95df0(plVar3);
  param_1[0x13f] = param_1[0x13f] + -1;
  (**(code **)(*(long *)param_1[0x13d] + 0x18))((long *)param_1[0x13d],lVar6);
  thunk_EXT_FUN_02e95df0(plVar3);
  lVar6 = param_1[0x66d];
  thunk_EXT_FUN_02e95df0(plVar3);
  param_1[0x13f] = param_1[0x13f] + -1;
  (**(code **)(*(long *)param_1[0x13d] + 0x18))((long *)param_1[0x13d],lVar6);
  thunk_EXT_FUN_02e95df0(plVar3);
  lVar6 = DAT_7103a6fa38 + 0x10;
  param_1[0x66c] = DAT_7103a6fc10 + 0x10;
  param_1[0x66e] = lVar6;
  thunk_EXT_FUN_02e95df0(param_1 + 0x66f);
  param_1[0x1e6] = lVar6;
  thunk_EXT_FUN_02e95df0(param_1 + 0x1e7);
  param_1[0x1e1] = lVar6;
  thunk_EXT_FUN_02e95df0(param_1 + 0x1e2);
  param_1[0x1a3] = DAT_7103a6f9e0 + 0x10;
  ret_71005FD8B0();
  ret_71005FC128();
  param_1[0x19c] = lVar6;
  thunk_EXT_FUN_02e95df0(param_1 + 0x19d);
  param_1[0x195] = lVar6;
  thunk_EXT_FUN_02e95df0(param_1 + 0x196);
  param_1[0x18e] = lVar6;
  thunk_EXT_FUN_02e95df0(param_1 + 399);
  FUN_71005f7224(param_1 + 0x14d);
  ret_71005F6FB0();
  lVar4 = DAT_7103a6fa30;
  param_1[0x141] = lVar6;
  param_1[0x140] = lVar4 + 0x10;
  thunk_EXT_FUN_02e95df0(plVar2);
  param_1[0x137] = lVar4 + 0x10;
  param_1[0x138] = lVar6;
  thunk_EXT_FUN_02e95df0(plVar3);
  return;
}



undefined8
FUN_71005f2754(long *param_1,undefined8 param_2,undefined8 param_3,long *param_4,long param_5,
              undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,byte param_10,
              undefined8 param_11,undefined *param_12)

{
  long *plVar1;
  ulong uVar2;
  long lVar3;
  long lVar4;
  long local_70 [2];
  
  lVar4 = (long)param_9;
  if (*(long *)(*param_1 + (long)param_9 * 8) != 0) {
    if (param_1[3] == 0) {
      lVar3 = *param_1;
      plVar1 = (long *)0x0;
    }
    else {
      local_70[1] = 0;
      lVar3 = *param_1;
      plVar1 = local_70;
      local_70[0] = param_1[3];
    }
    FUN_71005e4d80(*(long *)(lVar3 + lVar4 * 8),(long)param_4,plVar1);
    (**(code **)(*param_4 + 0x18))(param_4,*(undefined8 *)(*param_1 + lVar4 * 8));
    *(undefined8 *)(*param_1 + lVar4 * 8) = 0;
    FUN_71005dee10();
  }
  plVar1 = (long *)(**(code **)(*param_4 + 0x10))(param_4,0x570,0x80);
  if (plVar1 == (long *)0x0) {
    FUN_71005dee10();
  }
  else {
    FUN_71005e49c4(plVar1);
    uVar2 = FUN_71005e4b7c((long)plVar1,param_2,(long)param_4,param_5,param_6,param_7,param_8,
                           param_9,param_3,param_10 & 1,param_1[1],param_11,param_12);
    if ((uVar2 & 1) != 0) {
      *(long **)(*param_1 + lVar4 * 8) = plVar1;
      return 1;
    }
    FUN_71005dee10();
    (**(code **)(*param_4 + 0x18))(param_4,plVar1);
  }
  return 0;
}



uint FUN_71005f28f4(long param_1,long *param_2,long param_3,int param_4,byte param_5,
                   undefined8 param_6)

{
  undefined8 uVar1;
  
  uVar1 = FUN_71005f2754((long *)(param_1 + 0x33a8),*(undefined8 *)(param_1 + 0xa8),
                         *(undefined8 *)(param_1 + 0x8f0),param_2,param_3,0,0,0,param_4,param_5,
                         param_6,*(undefined **)(param_1 + 0x9b0));
  return (uint)uVar1 & 1;
}



uint FUN_71005f2950(long param_1,long *param_2,long param_3,int param_4,undefined8 param_5)

{
  long *plVar1;
  uint uVar2;
  long *plVar3;
  undefined8 uVar4;
  undefined8 uVar5;
  undefined *puVar6;
  long lVar7;
  long lVar8;
  long local_80;
  undefined8 uStack_78;
  long local_70;
  undefined8 uStack_68;
  
  puVar6 = *(undefined **)(param_1 + 0x9b0);
  uVar4 = *(undefined8 *)(param_1 + 0xa8);
  uVar5 = *(undefined8 *)(param_1 + 0x8f0);
  plVar1 = (long *)(param_1 + 0x33a8);
  lVar8 = (long)param_4;
  if (*(long *)(*plVar1 + (long)param_4 * 8) != 0) {
    if (*(long *)(param_1 + 0x33c0) == 0) {
      lVar7 = *plVar1;
      plVar3 = (long *)0x0;
    }
    else {
      uStack_68 = 0;
      lVar7 = *plVar1;
      plVar3 = &local_70;
      local_70 = *(long *)(param_1 + 0x33c0);
    }
    FUN_71005e4d80(*(long *)(lVar7 + lVar8 * 8),(long)param_2,plVar3);
    (**(code **)(*param_2 + 0x18))(param_2,*(undefined8 *)(*plVar1 + lVar8 * 8));
    *(undefined8 *)(*plVar1 + lVar8 * 8) = 0;
    FUN_71005dee10();
  }
  plVar3 = (long *)(**(code **)(*param_2 + 0x10))(param_2,0x570,0x80);
  if (plVar3 == (long *)0x0) {
    FUN_71005dee10();
    uVar2 = 0;
  }
  else {
    FUN_71005e49c4(plVar3);
    local_70 = *(long *)(param_1 + 0x33b8);
    local_80 = *(long *)(param_1 + 0x33c0);
    uStack_78 = param_5;
    uStack_68 = param_5;
    uVar2 = FUN_71005e5c18((long)plVar3,uVar4,(long)param_2,param_3,param_4,uVar5,&local_70,
                           &local_80,*(undefined8 *)(param_1 + 0x33b0),puVar6);
    if ((uVar2 & 1) == 0) {
      FUN_71005dee10();
      (**(code **)(*param_2 + 0x18))(param_2,plVar3);
    }
    else {
      *(long **)(*plVar1 + lVar8 * 8) = plVar3;
    }
  }
  return uVar2 & 1;
}



void FUN_71005f2b00(long param_1,long *param_2,int param_3,undefined8 param_4)

{
  long *plVar1;
  long lVar2;
  long local_40;
  undefined8 uStack_38;
  
  if (*(long *)(*(long *)(param_1 + 0x33a8) + (long)param_3 * 8) != 0) {
    plVar1 = &local_40;
    if (*(long *)(param_1 + 0x33c0) == 0) {
      lVar2 = *(long *)(param_1 + 0x33a8);
      plVar1 = (long *)0x0;
    }
    else {
      lVar2 = *(long *)(param_1 + 0x33a8);
      local_40 = *(long *)(param_1 + 0x33c0);
      uStack_38 = param_4;
    }
    FUN_71005e4d80(*(long *)(lVar2 + (long)param_3 * 8),(long)param_2,plVar1);
    lVar2 = (long)param_3 * 8;
    (**(code **)(*param_2 + 0x18))(param_2,*(undefined8 *)(*(long *)(param_1 + 0x33a8) + lVar2));
    *(undefined8 *)(*(long *)(param_1 + 0x33a8) + lVar2) = 0;
    return;
  }
  FUN_71005dee10();
  return;
}



uint FUN_71005f2bb0(long param_1,undefined8 *param_2,int param_3,int param_4,int param_5,
                   undefined4 param_6,uint param_7)

{
  int *piVar1;
  long lVar2;
  long lVar3;
  int iVar4;
  char cVar5;
  bool bVar6;
  undefined8 *puVar7;
  ulong uVar8;
  undefined8 uVar9;
  long *plVar10;
  uint uVar11;
  long lVar12;
  long local_90;
  long lStack_88;
  long local_80;
  long lStack_78;
  long local_70;
  undefined8 uStack_68;
  undefined8 local_60;
  undefined4 local_58;
  
  lVar12 = *(long *)(*(long *)(param_1 + 0x33a8) + (long)param_4 * 8);
  if ((lVar12 != 0) && (*(char *)(lVar12 + 0x569) != '\0')) {
    if (param_3 < *(int *)(lVar12 + 0x550) && *(long *)(lVar12 + 0x430) != 0) {
      if (*(int *)(param_1 + 0xc50) <
          (int)(uint)*(byte *)(*(long *)(lVar12 + 0x430) + (long)param_3 * 0x28 + 0x22))
      goto LAB_71005f2d08;
    }
    else if (0x7fffffff < *(uint *)(param_1 + 0xc50)) {
LAB_71005f2d08:
      *param_2 = 0;
      *(undefined4 *)(param_2 + 1) = 0xffffffff;
      FUN_71005dee10();
      goto LAB_71005f2d20;
    }
    puVar7 = (undefined8 *)FUN_71005f70f0((long *)(param_1 + 0xa48));
    if (puVar7 != (undefined8 *)0x0) {
      *param_2 = puVar7;
      local_80 = param_1 + 0xa68;
      iVar4 = *(int *)(param_1 + 0x33fc);
      lStack_88 = param_1 + 0x3360;
      *(int *)(param_1 + 0x33fc) = iVar4 + 1;
      *(int *)(param_2 + 1) = iVar4;
      local_90 = param_1 + 0x1020;
      lStack_78 = param_1 + 0xa00;
      uStack_68 = *(undefined8 *)(param_1 + 0x958);
      local_70 = param_1 + 0x33e8;
      local_60 = *(undefined8 *)(param_1 + 0x960);
      local_58 = param_6;
      uVar8 = FUN_71005d1c10(puVar7,lVar12,param_3,iVar4,(char)param_5,&local_90);
      uVar11 = (uint)uVar8;
      if ((uVar8 & 1) == 0) {
        FUN_71005d2390((long)puVar7);
      }
      else {
        piVar1 = (int *)(lVar12 + 0x548);
        do {
          cVar5 = '\x01';
          bVar6 = (bool)ExclusiveMonitorPass(piVar1,0x10);
          if (bVar6) {
            *piVar1 = *piVar1 + 1;
            cVar5 = ExclusiveMonitorsStatus();
          }
        } while (cVar5 != '\0');
        if ((param_7 & 1) == 0) {
          lVar12 = param_1 + (long)param_5 * 8;
          plVar10 = (long *)(param_1 + (long)param_5 * 8 + 0xb8);
          if (*plVar10 == 0) {
            *plVar10 = (long)puVar7;
            uVar9 = 0;
          }
          else {
            **(undefined8 **)(lVar12 + 0x2b8) = puVar7;
            uVar9 = *(undefined8 *)(lVar12 + 0x2b8);
          }
          puVar7[0xf] = uVar9;
          *puVar7 = 0;
          *(undefined8 **)(lVar12 + 0x2b8) = puVar7;
        }
        else {
          lVar2 = param_1 + 0xf38;
          thunk_EXT_FUN_02e95df0(lVar2);
          thunk_EXT_FUN_02e95df0(lVar2);
          lVar12 = param_1 + (long)param_5 * 8;
          lVar3 = param_1 + (long)param_5 * 8;
          if (*(long *)(lVar12 + 0x4b8) == 0) {
            *(undefined8 **)(lVar12 + 0x4b8) = puVar7;
            uVar9 = 0;
          }
          else {
            **(undefined8 **)(lVar3 + 0x6b8) = puVar7;
            uVar9 = *(undefined8 *)(lVar3 + 0x6b8);
          }
          puVar7[0xf] = uVar9;
          *puVar7 = 0;
          *(undefined8 **)(lVar3 + 0x6b8) = puVar7;
          thunk_EXT_FUN_02e95df0(lVar2);
          *(uint *)(puVar7 + 7) = *(uint *)(puVar7 + 7) | 8;
          thunk_EXT_FUN_02e95df0(lVar2);
        }
      }
      goto LAB_71005f2d24;
    }
  }
LAB_71005f2d20:
  uVar11 = 0;
LAB_71005f2d24:
  return uVar11 & 1;
}



uint FUN_71005f2dbc(long param_1,undefined8 *param_2,int param_3,int param_4,int param_5,
                   uint param_6)

{
  uint uVar1;
  
  uVar1 = FUN_71005f2bb0(param_1,param_2,param_3,param_4,param_5,0,param_6);
  return uVar1;
}



undefined8
FUN_71005f2dd0(long param_1,long *param_2,int param_3,int param_4,int param_5,int param_6,
              int param_7,undefined8 param_8,long param_9,undefined4 param_10)

{
  byte bVar1;
  uint uVar2;
  long lVar3;
  
  if (param_7 <= param_6) {
    lVar3 = *(long *)(*(long *)(param_1 + 0x33a8) + (long)param_4 * 8);
    if ((lVar3 == 0) || (*(char *)(lVar3 + 0x569) == '\0')) {
      FUN_71005dee10();
      return 0;
    }
    bVar1 = FUN_71005e7e10(lVar3,param_3);
    if (((((bVar1 & 1) == 0) &&
         (uVar2 = FUN_71005f2bb0(param_1,param_2,param_3,param_4,param_5,param_6,0),
         (uVar2 & 1) != 0)) && (*param_2 != 0)) && ((int)param_2[1] == *(int *)(*param_2 + 0x234)))
    {
      lVar3 = FUN_71005d3890(param_2);
      *(uint *)(lVar3 + 0x38) = *(uint *)(lVar3 + 0x38) | 0x80;
      lVar3 = FUN_71005d3890(param_2);
      *(undefined8 *)(lVar3 + 0xa0) = param_8;
      lVar3 = FUN_71005d3890(param_2);
      *(int *)(lVar3 + 0x244) = param_7;
      lVar3 = FUN_71005d3890(param_2);
      *(undefined4 *)(lVar3 + 0x60) = param_10;
      if (param_9 != 0) {
        lVar3 = FUN_71005d3890(param_2);
        FUN_71005d3870(lVar3,param_9);
      }
      lVar3 = FUN_71005d3890(param_2);
      lVar3 = *(long *)(lVar3 + 8);
      if (lVar3 != 0) {
        do {
          if (*(char *)(*(long *)(lVar3 + 0x48) + 0xcc3) != '\x01') {
            FUN_71005d3890(param_2);
            FUN_71005dee10();
          }
          lVar3 = *(long *)(lVar3 + 8);
        } while (lVar3 != 0);
        return 1;
      }
      return 1;
    }
  }
  FUN_71005dee10();
  return 0;
}



void FUN_71005f2fb0(long param_1,long param_2)

{
  long lVar1;
  ulong uVar2;
  long lVar3;
  ulong uVar4;
  long *plVar5;
  
  if ((*(byte *)(param_2 + 0x39) >> 2 & 1) == 0) {
    FUN_71005dee10();
    return;
  }
  lVar1 = param_1 + 0xf10;
  *(ulong *)(param_2 + 0x28) = *(ulong *)(param_2 + 0x28) & 0xfffffffffffffffe;
  thunk_EXT_FUN_02e95df0(lVar1);
  uVar2 = *(ulong *)(param_1 + 0xc60);
  if (0 < (int)uVar2) {
    uVar4 = uVar2 & 0xffffffff;
    lVar3 = 0xffffffff;
    plVar5 = *(long **)(param_1 + 0xc58);
    do {
      if (*plVar5 == param_2) {
        if (lVar3 != 0) {
          thunk_EXT_FUN_02e95df0(lVar1);
          return;
        }
        break;
      }
      lVar3 = lVar3 + -1;
      uVar4 = uVar4 - 1;
      plVar5 = plVar5 + 1;
    } while (uVar4 != 0);
  }
  *(ulong *)(param_1 + 0xc60) = uVar2 + 1;
  (*(long **)(param_1 + 0xc58))[uVar2] = param_2;
  thunk_EXT_FUN_02e95df0(lVar1);
  return;
}



void FUN_71005f3070(long param_1)

{
  int *piVar1;
  char cVar2;
  bool bVar3;
  ulong uVar4;
  long lVar5;
  long *plVar6;
  ulong uVar7;
  
  thunk_EXT_FUN_02e95df0(param_1 + 0xf10);
  uVar4 = *(ulong *)(param_1 + 0xc60);
  if (0 < (int)uVar4) {
    uVar7 = 0;
    do {
      plVar6 = *(long **)(*(long *)(param_1 + 0xc58) + uVar7 * 8);
      lVar5 = *(long *)(*(long *)(param_1 + 0x33a8) + (long)(int)plVar6[10] * 8);
      if ((lVar5 != 0) && (*(char *)(lVar5 + 0x569) != '\0')) {
        piVar1 = (int *)(lVar5 + 0x548);
        do {
          cVar2 = '\x01';
          bVar3 = (bool)ExclusiveMonitorPass(piVar1,0x10);
          if (bVar3) {
            *piVar1 = *piVar1 + -1;
            cVar2 = ExclusiveMonitorsStatus();
          }
        } while (cVar2 != '\0');
      }
      FUN_71005d2390((long)plVar6);
      FUN_71005f7190(param_1 + 0xa48,(long)plVar6);
      FUN_71005f3140(param_1,plVar6);
      *(undefined8 *)(*(long *)(param_1 + 0xc58) + uVar7 * 8) = 0;
      uVar7 = uVar7 + 1;
    } while (uVar7 != (uVar4 & 0xffffffff));
  }
  *(undefined8 *)(param_1 + 0xc60) = 0;
  thunk_EXT_FUN_02e95df0(param_1 + 0xf10);
  return;
}



void FUN_71005f3140(long param_1,long *param_2)

{
  long lVar1;
  long lVar2;
  ulong uVar3;
  long *plVar4;
  long *plVar5;
  
  lVar2 = *param_2;
  if (((lVar2 != 0) || (plVar5 = param_2 + 0xf, *plVar5 != 0)) ||
     ((*(byte *)(param_2 + 7) >> 3 & 1) == 0)) {
    lVar1 = param_1 + (ulong)*(byte *)((long)param_2 + 0x65) * 8;
    if (*(long **)(lVar1 + 0xb8) == param_2) {
      *(long *)(lVar1 + 0xb8) = lVar2;
      uVar3 = (ulong)*(byte *)((long)param_2 + 0x65);
      lVar2 = *(long *)(param_1 + uVar3 * 8 + 0xb8);
      if (lVar2 != 0) {
        *(undefined8 *)(lVar2 + 0x78) = 0;
        uVar3 = (ulong)*(byte *)((long)param_2 + 0x65);
      }
      lVar2 = param_1 + uVar3 * 8;
      if (*(long **)(lVar2 + 0x2b8) == param_2) {
        *(undefined8 *)(lVar2 + 0x2b8) = 0;
        *param_2 = 0;
        param_2[0xf] = 0;
        return;
      }
    }
    else {
      if (*(long **)(lVar1 + 0x2b8) == param_2) {
        *(long *)(lVar1 + 0x2b8) = param_2[0xf];
        lVar2 = *param_2;
      }
      if (lVar2 != 0) {
        *(long *)(lVar2 + 0x78) = param_2[0xf];
      }
      if ((long *)param_2[0xf] != (long *)0x0) {
        *(long *)param_2[0xf] = *param_2;
        *param_2 = 0;
        param_2[0xf] = 0;
        return;
      }
      FUN_71005dee50();
    }
    *param_2 = 0;
    param_2[0xf] = 0;
    return;
  }
  lVar2 = param_1 + (ulong)*(byte *)((long)param_2 + 0x65) * 8;
  if (*(long **)(lVar2 + 0x4b8) == param_2) {
    *(undefined8 *)(lVar2 + 0x4b8) = 0;
    uVar3 = (ulong)*(byte *)((long)param_2 + 0x65);
    lVar2 = *(long *)(param_1 + uVar3 * 8 + 0x4b8);
    if (lVar2 != 0) {
      *(undefined8 *)(lVar2 + 0x78) = 0;
      uVar3 = (ulong)*(byte *)((long)param_2 + 0x65);
    }
    lVar2 = param_1 + uVar3 * 8;
    if (*(long **)(lVar2 + 0x6b8) == param_2) {
      *(undefined8 *)(lVar2 + 0x6b8) = 0;
    }
  }
  else {
    if (*(long **)(lVar2 + 0x6b8) == param_2) {
      *(undefined8 *)(lVar2 + 0x6b8) = 0;
      plVar4 = (long *)param_2[0xf];
      if (*param_2 != 0) {
        *(long **)(*param_2 + 0x78) = plVar4;
        plVar4 = (long *)*plVar5;
      }
      if (plVar4 != (long *)0x0) {
        *plVar4 = *param_2;
        goto LAB_71005f32cc;
      }
    }
    FUN_71005dee50();
  }
LAB_71005f32cc:
  *param_2 = 0;
  *(uint *)(param_2 + 7) = *(uint *)(param_2 + 7) & 0xfffffff7;
  *plVar5 = 0;
  return;
}



void FUN_71005f32f0(long param_1,int param_2)

{
  ulong uVar1;
  ulong uVar2;
  long *plVar3;
  long lVar4;
  long lVar5;
  long *plVar6;
  long *plVar7;
  
  plVar6 = *(long **)(param_1 + (long)param_2 * 8 + 0xb8);
  if (plVar6 != (long *)0x0) {
    lVar5 = param_1 + 0xf10;
    do {
      while (plVar7 = (long *)*plVar6, (*(byte *)((long)plVar6 + 0x39) >> 2 & 1) == 0) {
        FUN_71005dee10();
        plVar6 = plVar7;
        if (plVar7 == (long *)0x0) goto LAB_71005f33dc;
      }
      plVar6[5] = plVar6[5] & 0xfffffffffffffffe;
      thunk_EXT_FUN_02e95df0(lVar5);
      uVar1 = *(ulong *)(param_1 + 0xc60);
      if (0 < (int)uVar1) {
        uVar2 = uVar1 & 0xffffffff;
        lVar4 = 0xffffffff;
        plVar3 = *(long **)(param_1 + 0xc58);
        do {
          if ((long *)*plVar3 == plVar6) {
            if (lVar4 != 0) {
              thunk_EXT_FUN_02e95df0(lVar5);
              goto joined_r0x0071005f33b0;
            }
            break;
          }
          lVar4 = lVar4 + -1;
          uVar2 = uVar2 - 1;
          plVar3 = plVar3 + 1;
        } while (uVar2 != 0);
      }
      *(ulong *)(param_1 + 0xc60) = uVar1 + 1;
      (*(long **)(param_1 + 0xc58))[uVar1] = (long)plVar6;
      thunk_EXT_FUN_02e95df0(lVar5);
joined_r0x0071005f33b0:
      plVar6 = plVar7;
    } while (plVar7 != (long *)0x0);
  }
LAB_71005f33dc:
  plVar6 = *(long **)(param_1 + (long)param_2 * 8 + 0x4b8);
  if (plVar6 != (long *)0x0) {
    do {
      while (plVar7 = (long *)*plVar6, (*(byte *)((long)plVar6 + 0x39) >> 2 & 1) != 0) {
        plVar6[5] = plVar6[5] & 0xfffffffffffffffe;
        thunk_EXT_FUN_02e95df0(param_1 + 0xf10);
        uVar1 = *(ulong *)(param_1 + 0xc60);
        if (0 < (int)uVar1) {
          uVar2 = uVar1 & 0xffffffff;
          lVar5 = 0xffffffff;
          plVar3 = *(long **)(param_1 + 0xc58);
          do {
            if ((long *)*plVar3 == plVar6) {
              if (lVar5 != 0) goto LAB_71005f3490;
              break;
            }
            lVar5 = lVar5 + -1;
            uVar2 = uVar2 - 1;
            plVar3 = plVar3 + 1;
          } while (uVar2 != 0);
        }
        *(ulong *)(param_1 + 0xc60) = uVar1 + 1;
        (*(long **)(param_1 + 0xc58))[uVar1] = (long)plVar6;
LAB_71005f3490:
        thunk_EXT_FUN_02e95df0(param_1 + 0xf10);
        *(uint *)(plVar6 + 7) = *(uint *)(plVar6 + 7) & 0xfffffff7;
        plVar6 = plVar7;
        if (plVar7 == (long *)0x0) {
          return;
        }
      }
      FUN_71005dee10();
      *(uint *)(plVar6 + 7) = *(uint *)(plVar6 + 7) & 0xfffffff7;
      plVar6 = plVar7;
    } while (plVar7 != (long *)0x0);
  }
  return;
}



void FUN_71005f34c4(long param_1)

{
  FUN_71005f32f0(param_1,0);
  FUN_71005f32f0(param_1,1);
  FUN_71005f32f0(param_1,2);
  FUN_71005f32f0(param_1,3);
  FUN_71005f32f0(param_1,4);
  FUN_71005f32f0(param_1,5);
  FUN_71005f32f0(param_1,6);
  FUN_71005f32f0(param_1,7);
  FUN_71005f32f0(param_1,8);
  FUN_71005f32f0(param_1,9);
  FUN_71005f32f0(param_1,10);
  FUN_71005f32f0(param_1,0xb);
  FUN_71005f32f0(param_1,0xc);
  FUN_71005f32f0(param_1,0xd);
  FUN_71005f32f0(param_1,0xe);
  FUN_71005f32f0(param_1,0xf);
  FUN_71005f32f0(param_1,0x10);
  FUN_71005f32f0(param_1,0x11);
  FUN_71005f32f0(param_1,0x12);
  FUN_71005f32f0(param_1,0x13);
  FUN_71005f32f0(param_1,0x14);
  FUN_71005f32f0(param_1,0x15);
  FUN_71005f32f0(param_1,0x16);
  FUN_71005f32f0(param_1,0x17);
  FUN_71005f32f0(param_1,0x18);
  FUN_71005f32f0(param_1,0x19);
  FUN_71005f32f0(param_1,0x1a);
  FUN_71005f32f0(param_1,0x1b);
  FUN_71005f32f0(param_1,0x1c);
  FUN_71005f32f0(param_1,0x1d);
  FUN_71005f32f0(param_1,0x1e);
  FUN_71005f32f0(param_1,0x1f);
  FUN_71005f32f0(param_1,0x20);
  FUN_71005f32f0(param_1,0x21);
  FUN_71005f32f0(param_1,0x22);
  FUN_71005f32f0(param_1,0x23);
  FUN_71005f32f0(param_1,0x24);
  FUN_71005f32f0(param_1,0x25);
  FUN_71005f32f0(param_1,0x26);
  FUN_71005f32f0(param_1,0x27);
  FUN_71005f32f0(param_1,0x28);
  FUN_71005f32f0(param_1,0x29);
  FUN_71005f32f0(param_1,0x2a);
  FUN_71005f32f0(param_1,0x2b);
  FUN_71005f32f0(param_1,0x2c);
  FUN_71005f32f0(param_1,0x2d);
  FUN_71005f32f0(param_1,0x2e);
  FUN_71005f32f0(param_1,0x2f);
  FUN_71005f32f0(param_1,0x30);
  FUN_71005f32f0(param_1,0x31);
  FUN_71005f32f0(param_1,0x32);
  FUN_71005f32f0(param_1,0x33);
  FUN_71005f32f0(param_1,0x34);
  FUN_71005f32f0(param_1,0x35);
  FUN_71005f32f0(param_1,0x36);
  FUN_71005f32f0(param_1,0x37);
  FUN_71005f32f0(param_1,0x38);
  FUN_71005f32f0(param_1,0x39);
  FUN_71005f32f0(param_1,0x3a);
  FUN_71005f32f0(param_1,0x3b);
  FUN_71005f32f0(param_1,0x3c);
  FUN_71005f32f0(param_1,0x3d);
  FUN_71005f32f0(param_1,0x3e);
  FUN_71005f32f0(param_1,0x3f);
  thunk_EXT_FUN_02e95df0(param_1 + 0xc78);
  *(undefined8 *)(param_1 + 0xca0) = 0;
  *(undefined8 *)(param_1 + 0xc98) = 0;
  thunk_EXT_FUN_02e95df0(param_1 + 0xc78);
  thunk_EXT_FUN_02e95df0(param_1 + 0xcb0);
  *(undefined8 *)(param_1 + 0xcd8) = 0;
  *(undefined8 *)(param_1 + 0xcd0) = 0;
  thunk_EXT_FUN_02e95df0(param_1 + 0xcb0);
  thunk_EXT_FUN_02e95df0(param_1 + 0xce8);
  *(undefined8 *)(param_1 + 0xd10) = 0;
  *(undefined8 *)(param_1 + 0xd08) = 0;
  thunk_EXT_FUN_02e95df0(param_1 + 0xce8);
  return;
}



void FUN_71005f3830(long param_1)

{
  long lVar1;
  bool bVar2;
  bool bVar3;
  long lVar4;
  long lVar5;
  undefined8 *puVar6;
  undefined8 *puVar7;
  undefined8 *puVar8;
  undefined8 uVar9;
  
  if (*(char *)(param_1 + 0x33ee) == '\0') {
    return;
  }
  *(int *)(param_1 + 0x3400) = *(int *)(param_1 + 0x3400) + 1;
  thunk_EXT_FUN_02e95df0(param_1 + 0xc78);
  *(undefined8 *)(param_1 + 0xca0) = 0;
  *(undefined8 *)(param_1 + 0xc98) = 0;
  thunk_EXT_FUN_02e95df0(param_1 + 0xc78);
  thunk_EXT_FUN_02e95df0(param_1 + 0xcb0);
  *(undefined8 *)(param_1 + 0xcd8) = 0;
  *(undefined8 *)(param_1 + 0xcd0) = 0;
  thunk_EXT_FUN_02e95df0(param_1 + 0xcb0);
  thunk_EXT_FUN_02e95df0(param_1 + 0xce8);
  *(undefined8 *)(param_1 + 0xd10) = 0;
  *(undefined8 *)(param_1 + 0xd08) = 0;
  thunk_EXT_FUN_02e95df0(param_1 + 0xce8);
  FUN_71005cf0d0(param_1 + 0xd18);
  if (0 < *(int *)(param_1 + 0x33f4)) {
    lVar4 = 0;
    lVar5 = 0;
    do {
      *(undefined8 *)(*(long *)(param_1 + 0xb0) + lVar5 * 8) = 0;
      lVar5 = lVar5 + 1;
      puVar6 = (undefined8 *)(*(long *)(param_1 + 0x8c0) + lVar4);
      lVar4 = lVar4 + 0x38;
      *(undefined2 *)(puVar6 + 6) = 0;
      puVar6[4] = 0;
      puVar6[5] = 0;
      puVar6[2] = 0;
      puVar6[3] = 0;
      *puVar6 = 0;
      puVar6[1] = 0;
    } while (lVar5 < *(int *)(param_1 + 0x33f4));
    if (0 < *(int *)(param_1 + 0x33f4)) {
      lVar4 = 0;
      lVar5 = 0;
      do {
        lVar5 = lVar5 + 1;
        puVar6 = (undefined8 *)(*(long *)(param_1 + 0x90) + lVar4);
        puVar6[0x1e] = 0;
        puVar6[0x1f] = 0;
        puVar6[0x1c] = 0;
        puVar6[0x1d] = 0;
        puVar6[0x1a] = 0;
        puVar6[0x1b] = 0;
        puVar6[0x18] = 0;
        puVar6[0x19] = 0;
        puVar6[0x16] = 0;
        puVar6[0x17] = 0;
        puVar6[0x14] = 0;
        puVar6[0x15] = 0;
        puVar6[0x12] = 0;
        puVar6[0x13] = 0;
        puVar6[0x10] = 0;
        puVar6[0x11] = 0;
        puVar6[0xe] = 0;
        puVar6[0xf] = 0;
        puVar6[0xc] = 0;
        puVar6[0xd] = 0;
        puVar6[10] = 0;
        puVar6[0xb] = 0;
        puVar6[8] = 0;
        puVar6[9] = 0;
        puVar6[6] = 0;
        puVar6[7] = 0;
        puVar6[4] = 0;
        puVar6[5] = 0;
        puVar6[2] = 0;
        puVar6[3] = 0;
        *puVar6 = 0;
        puVar6[1] = 0;
        lVar1 = *(long *)(param_1 + 0x90) + lVar4;
        *(undefined8 *)(lVar1 + 0x1f0) = 0;
        *(undefined8 *)(lVar1 + 0x1f8) = 0;
        *(undefined8 *)(lVar1 + 0x1e0) = 0;
        *(undefined8 *)(lVar1 + 0x1e8) = 0;
        *(undefined8 *)(lVar1 + 0x1d0) = 0;
        *(undefined8 *)(lVar1 + 0x1d8) = 0;
        *(undefined8 *)(lVar1 + 0x1c0) = 0;
        *(undefined8 *)(lVar1 + 0x1c8) = 0;
        *(undefined8 *)(lVar1 + 0x1b0) = 0;
        *(undefined8 *)(lVar1 + 0x1b8) = 0;
        *(undefined8 *)(lVar1 + 0x1a0) = 0;
        *(undefined8 *)(lVar1 + 0x1a8) = 0;
        *(undefined8 *)(lVar1 + 400) = 0;
        *(undefined8 *)(lVar1 + 0x198) = 0;
        *(undefined8 *)(lVar1 + 0x180) = 0;
        *(undefined8 *)(lVar1 + 0x188) = 0;
        *(undefined8 *)(lVar1 + 0x170) = 0;
        *(undefined8 *)(lVar1 + 0x178) = 0;
        *(undefined8 *)(lVar1 + 0x160) = 0;
        *(undefined8 *)(lVar1 + 0x168) = 0;
        *(undefined8 *)(lVar1 + 0x150) = 0;
        *(undefined8 *)(lVar1 + 0x158) = 0;
        *(undefined8 *)(lVar1 + 0x140) = 0;
        *(undefined8 *)(lVar1 + 0x148) = 0;
        *(undefined8 *)(lVar1 + 0x130) = 0;
        *(undefined8 *)(lVar1 + 0x138) = 0;
        *(undefined8 *)(lVar1 + 0x120) = 0;
        *(undefined8 *)(lVar1 + 0x128) = 0;
        *(undefined8 *)(lVar1 + 0x110) = 0;
        *(undefined8 *)(lVar1 + 0x118) = 0;
        *(undefined8 *)(lVar1 + 0x100) = 0;
        *(undefined8 *)(lVar1 + 0x108) = 0;
        lVar1 = *(long *)(param_1 + 0x90) + lVar4;
        lVar4 = lVar4 + 0x300;
        *(undefined8 *)(lVar1 + 0x2f8) = 0;
        *(undefined8 *)(lVar1 + 0x2f0) = 0;
        *(undefined8 *)(lVar1 + 0x2e8) = 0;
        *(undefined8 *)(lVar1 + 0x2e0) = 0;
        *(undefined8 *)(lVar1 + 0x2d8) = 0;
        *(undefined8 *)(lVar1 + 0x2d0) = 0;
        *(undefined8 *)(lVar1 + 0x2c8) = 0;
        *(undefined8 *)(lVar1 + 0x2c0) = 0;
        *(undefined8 *)(lVar1 + 0x2b8) = 0;
        *(undefined8 *)(lVar1 + 0x2b0) = 0;
        *(undefined8 *)(lVar1 + 0x2a8) = 0;
        *(undefined8 *)(lVar1 + 0x2a0) = 0;
        *(undefined8 *)(lVar1 + 0x298) = 0;
        *(undefined8 *)(lVar1 + 0x290) = 0;
        *(undefined8 *)(lVar1 + 0x288) = 0;
        *(undefined8 *)(lVar1 + 0x280) = 0;
        *(undefined8 *)(lVar1 + 0x278) = 0;
        *(undefined8 *)(lVar1 + 0x270) = 0;
        *(undefined8 *)(lVar1 + 0x268) = 0;
        *(undefined8 *)(lVar1 + 0x260) = 0;
        *(undefined8 *)(lVar1 + 600) = 0;
        *(undefined8 *)(lVar1 + 0x250) = 0;
        *(undefined8 *)(lVar1 + 0x248) = 0;
        *(undefined8 *)(lVar1 + 0x240) = 0;
        *(undefined8 *)(lVar1 + 0x238) = 0;
        *(undefined8 *)(lVar1 + 0x230) = 0;
        *(undefined8 *)(lVar1 + 0x228) = 0;
        *(undefined8 *)(lVar1 + 0x220) = 0;
        *(undefined8 *)(lVar1 + 0x218) = 0;
        *(undefined8 *)(lVar1 + 0x210) = 0;
        *(undefined8 *)(lVar1 + 0x208) = 0;
        *(undefined8 *)(lVar1 + 0x200) = 0;
      } while (lVar5 < *(int *)(param_1 + 0x33f4));
    }
  }
  FUN_71005f3070(param_1);
  lVar5 = param_1 + 0xf38;
  thunk_EXT_FUN_02e95df0(lVar5);
  lVar4 = 0;
  bVar2 = false;
  do {
    puVar6 = (undefined8 *)(param_1 + 0x2b8 + lVar4 * 8);
    while ((undefined8 *)puVar6[0x40] == (undefined8 *)0x0) {
      lVar4 = lVar4 + 1;
      puVar6 = puVar6 + 1;
      if (lVar4 == 0x40) {
        thunk_EXT_FUN_02e95df0(lVar5);
        if (!bVar2) {
          return;
        }
        goto LAB_71005f3af8;
      }
    }
    lVar1 = param_1 + lVar4 * 8;
    puVar7 = (undefined8 *)puVar6[0x40];
    do {
      puVar8 = (undefined8 *)*puVar7;
      if (*(long *)(lVar1 + 0xb8) == 0) {
        *(undefined8 **)(lVar1 + 0xb8) = puVar7;
        uVar9 = 0;
      }
      else {
        *(undefined8 **)*puVar6 = puVar7;
        uVar9 = *puVar6;
      }
      puVar7[0xf] = uVar9;
      *puVar7 = 0;
      *puVar6 = puVar7;
      *(uint *)(puVar7 + 7) = *(uint *)(puVar7 + 7) & 0xfffffff7;
      puVar7 = puVar8;
    } while (puVar8 != (undefined8 *)0x0);
    bVar3 = lVar4 != 0x3f;
    lVar4 = lVar4 + 1;
    bVar2 = true;
  } while (bVar3);
  thunk_EXT_FUN_02e95df0(lVar5);
LAB_71005f3af8:
  thunk_EXT_FUN_02e95df0(param_1 + 0x4b8,0,0x400);
  return;
}



undefined8
FUN_71005f3b30(float param_1,long param_2,uint param_3,long param_4,char param_5,ulong *param_6)

{
  byte bVar1;
  long lVar2;
  long lVar3;
  long lVar4;
  ulong uVar5;
  long lVar6;
  ulong uVar7;
  long *plVar8;
  
  bVar1 = *(byte *)(param_4 + 0x65);
  if (param_1 != 0.0) {
    uVar5 = -(ulong)(param_3 >> 0x1f) & 0xfffffff800000000 | (ulong)param_3 << 3;
    *(ulong *)(*(long *)(param_2 + 0xb0) + uVar5) =
         *(ulong *)(*(long *)(param_2 + 0xb0) + uVar5) | 1L << ((ulong)bVar1 & 0x3f);
  }
  if (((*(byte *)(param_4 + 0x38) >> 1 & 1) == 0) || ((*param_6 & *(ulong *)(param_4 + 0x18)) == 0))
  {
    param_1 = 0.0;
  }
  FUN_71005d24e0(param_1,param_4,param_5,0,*(undefined **)(param_2 + 0x978),param_2 + 0xc70,
                 (undefined1 (*) [12])(param_2 + 0x7c),*(undefined **)(param_2 + 0x988));
  if (((0 < *(short *)(param_4 + 0xe8)) && ((*(byte *)(param_4 + 0x39) >> 2 & 1) != 0)) ||
     ((*(byte *)(param_4 + 0x67) & 1) != 0)) {
    lVar2 = (-(ulong)(param_3 >> 0x1f) & 0xffffffc000000000 | (ulong)param_3 << 6) +
            (long)(int)param_3 * -8;
    lVar4 = *(long *)(param_2 + 0x8c0) + lVar2;
    *(short *)(lVar4 + 0x2a) = *(short *)(lVar4 + 0x2a) + 1;
    lVar4 = *(long *)(param_2 + 0x8c0) + lVar2;
    *(short *)(lVar4 + 0x20) = *(short *)(lVar4 + 0x20) + *(short *)(param_4 + 0xe8);
    lVar4 = *(long *)(param_2 + 0x8c0) + lVar2;
    *(short *)(lVar4 + 0x22) = *(short *)(lVar4 + 0x22) + *(short *)(param_4 + 0xea);
    lVar4 = *(long *)(param_2 + 0x8c0) + lVar2;
    *(int *)(lVar4 + 0x14) = *(int *)(lVar4 + 0x14) + *(int *)(param_4 + 0xdc);
    lVar4 = *(long *)(param_2 + 0x8c0) + lVar2;
    *(int *)(lVar4 + 0x18) = *(int *)(lVar4 + 0x18) + *(int *)(param_4 + 0xe0);
    lVar4 = *(long *)(param_2 + 0x8c0) + lVar2;
    *(int *)(lVar4 + 0x1c) = *(int *)(lVar4 + 0x1c) + *(int *)(param_4 + 0xe4);
    lVar4 = *(long *)(param_2 + 0x8c0) + lVar2;
    *(int *)(lVar4 + 0x10) = *(int *)(lVar4 + 0x10) + *(int *)(param_4 + 0xd8);
    lVar4 = *(long *)(param_2 + 0x8c0) + lVar2;
    *(short *)(lVar4 + 0x24) = *(short *)(lVar4 + 0x24) + *(short *)(param_4 + 0xec);
    lVar4 = *(long *)(param_2 + 0x8c0) + lVar2;
    *(short *)(lVar4 + 0x26) = *(short *)(lVar4 + 0x26) + *(short *)(param_4 + 0xee);
    lVar4 = *(long *)(param_2 + 0x8c0) + lVar2;
    *(short *)(lVar4 + 0x28) = *(short *)(lVar4 + 0x28) + *(short *)(param_4 + 0xf0);
    lVar4 = *(long *)(param_2 + 0x8c0) + lVar2;
    *(short *)(lVar4 + 0x2c) = *(short *)(lVar4 + 0x2c) + *(short *)(param_4 + 0xf4);
    lVar4 = *(long *)(param_2 + 0x8c0) + lVar2;
    *(short *)(lVar4 + 0x2e) = *(short *)(lVar4 + 0x2e) + *(short *)(param_4 + 0xf6);
    lVar4 = *(long *)(param_2 + 0x8c0) + lVar2;
    *(short *)(lVar4 + 0x30) = *(short *)(lVar4 + 0x30) + *(short *)(param_4 + 0xf8);
    *(long *)(*(long *)(param_2 + 0x8c0) + lVar2) =
         *(long *)(*(long *)(param_2 + 0x8c0) + lVar2) + *(long *)(param_4 + 200);
    lVar3 = ((long)(int)param_3 + (long)(int)param_3 * 2) * 0x100;
    lVar2 = *(long *)(param_2 + 0x8c0) + lVar2;
    lVar6 = (ulong)bVar1 * 4;
    *(long *)(lVar2 + 8) = *(long *)(lVar2 + 8) + *(long *)(param_4 + 0xd0);
    lVar4 = *(long *)(param_2 + 0x90) + lVar3;
    *(uint *)(lVar4 + lVar6) = *(uint *)(lVar4 + lVar6) | *(uint *)(param_4 + 0x30);
    lVar4 = *(long *)(param_2 + 0x90) + lVar3 + lVar6;
    *(uint *)(lVar4 + 0x100) = *(uint *)(lVar4 + 0x100) | *(uint *)(param_4 + 0x268);
    lVar6 = *(long *)(param_2 + 0x90) + lVar3 + lVar6;
    *(uint *)(lVar6 + 0x200) = *(uint *)(lVar6 + 0x200) | *(uint *)(param_4 + 0x26c);
    return 1;
  }
  if ((*(byte *)(param_4 + 0x39) >> 2 & 1) == 0) {
    FUN_71005dee10();
    *(undefined4 *)(param_4 + 0x234) = 0xffffffff;
    return 0;
  }
  *(ulong *)(param_4 + 0x28) = *(ulong *)(param_4 + 0x28) & 0xfffffffffffffffe;
  thunk_EXT_FUN_02e95df0(param_2 + 0xf10);
  uVar5 = *(ulong *)(param_2 + 0xc60);
  if (0 < (int)uVar5) {
    uVar7 = uVar5 & 0xffffffff;
    lVar4 = 0xffffffff;
    plVar8 = *(long **)(param_2 + 0xc58);
    do {
      if (*plVar8 == param_4) {
        if (lVar4 != 0) goto LAB_71005f3e50;
        break;
      }
      lVar4 = lVar4 + -1;
      uVar7 = uVar7 - 1;
      plVar8 = plVar8 + 1;
    } while (uVar7 != 0);
  }
  *(ulong *)(param_2 + 0xc60) = uVar5 + 1;
  (*(long **)(param_2 + 0xc58))[uVar5] = param_4;
LAB_71005f3e50:
  thunk_EXT_FUN_02e95df0(param_2 + 0xf10);
  return 0;
}



void FUN_71005f3e70(float param_1,long param_2,uint param_3,int param_4,char param_5,ulong *param_6)

{
  long *plVar1;
  long *plVar2;
  
  if ((*(char *)(param_2 + 0x33ee) != '\0') &&
     (plVar2 = *(long **)(param_2 + (long)param_4 * 8 + 0xb8), plVar2 != (long *)0x0)) {
    for (plVar1 = (long *)*plVar2; plVar1 != (long *)0x0; plVar1 = (long *)*plVar1) {
      Hint_Prefetch(plVar1,0,0,0);
      Hint_Prefetch(plVar1 + 8,0,0,0);
      Hint_Prefetch(plVar1 + 0x10,0,0,0);
      Hint_Prefetch(plVar1 + 0x18,0,0,0);
      FUN_71005f3b30(param_1,param_2,param_3,(long)plVar2,param_5,param_6);
      plVar2 = plVar1;
    }
    FUN_71005f3b30(param_1,param_2,param_3,(long)plVar2,param_5,param_6);
    return;
  }
  return;
}



void FUN_71005f3f50(long param_1,int param_2,long param_3,long param_4,ulong param_5)

{
  long lVar1;
  undefined4 uVar2;
  long lVar3;
  long lVar4;
  undefined8 uVar5;
  undefined4 *puVar6;
  long lVar7;
  long lVar8;
  long lVar9;
  
  thunk_EXT_FUN_02e95df0(*(long *)(param_1 + 0x98) + (long)param_2 * 0x828 + 0x530,param_4,0x250);
  lVar3 = *(long *)(param_1 + 0x98) + (long)param_2 * 0x828;
  lVar3 = FUN_71005fb2f4(lVar3,(long *)(lVar3 + 0x780),0x250);
  if (lVar3 != 0) {
    uVar5 = *(undefined8 *)(param_1 + 0x7c);
    *(undefined8 *)(param_4 + 0x208) = *(undefined8 *)(param_1 + 0x84);
    *(undefined8 *)(param_4 + 0x200) = uVar5;
    uVar5 = *(undefined8 *)(param_1 + 0x910);
    *(undefined8 *)(param_4 + 0x218) = *(undefined8 *)(param_1 + 0x918);
    *(undefined8 *)(param_4 + 0x210) = uVar5;
    uVar5 = *(undefined8 *)(param_1 + 0x920);
    *(undefined8 *)(param_4 + 0x228) = *(undefined8 *)(param_1 + 0x928);
    *(undefined8 *)(param_4 + 0x220) = uVar5;
    uVar5 = *(undefined8 *)(param_1 + 0x930);
    *(undefined8 *)(param_4 + 0x238) = *(undefined8 *)(param_1 + 0x938);
    *(undefined8 *)(param_4 + 0x230) = uVar5;
    uVar5 = *(undefined8 *)(param_1 + 0x940);
    *(undefined8 *)(param_4 + 0x248) = *(undefined8 *)(param_1 + 0x948);
    *(undefined8 *)(param_4 + 0x240) = uVar5;
    thunk_EXT_FUN_02e95df0(lVar3,param_4,0x250);
    if ((param_5 & 1) != 0) {
      FUN_71005fd4d4(param_3,5,0,*(long *)(param_1 + 0x98) + (long)param_2 * 0x828 + 0x780,0x250);
      FUN_71005fd4d4(param_3,5,4,*(long *)(param_1 + 0x98) + (long)param_2 * 0x828 + 0x780,0x250);
      FUN_71005fd4d4(param_3,5,5,*(long *)(param_1 + 0x98) + (long)param_2 * 0x828 + 0x780,0x250);
    }
    ret_71005FB3B0();
  }
  if ((param_5 & 1) == 0) {
    lVar3 = *(long *)(*(long *)(param_1 + 0x8c8) + (long)param_2 * 0xc0);
    if (lVar3 != 0) {
      lVar8 = *(long *)(*(long *)(param_1 + 0x8c8) + (long)param_2 * 0xc0 + 0x30);
      lVar9 = *(long *)(param_1 + 0x98) + (long)param_2 * 0x828;
      lVar9 = FUN_71005fb2f4(lVar9,(long *)(lVar9 + 0x790),lVar8);
      if (lVar9 != 0) {
        thunk_EXT_FUN_02e95df0(lVar9,lVar3,lVar8);
        ret_71005FB3B0();
      }
    }
    lVar3 = *(long *)(*(long *)(param_1 + 0x8c8) + (long)param_2 * 0xc0 + 8);
    if (lVar3 != 0) {
      lVar8 = *(long *)(*(long *)(param_1 + 0x8c8) + (long)param_2 * 0xc0 + 0x38);
      lVar9 = *(long *)(param_1 + 0x98) + (long)param_2 * 0x828;
      lVar9 = FUN_71005fb2f4(lVar9,(long *)(lVar9 + 0x7a0),lVar8);
      if (lVar9 != 0) {
        thunk_EXT_FUN_02e95df0(lVar9,lVar3,lVar8);
        ret_71005FB3B0();
      }
    }
    lVar3 = *(long *)(*(long *)(param_1 + 0x8c8) + (long)param_2 * 0xc0 + 0x10);
    if (lVar3 != 0) {
      lVar8 = *(long *)(*(long *)(param_1 + 0x8c8) + (long)param_2 * 0xc0 + 0x40);
      lVar9 = *(long *)(param_1 + 0x98) + (long)param_2 * 0x828;
      lVar9 = FUN_71005fb2f4(lVar9,(long *)(lVar9 + 0x7b0),lVar8);
      if (lVar9 != 0) {
        thunk_EXT_FUN_02e95df0(lVar9,lVar3,lVar8);
        ret_71005FB3B0();
      }
    }
    lVar3 = *(long *)(*(long *)(param_1 + 0x8c8) + (long)param_2 * 0xc0 + 0x18);
    if (lVar3 != 0) {
      lVar8 = *(long *)(*(long *)(param_1 + 0x8c8) + (long)param_2 * 0xc0 + 0x48);
      lVar9 = *(long *)(param_1 + 0x98) + (long)param_2 * 0x828;
      lVar9 = FUN_71005fb2f4(lVar9,(long *)(lVar9 + 0x7c0),lVar8);
      if (lVar9 != 0) {
        thunk_EXT_FUN_02e95df0(lVar9,lVar3,lVar8);
        ret_71005FB3B0();
      }
    }
    lVar3 = *(long *)(*(long *)(param_1 + 0x8c8) + (long)param_2 * 0xc0 + 0x20);
    if (lVar3 != 0) {
      lVar8 = *(long *)(*(long *)(param_1 + 0x8c8) + (long)param_2 * 0xc0 + 0x50);
      lVar9 = *(long *)(param_1 + 0x98) + (long)param_2 * 0x828;
      lVar9 = FUN_71005fb2f4(lVar9,(long *)(lVar9 + 2000),lVar8);
      if (lVar9 != 0) {
        thunk_EXT_FUN_02e95df0(lVar9,lVar3,lVar8);
        ret_71005FB3B0();
      }
    }
    lVar3 = *(long *)(*(long *)(param_1 + 0x8c8) + (long)param_2 * 0xc0 + 0x28);
    if (lVar3 != 0) {
      lVar8 = *(long *)(*(long *)(param_1 + 0x8c8) + (long)param_2 * 0xc0 + 0x58);
      lVar9 = *(long *)(param_1 + 0x98) + (long)param_2 * 0x828;
      lVar9 = FUN_71005fb2f4(lVar9,(long *)(lVar9 + 0x7e0),lVar8);
      if (lVar9 != 0) {
        thunk_EXT_FUN_02e95df0(lVar9,lVar3,lVar8);
        ret_71005FB3B0();
        return;
      }
    }
  }
  else {
    lVar3 = 0;
    lVar9 = (long)param_2 * 0xc0;
    puVar6 = &DAT_710329b660;
    do {
      lVar8 = *(long *)(*(long *)(param_1 + 0x8c8) + lVar9);
      if (lVar8 != 0) {
        lVar7 = *(long *)(*(long *)(param_1 + 0x8c8) + lVar9 + 0x30);
        lVar1 = (long)param_2 * 0x828 + 0x790 + lVar3;
        lVar4 = FUN_71005fb2f4(*(long *)(param_1 + 0x98) + (long)param_2 * 0x828,
                               (long *)(*(long *)(param_1 + 0x98) + lVar1),lVar7);
        if (lVar4 != 0) {
          thunk_EXT_FUN_02e95df0(lVar4,lVar8,lVar7);
          uVar2 = *puVar6;
          FUN_71005fd4d4(param_3,uVar2,0,*(long *)(param_1 + 0x98) + lVar1,lVar7);
          FUN_71005fd4d4(param_3,uVar2,4,*(long *)(param_1 + 0x98) + lVar1,lVar7);
          FUN_71005fd4d4(param_3,uVar2,5,*(long *)(param_1 + 0x98) + lVar1,lVar7);
          ret_71005FB3B0();
        }
      }
      lVar3 = lVar3 + 0x10;
      lVar9 = lVar9 + 8;
      puVar6 = puVar6 + 1;
    } while (lVar3 != 0x60);
  }
  return;
}



void FUN_71005f43d0(long param_1,int param_2,long param_3,long param_4,ulong param_5)

{
  long lVar1;
  undefined8 uVar2;
  
  thunk_EXT_FUN_02e95df0(*(long *)(param_1 + 0x98) + (long)param_2 * 0x828 + 0x530,param_4,0x250);
  lVar1 = *(long *)(param_1 + 0x98) + (long)param_2 * 0x828;
  lVar1 = FUN_71005fb2f4(lVar1,(long *)(lVar1 + 0x780),0x250);
  if (lVar1 != 0) {
    uVar2 = *(undefined8 *)(param_1 + 0x7c);
    *(undefined8 *)(param_4 + 0x208) = *(undefined8 *)(param_1 + 0x84);
    *(undefined8 *)(param_4 + 0x200) = uVar2;
    uVar2 = *(undefined8 *)(param_1 + 0x910);
    *(undefined8 *)(param_4 + 0x218) = *(undefined8 *)(param_1 + 0x918);
    *(undefined8 *)(param_4 + 0x210) = uVar2;
    uVar2 = *(undefined8 *)(param_1 + 0x920);
    *(undefined8 *)(param_4 + 0x228) = *(undefined8 *)(param_1 + 0x928);
    *(undefined8 *)(param_4 + 0x220) = uVar2;
    uVar2 = *(undefined8 *)(param_1 + 0x930);
    *(undefined8 *)(param_4 + 0x238) = *(undefined8 *)(param_1 + 0x938);
    *(undefined8 *)(param_4 + 0x230) = uVar2;
    uVar2 = *(undefined8 *)(param_1 + 0x940);
    *(undefined8 *)(param_4 + 0x248) = *(undefined8 *)(param_1 + 0x948);
    *(undefined8 *)(param_4 + 0x240) = uVar2;
    thunk_EXT_FUN_02e95df0(lVar1,param_4,0x250);
    if ((param_5 & 1) != 0) {
      FUN_71005fd4d4(param_3,5,0,*(long *)(param_1 + 0x98) + (long)param_2 * 0x828 + 0x780,0x250);
      FUN_71005fd4d4(param_3,5,4,*(long *)(param_1 + 0x98) + (long)param_2 * 0x828 + 0x780,0x250);
    }
    ret_71005FB3B0();
  }
  if ((param_5 & 1) != 0) {
    lVar1 = *(long *)(param_1 + 0x8c8);
    if (*(long *)(lVar1 + (long)param_2 * 0xc0) != 0) {
      lVar1 = lVar1 + (long)param_2 * 0xc0;
      uVar2 = *(undefined8 *)(lVar1 + 0x30);
      lVar1 = lVar1 + 0x60;
      FUN_71005fd4d4(param_3,0xb,0,lVar1,uVar2);
      FUN_71005fd4d4(param_3,0xb,4,lVar1,uVar2);
      lVar1 = *(long *)(param_1 + 0x8c8);
    }
    if (*(long *)(lVar1 + (long)param_2 * 0xc0 + 8) != 0) {
      lVar1 = lVar1 + (long)param_2 * 0xc0;
      uVar2 = *(undefined8 *)(lVar1 + 0x38);
      lVar1 = lVar1 + 0x70;
      FUN_71005fd4d4(param_3,0xc,0,lVar1,uVar2);
      FUN_71005fd4d4(param_3,0xc,4,lVar1,uVar2);
      lVar1 = *(long *)(param_1 + 0x8c8);
    }
    if (*(long *)(lVar1 + (long)param_2 * 0xc0 + 0x10) != 0) {
      lVar1 = lVar1 + (long)param_2 * 0xc0;
      uVar2 = *(undefined8 *)(lVar1 + 0x40);
      lVar1 = lVar1 + 0x80;
      FUN_71005fd4d4(param_3,0xd,0,lVar1,uVar2);
      FUN_71005fd4d4(param_3,0xd,4,lVar1,uVar2);
      lVar1 = *(long *)(param_1 + 0x8c8);
    }
    if (*(long *)(lVar1 + (long)param_2 * 0xc0 + 0x18) != 0) {
      lVar1 = lVar1 + (long)param_2 * 0xc0;
      uVar2 = *(undefined8 *)(lVar1 + 0x48);
      lVar1 = lVar1 + 0x90;
      FUN_71005fd4d4(param_3,4,0,lVar1,uVar2);
      FUN_71005fd4d4(param_3,4,4,lVar1,uVar2);
      lVar1 = *(long *)(param_1 + 0x8c8);
    }
    if (*(long *)(lVar1 + (long)param_2 * 0xc0 + 0x20) != 0) {
      lVar1 = lVar1 + (long)param_2 * 0xc0;
      uVar2 = *(undefined8 *)(lVar1 + 0x50);
      lVar1 = lVar1 + 0xa0;
      FUN_71005fd4d4(param_3,3,0,lVar1,uVar2);
      FUN_71005fd4d4(param_3,3,4,lVar1,uVar2);
      lVar1 = *(long *)(param_1 + 0x8c8);
    }
    if (*(long *)(lVar1 + (long)param_2 * 0xc0 + 0x28) != 0) {
      lVar1 = lVar1 + (long)param_2 * 0xc0;
      uVar2 = *(undefined8 *)(lVar1 + 0x58);
      lVar1 = lVar1 + 0xb0;
      FUN_71005fd4d4(param_3,2,0,lVar1,uVar2);
      FUN_71005fd4d4(param_3,2,4,lVar1,uVar2);
      return;
    }
  }
  return;
}



void FUN_71005f4724(long param_1,int param_2,long param_3,long param_4,ulong param_5)

{
  long lVar1;
  undefined8 uVar2;
  
  thunk_EXT_FUN_02e95df0(*(long *)(param_1 + 0x98) + (long)param_2 * 0x828 + 0x530,param_4,0x250);
  lVar1 = *(long *)(param_1 + 0x98) + (long)param_2 * 0x828;
  lVar1 = FUN_71005fb2f4(lVar1,(long *)(lVar1 + 0x780),0x250);
  if (lVar1 != 0) {
    uVar2 = *(undefined8 *)(param_1 + 0x7c);
    *(undefined8 *)(param_4 + 0x208) = *(undefined8 *)(param_1 + 0x84);
    *(undefined8 *)(param_4 + 0x200) = uVar2;
    uVar2 = *(undefined8 *)(param_1 + 0x910);
    *(undefined8 *)(param_4 + 0x218) = *(undefined8 *)(param_1 + 0x918);
    *(undefined8 *)(param_4 + 0x210) = uVar2;
    uVar2 = *(undefined8 *)(param_1 + 0x920);
    *(undefined8 *)(param_4 + 0x228) = *(undefined8 *)(param_1 + 0x928);
    *(undefined8 *)(param_4 + 0x220) = uVar2;
    uVar2 = *(undefined8 *)(param_1 + 0x930);
    *(undefined8 *)(param_4 + 0x238) = *(undefined8 *)(param_1 + 0x938);
    *(undefined8 *)(param_4 + 0x230) = uVar2;
    uVar2 = *(undefined8 *)(param_1 + 0x940);
    *(undefined8 *)(param_4 + 0x248) = *(undefined8 *)(param_1 + 0x948);
    *(undefined8 *)(param_4 + 0x240) = uVar2;
    thunk_EXT_FUN_02e95df0(lVar1,param_4,0x250);
    if ((param_5 & 1) != 0) {
      FUN_71005fd4d4(param_3,5,5,*(long *)(param_1 + 0x98) + (long)param_2 * 0x828 + 0x780,0x250);
    }
    ret_71005FB3B0();
  }
  if ((param_5 & 1) != 0) {
    lVar1 = *(long *)(param_1 + 0x8c8);
    if (*(long *)(lVar1 + (long)param_2 * 0xc0) != 0) {
      lVar1 = lVar1 + (long)param_2 * 0xc0;
      FUN_71005fd4d4(param_3,0xb,5,lVar1 + 0x60,*(undefined8 *)(lVar1 + 0x30));
      lVar1 = *(long *)(param_1 + 0x8c8);
    }
    if (*(long *)(lVar1 + (long)param_2 * 0xc0 + 8) != 0) {
      lVar1 = lVar1 + (long)param_2 * 0xc0;
      FUN_71005fd4d4(param_3,0xc,5,lVar1 + 0x70,*(undefined8 *)(lVar1 + 0x38));
      lVar1 = *(long *)(param_1 + 0x8c8);
    }
    if (*(long *)(lVar1 + (long)param_2 * 0xc0 + 0x10) != 0) {
      lVar1 = lVar1 + (long)param_2 * 0xc0;
      FUN_71005fd4d4(param_3,0xd,5,lVar1 + 0x80,*(undefined8 *)(lVar1 + 0x40));
      lVar1 = *(long *)(param_1 + 0x8c8);
    }
    if (*(long *)(lVar1 + (long)param_2 * 0xc0 + 0x18) != 0) {
      lVar1 = lVar1 + (long)param_2 * 0xc0;
      FUN_71005fd4d4(param_3,4,5,lVar1 + 0x90,*(undefined8 *)(lVar1 + 0x48));
      lVar1 = *(long *)(param_1 + 0x8c8);
    }
    if (*(long *)(lVar1 + (long)param_2 * 0xc0 + 0x20) != 0) {
      lVar1 = lVar1 + (long)param_2 * 0xc0;
      FUN_71005fd4d4(param_3,3,5,lVar1 + 0xa0,*(undefined8 *)(lVar1 + 0x50));
      lVar1 = *(long *)(param_1 + 0x8c8);
    }
    if (*(long *)(lVar1 + (long)param_2 * 0xc0 + 0x28) != 0) {
      lVar1 = lVar1 + (long)param_2 * 0xc0;
      FUN_71005fd4d4(param_3,2,5,lVar1 + 0xb0,*(undefined8 *)(lVar1 + 0x58));
      return;
    }
  }
  return;
}



void FUN_71005f4988(long param_1,int param_2,long param_3,long param_4)

{
  char cVar1;
  undefined8 uVar2;
  
  cVar1 = *(char *)(param_4 + 0x7b);
  if (*(char *)(param_4 + 0x39) != -1) {
    FUN_71005fd4d4(param_3,(int)*(char *)(param_4 + 0x39),0,
                   *(long *)(param_1 + 0x98) + (long)param_2 * 0x828 + 0x780,0x250);
  }
  if (cVar1 != -1) {
    FUN_71005fd4d4(param_3,(int)cVar1,4,*(long *)(param_1 + 0x98) + (long)param_2 * 0x828 + 0x780,
                   0x250);
  }
  cVar1 = *(char *)(param_4 + 0x81);
  uVar2 = *(undefined8 *)(*(long *)(param_1 + 0x8c8) + (long)param_2 * 0xc0 + 0x30);
  if (*(char *)(param_4 + 0x3f) != -1) {
    FUN_71005fd4d4(param_3,(int)*(char *)(param_4 + 0x3f),0,
                   *(long *)(param_1 + 0x98) + (long)param_2 * 0x828 + 0x790,uVar2);
  }
  if (cVar1 != -1) {
    FUN_71005fd4d4(param_3,(int)cVar1,4,*(long *)(param_1 + 0x98) + (long)param_2 * 0x828 + 0x790,
                   uVar2);
  }
  cVar1 = *(char *)(param_4 + 0x82);
  uVar2 = *(undefined8 *)(*(long *)(param_1 + 0x8c8) + (long)param_2 * 0xc0 + 0x38);
  if (*(char *)(param_4 + 0x40) != -1) {
    FUN_71005fd4d4(param_3,(int)*(char *)(param_4 + 0x40),0,
                   *(long *)(param_1 + 0x98) + (long)param_2 * 0x828 + 0x7a0,uVar2);
  }
  if (cVar1 != -1) {
    FUN_71005fd4d4(param_3,(int)cVar1,4,*(long *)(param_1 + 0x98) + (long)param_2 * 0x828 + 0x7a0,
                   uVar2);
  }
  cVar1 = *(char *)(param_4 + 0x83);
  uVar2 = *(undefined8 *)(*(long *)(param_1 + 0x8c8) + (long)param_2 * 0xc0 + 0x40);
  if (*(char *)(param_4 + 0x41) != -1) {
    FUN_71005fd4d4(param_3,(int)*(char *)(param_4 + 0x41),0,
                   *(long *)(param_1 + 0x98) + (long)param_2 * 0x828 + 0x7b0,uVar2);
  }
  if (cVar1 != -1) {
    FUN_71005fd4d4(param_3,(int)cVar1,4,*(long *)(param_1 + 0x98) + (long)param_2 * 0x828 + 0x7b0,
                   uVar2);
  }
  cVar1 = *(char *)(param_4 + 0x84);
  uVar2 = *(undefined8 *)(*(long *)(param_1 + 0x8c8) + (long)param_2 * 0xc0 + 0x48);
  if (*(char *)(param_4 + 0x42) != -1) {
    FUN_71005fd4d4(param_3,(int)*(char *)(param_4 + 0x42),0,
                   *(long *)(param_1 + 0x98) + (long)param_2 * 0x828 + 0x7c0,uVar2);
  }
  if (cVar1 != -1) {
    FUN_71005fd4d4(param_3,(int)cVar1,4,*(long *)(param_1 + 0x98) + (long)param_2 * 0x828 + 0x7c0,
                   uVar2);
  }
  cVar1 = *(char *)(param_4 + 0x85);
  uVar2 = *(undefined8 *)(*(long *)(param_1 + 0x8c8) + (long)param_2 * 0xc0 + 0x50);
  if (*(char *)(param_4 + 0x43) != -1) {
    FUN_71005fd4d4(param_3,(int)*(char *)(param_4 + 0x43),0,
                   *(long *)(param_1 + 0x98) + (long)param_2 * 0x828 + 2000,uVar2);
  }
  if (cVar1 != -1) {
    FUN_71005fd4d4(param_3,(int)cVar1,4,*(long *)(param_1 + 0x98) + (long)param_2 * 0x828 + 2000,
                   uVar2);
  }
  cVar1 = *(char *)(param_4 + 0x86);
  uVar2 = *(undefined8 *)(*(long *)(param_1 + 0x8c8) + (long)param_2 * 0xc0 + 0x58);
  if (*(char *)(param_4 + 0x44) != -1) {
    FUN_71005fd4d4(param_3,(int)*(char *)(param_4 + 0x44),0,
                   *(long *)(param_1 + 0x98) + (long)param_2 * 0x828 + 0x7e0,uVar2);
  }
  if (cVar1 == -1) {
    return;
  }
  FUN_71005fd4d4(param_3,(int)cVar1,4,*(long *)(param_1 + 0x98) + (long)param_2 * 0x828 + 0x7e0,
                 uVar2);
  return;
}



void FUN_71005f4ccc(long param_1,int param_2,long param_3,long param_4)

{
  int iVar1;
  
  if (*(char *)(param_4 + 0x42) == -1) {
    iVar1 = (int)*(char *)(param_4 + 0x48);
    if (iVar1 == -1) goto LAB_71005f4d58;
  }
  else {
    FUN_71005fd4d4(param_3,(int)*(char *)(param_4 + 0x42),5,
                   *(long *)(param_1 + 0x98) + (long)param_2 * 0x828 + 0x780,0x250);
    iVar1 = (int)*(char *)(param_4 + 0x48);
    if (*(char *)(param_4 + 0x48) == -1) goto LAB_71005f4d58;
  }
  FUN_71005fd4d4(param_3,iVar1,5,*(long *)(param_1 + 0x98) + (long)param_2 * 0x828 + 0x790,
                 *(undefined8 *)(*(long *)(param_1 + 0x8c8) + (long)param_2 * 0xc0 + 0x30));
LAB_71005f4d58:
  if (*(char *)(param_4 + 0x49) != -1) {
    FUN_71005fd4d4(param_3,(int)*(char *)(param_4 + 0x49),5,
                   *(long *)(param_1 + 0x98) + (long)param_2 * 0x828 + 0x7a0,
                   *(undefined8 *)(*(long *)(param_1 + 0x8c8) + (long)param_2 * 0xc0 + 0x38));
  }
  if (*(char *)(param_4 + 0x4a) != -1) {
    FUN_71005fd4d4(param_3,(int)*(char *)(param_4 + 0x4a),5,
                   *(long *)(param_1 + 0x98) + (long)param_2 * 0x828 + 0x7b0,
                   *(undefined8 *)(*(long *)(param_1 + 0x8c8) + (long)param_2 * 0xc0 + 0x40));
  }
  if (*(char *)(param_4 + 0x4b) != -1) {
    FUN_71005fd4d4(param_3,(int)*(char *)(param_4 + 0x4b),5,
                   *(long *)(param_1 + 0x98) + (long)param_2 * 0x828 + 0x7c0,
                   *(undefined8 *)(*(long *)(param_1 + 0x8c8) + (long)param_2 * 0xc0 + 0x48));
  }
  if (*(char *)(param_4 + 0x4c) != -1) {
    FUN_71005fd4d4(param_3,(int)*(char *)(param_4 + 0x4c),5,
                   *(long *)(param_1 + 0x98) + (long)param_2 * 0x828 + 2000,
                   *(undefined8 *)(*(long *)(param_1 + 0x8c8) + (long)param_2 * 0xc0 + 0x50));
  }
  if (*(char *)(param_4 + 0x4d) == -1) {
    return;
  }
  FUN_71005fd4d4(param_3,(int)*(char *)(param_4 + 0x4d),5,
                 *(long *)(param_1 + 0x98) + (long)param_2 * 0x828 + 0x7e0,
                 *(undefined8 *)(*(long *)(param_1 + 0x8c8) + (long)param_2 * 0xc0 + 0x58));
  return;
}



void FUN_71005f4ea0(long param_1,int param_2,int param_3,uint param_4,ulong *param_5)

{
  long *plVar1;
  int *piVar2;
  byte bVar3;
  undefined1 auVar4 [16];
  undefined4 uVar5;
  uint uVar6;
  long lVar7;
  long lVar8;
  long *plVar9;
  long *plVar10;
  code *pcVar11;
  float fVar12;
  float fVar13;
  float fVar14;
  float fVar15;
  undefined1 auVar16 [16];
  
  plVar9 = *(long **)(param_1 + (long)param_3 * 8 + 0xb8);
  if (plVar9 != (long *)0x0) {
    Hint_Prefetch(plVar9,0,0,0);
    lVar8 = *(long *)(param_1 + 0x98);
    pcVar11 = *(code **)(param_1 + 0x9a0);
    lVar7 = lVar8 + (long)param_2 * 0x828;
    plVar1 = (long *)(lVar7 + 0x808);
    piVar2 = (int *)(lVar7 + 0x814);
    if (pcVar11 == (code *)0x0) {
      do {
        plVar10 = (long *)*plVar9;
        if (plVar10 != (long *)0x0) {
          Hint_Prefetch(plVar10,0,0,0);
        }
        if ((((*(uint *)(lVar7 + 0x81c) & *(uint *)((long)plVar9 + 0x34)) != 0) &&
            ((*(uint *)(plVar9 + 6) & param_4) != 0)) &&
           (((*param_5 & plVar9[4]) != 0 && (plVar9[5] == -1)))) {
          *(long **)(*plVar1 + (long)*piVar2 * 0x10) = plVar9;
          bVar3 = *(byte *)((long)plVar9 + 0x66);
          fVar12 = (float)plVar9[0x26] * *(float *)(lVar7 + 0x550);
          fVar13 = (float)((ulong)plVar9[0x26] >> 0x20) * *(float *)(lVar7 + 0x554);
          fVar14 = (float)plVar9[0x27] * *(float *)(lVar7 + 0x558);
          fVar15 = (float)((ulong)plVar9[0x27] >> 0x20) * 0.0;
          auVar16._4_4_ = fVar13;
          auVar16._0_4_ = fVar12;
          auVar16._8_4_ = fVar14;
          auVar16._12_4_ = fVar15;
          auVar4._4_4_ = fVar13;
          auVar4._0_4_ = fVar12;
          auVar4._8_4_ = fVar14;
          auVar4._12_4_ = fVar15;
          auVar16 = NEON_ext(auVar16,auVar4,8,1);
          fVar13 = *(float *)(plVar9 + 0x4c) +
                   *(float *)(*(long *)plVar9[2] + 0xa4) +
                   auVar16._0_4_ + fVar12 + auVar16._4_4_ + fVar13 + *(float *)(lVar7 + 0x55c);
          fVar12 = 0.0;
          if (fVar13 <= 0.0) {
            fVar12 = fVar13;
          }
          uVar6 = FUN_71005df0f0((uint)fVar12);
          *(uint *)(*plVar1 + (long)*piVar2 * 0x10 + 8) = uVar6 | (uint)bVar3 << 0x18;
          *piVar2 = *piVar2 + 1;
        }
        plVar9 = plVar10;
      } while (plVar10 != (long *)0x0);
    }
    else {
      do {
        plVar10 = (long *)*plVar9;
        if (plVar10 != (long *)0x0) {
          Hint_Prefetch(plVar10,0,0,0);
        }
        if (((((*(uint *)(lVar7 + 0x81c) & *(uint *)((long)plVar9 + 0x34)) != 0) &&
             ((*(uint *)(plVar9 + 6) & param_4) != 0)) && ((*param_5 & plVar9[4]) != 0)) &&
           (plVar9[5] == -1)) {
          *(long **)(*plVar1 + (long)*piVar2 * 0x10) = plVar9;
          uVar5 = (*pcVar11)(plVar9,lVar7 + 0x530);
          *(undefined4 *)(*plVar1 + (long)*piVar2 * 0x10 + 8) = uVar5;
          *piVar2 = *piVar2 + 1;
        }
        plVar9 = plVar10;
      } while (plVar10 != (long *)0x0);
    }
    lVar8 = lVar8 + (long)param_2 * 0x828;
    *(uint *)(lVar8 + 0x818) = *(uint *)(lVar8 + 0x818) | param_4;
  }
  return;
}



void FUN_71005f50a0(long param_1,int param_2,long *param_3,int *param_4,uint param_5,
                   undefined8 param_6)

{
  uint *puVar1;
  uint uVar2;
  int iVar3;
  undefined8 *puVar4;
  long lVar5;
  ulong uVar6;
  long lVar7;
  long lVar8;
  long lVar9;
  long lVar10;
  long lVar11;
  long lVar12;
  long *plVar13;
  undefined1 auStack_64 [4];
  
  lVar9 = *(long *)(param_1 + 0x98);
  lVar7 = lVar9 + (long)param_2 * 0x828;
  iVar3 = *(int *)(lVar7 + 0x814);
  if (iVar3 != 0) {
    puVar1 = (uint *)(lVar7 + 0x814);
    lVar7 = lVar9 + (long)param_2 * 0x828;
    puVar4 = *(undefined8 **)(lVar7 + 0x808);
    FUN_71005f5be0(puVar4,puVar4 + (long)iVar3 * 2,auStack_64,LZCOUNT((long)iVar3) * -2 + 0x7e,1);
    if (param_2 < *(int *)(param_1 + 0x33f8)) {
      lVar11 = (long)param_2 * 0x30;
      *(undefined4 *)(*(long *)(param_1 + 0xa0) + lVar11 + 0x28) =
           *(undefined4 *)(*(long *)(param_1 + 0x98) + (long)param_2 * 0x828 + 0x81c);
      *(undefined1 *)(*(long *)(param_1 + 0xa0) + lVar11 + 0x2c) =
           *(undefined1 *)(*(long *)(param_1 + 0x98) + (long)param_2 * 0x828 + 0x821);
      *(undefined4 *)(*(long *)(param_1 + 0xa0) + lVar11 + 0x24) =
           *(undefined4 *)(*(long *)(param_1 + 0x98) + (long)param_2 * 0x828 + 0x810);
      *(undefined8 *)(*(long *)(param_1 + 0xa0) + lVar11) =
           *(undefined8 *)(*(long *)(param_1 + 0x98) + (long)param_2 * 0x828 + 0x7f0);
      *(undefined8 *)(*(long *)(param_1 + 0xa0) + lVar11 + 8) =
           *(undefined8 *)(*(long *)(param_1 + 0x98) + (long)param_2 * 0x828 + 0x7f8);
      plVar13 = (long *)(*(long *)(param_1 + 0xa0) + lVar11);
      uVar2 = *puVar1;
    }
    else {
      plVar13 = (long *)0x0;
      uVar2 = *puVar1;
    }
    if (0 < (int)uVar2) {
      uVar6 = (ulong)uVar2;
      lVar11 = 0;
      lVar12 = 0;
      do {
        lVar8 = *(long *)(lVar7 + 0x808);
        lVar5 = *(long *)(lVar8 + lVar11);
        lVar10 = *(long *)(lVar5 + 8);
        if (lVar10 != 0) {
          Hint_Prefetch(lVar10,0,0,0);
          Hint_Prefetch(lVar10 + 0x40,0,0,0);
          Hint_Prefetch(lVar10 + 0x80,0,0,0);
          Hint_Prefetch(lVar10 + 0xc0,0,0,0);
        }
        lVar12 = lVar12 + 1;
        if (lVar12 < (int)uVar6) {
          lVar8 = *(long *)(lVar8 + lVar11 + 0x10);
          Hint_Prefetch(lVar8,0,0,0);
          Hint_Prefetch(lVar8 + 0x40,0,0,0);
        }
        FUN_71005d3140(lVar5,param_3,*(uint *)(lVar9 + (long)param_2 * 0x828 + 0x818),param_5 & 1,
                       param_6,plVar13,(char *)(param_1 + 0x78),param_1 + 0x7c,param_4,
                       *(undefined **)(param_1 + 0x980),*(undefined **)(param_1 + 0x968),
                       *(undefined **)(param_1 + 0x990));
        uVar6 = (ulong)(int)*puVar1;
        lVar11 = lVar11 + 0x10;
      } while (lVar12 < (long)uVar6);
    }
    *puVar1 = 0;
  }
  *(undefined4 *)(lVar9 + (long)param_2 * 0x828 + 0x818) = 0;
  return;
}



void FUN_71005f52b0(long param_1,long param_2,long *param_3,uint param_4,undefined8 param_5,
                   long *param_6,int *param_7)

{
  FUN_71005c961c(param_3,param_2,param_4,param_5,param_6,(char *)(param_1 + 0x78),param_1 + 0x7c,
                 param_7);
  return;
}



void FUN_71005f5300(long param_1)

{
  long lVar1;
  long lVar2;
  
  if (0 < *(int *)(param_1 + 0x33f8)) {
    lVar1 = 0;
    lVar2 = 0;
    do {
      FUN_71005fb254(*(long *)(param_1 + 0x98) + lVar1);
      lVar2 = lVar2 + 1;
      lVar1 = lVar1 + 0x828;
    } while (lVar2 < *(int *)(param_1 + 0x33f8));
  }
  return;
}



long FUN_71005f5360(long param_1,int param_2,long *param_3,long param_4)

{
  long lVar1;
  
  if (param_2 < *(int *)(param_1 + 0x33f8)) {
    lVar1 = FUN_71005fb2f4(*(long *)(param_1 + 0x98) + (long)param_2 * 0x828,param_3,param_4);
    return lVar1;
  }
  return 0;
}



ulong FUN_71005f538c(long param_1,undefined8 param_2,int param_3)

{
  long lVar1;
  ulong uVar2;
  
  lVar1 = *(long *)(*(long *)(param_1 + 0x33a8) + (long)param_3 * 8);
  if (lVar1 != 0) {
    uVar2 = FUN_71005e7d60(lVar1,param_2);
    return uVar2;
  }
  return 0xffffffff;
}



void FUN_71005f53a4(long param_1,byte param_2,undefined4 param_3,undefined8 param_4)

{
  if (param_2 < 8) {
    *(undefined4 *)(param_1 + 13000 + (ulong)param_2 * 4) = param_3;
    *(undefined8 *)(param_1 + 13000 + (ulong)param_2 * 8 + 0x20) = param_4;
  }
  return;
}



void FUN_71005f53cc(long param_1,uint param_2,long param_3,byte param_4,undefined8 param_5,
                   uint param_6)

{
  int local_20 [3];
  undefined2 local_14;
  
  local_20[0] = -1;
  local_20[1] = -1;
  local_20[2] = 0xffffffff;
  local_14 = 0x100;
  FUN_71005f5410(param_1,param_2,param_3,param_4,param_5,local_20,param_6);
  return;
}



void FUN_71005f5410(long param_1,uint param_2,long param_3,byte param_4,undefined8 param_5,
                   int *param_6,uint param_7)

{
  long *plVar1;
  long lVar2;
  ulong uVar3;
  long *plVar4;
  long *plVar5;
  
  uVar3 = (ulong)param_4;
  plVar4 = *(long **)(param_1 + uVar3 * 0x38 + 0xc98);
  if (plVar4 == (long *)0x0 || *(char *)(param_1 + 0x8c) == '\0') {
    return;
  }
  Hint_Prefetch(plVar4,0,0,0);
  Hint_Prefetch(plVar4 + 8,0,0,0);
  Hint_Prefetch(plVar4 + 0x10,0,0,0);
  Hint_Prefetch(plVar4 + 0x18,0,0,0);
  plVar1 = (long *)(*(long *)(param_1 + 0xa0) + (ulong)param_2 * 0x30);
  if ((int)param_2 < 0) {
    plVar1 = (long *)0x0;
  }
  if (*(char *)((long)param_6 + 0xd) != '\0') {
    FUN_71005fd1c4(param_3,0x40);
  }
  if ((char)param_6[3] != '\0') {
    param_6[0] = -1;
    param_6[1] = -1;
    param_6[2] = -1;
  }
  do {
    lVar2 = *plVar4;
    plVar5 = (long *)plVar4[uVar3 + 2];
    if (lVar2 != 0) {
      Hint_Prefetch(lVar2,0,0,0);
      Hint_Prefetch(lVar2 + 0x40,0,0,0);
    }
    if (plVar5 != (long *)0x0) {
      Hint_Prefetch(plVar5,0,0,0);
      Hint_Prefetch(plVar5 + 8,0,0,0);
      Hint_Prefetch(plVar5 + 0x10,0,0,0);
      Hint_Prefetch(plVar5 + 0x18,0,0,0);
    }
    if (((lVar2 != 0) && ((*(uint *)(plVar4 + 0xe) & param_7) != 0)) &&
       ((*(byte *)((long)plVar4 + 0x32) & 1) != 0)) {
      FUN_71005cfc34((long *)plVar4[0xe1],param_3,plVar4,*(long **)(plVar4[8] + uVar3 * 8 + 0x50),
                     param_4,*(int *)(lVar2 + 0x3c),1,param_5,0,plVar1,param_6,
                     *(undefined **)(param_1 + 0x970));
    }
    plVar4 = plVar5;
  } while (plVar5 != (long *)0x0);
  FUN_71005fd19c(param_3,0x40);
  return;
}



void FUN_71005f5590(undefined8 param_1,undefined *param_2,undefined8 param_3)

{
  FUN_71005d1b80(param_2,param_3);
  return;
}



void FUN_71005f559c(long param_1)

{
                    // WARNING: Could not recover jumptable at 0x0071005f55a8. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(**(long **)(param_1 + 0x8f0) + 0x10))();
  return;
}



void FUN_71005f55d0(long *param_1)

{
  long lVar1;
  
  lVar1 = DAT_7103a6fa38;
  *param_1 = DAT_7103a6fc10 + 0x10;
  param_1[2] = lVar1 + 0x10;
  thunk_EXT_FUN_02e95df0(param_1 + 3);
  FUN_71024d49c0((long)param_1);
  return;
}



void FUN_71005f5a7c(long param_1,long param_2,undefined8 param_3,long param_4,long param_5,
                   long param_6,undefined8 *param_7,undefined8 param_8,undefined8 param_9)

{
  char cVar1;
  undefined8 *puVar2;
  undefined8 local_c0;
  undefined8 uStack_b8;
  undefined8 local_b0;
  undefined8 uStack_a8;
  undefined8 local_a0;
  undefined8 uStack_98;
  undefined8 local_90;
  undefined8 uStack_88;
  undefined8 local_80;
  undefined8 uStack_78;
  undefined8 local_70;
  undefined8 uStack_68;
  undefined8 local_60;
  undefined8 uStack_58;
  long local_50 [2];
  
  FUN_71005ebbd0(&local_c0,param_5,param_6,param_7);
  local_50[0] = 0;
  local_50[1] = 0;
  puVar2 = (undefined8 *)FUN_71005fb2f4(param_2,local_50,0x70);
  if (puVar2 != (undefined8 *)0x0) {
    *puVar2 = local_c0;
    puVar2[1] = uStack_b8;
    puVar2[4] = local_a0;
    puVar2[5] = uStack_98;
    puVar2[2] = local_b0;
    puVar2[3] = uStack_a8;
    puVar2[8] = local_80;
    puVar2[9] = uStack_78;
    puVar2[6] = local_90;
    puVar2[7] = uStack_88;
    puVar2[0xc] = local_60;
    puVar2[0xd] = uStack_58;
    puVar2[10] = local_70;
    puVar2[0xb] = uStack_68;
    cVar1 = *(char *)(param_4 + 0x7f);
    if (*(char *)(param_4 + 0x3d) != -1) {
      FUN_71005fd4d4(param_1,(int)*(char *)(param_4 + 0x3d),0,local_50,0x70);
    }
    if (cVar1 != -1) {
      FUN_71005fd4d4(param_1,(int)cVar1,4,local_50,0x70);
    }
    ret_71005FB3B0();
    FUN_71005fc404(param_1,4,1,param_8,*(undefined4 *)(param_7 + 0x11),0);
    if (*(char *)(param_5 + 2) == '\x01') {
      FUN_71005fc404(param_1,4,1,param_9,*(undefined4 *)(param_7 + 0x11),0);
    }
    return;
  }
  ret_71005DEE40();
  return;
}



// WARNING: Type propagation algorithm not settling

void FUN_71005f5be0(undefined8 *param_1,undefined8 *param_2,undefined8 param_3,long param_4,
                   uint param_5)

{
  long lVar1;
  undefined8 uVar2;
  undefined8 uVar3;
  undefined8 uVar4;
  uint uVar5;
  undefined4 uVar6;
  bool bVar7;
  bool bVar8;
  uint uVar9;
  long lVar10;
  ulong uVar11;
  uint *puVar12;
  undefined8 *puVar13;
  undefined8 uVar14;
  ulong uVar15;
  uint *puVar16;
  undefined8 *puVar17;
  undefined8 *puVar18;
  uint *puVar19;
  undefined8 *puVar20;
  undefined8 *puVar21;
  long lVar22;
  undefined8 *puVar23;
  undefined8 *puVar24;
  undefined8 local_70;
  undefined8 uStack_68;
  
LAB_71005f5c14:
  puVar23 = param_2 + -2;
  puVar18 = param_2 + -4;
  puVar24 = param_2 + -6;
  puVar20 = param_1;
LAB_71005f5c28:
  param_1 = puVar20;
  uVar11 = (long)param_2 - (long)param_1;
  switch((long)uVar11 >> 4) {
  case 0:
  case 1:
    goto switchD_71005f62dc_caseD_0;
  case 2:
    if (*(uint *)(param_2 + -1) <= *(uint *)(param_1 + 1)) {
      return;
    }
    uVar14 = *param_1;
    uVar2 = param_1[1];
    uVar3 = param_2[-1];
    *param_1 = param_2[-2];
    param_1[1] = uVar3;
    param_2[-2] = uVar14;
    param_2[-1] = uVar2;
    return;
  case 3:
    uVar9 = *(uint *)(param_1 + 3);
    puVar20 = param_1 + 2;
    if (*(uint *)(param_1 + 1) < uVar9) {
      if (uVar9 < *(uint *)(param_2 + -1)) {
        uVar14 = *param_1;
        uVar2 = param_1[1];
        uVar3 = param_2[-1];
        *param_1 = *puVar23;
        param_1[1] = uVar3;
        *puVar23 = uVar14;
        param_2[-1] = uVar2;
        return;
      }
      uVar14 = *param_1;
      uVar2 = param_1[1];
      *param_1 = *puVar20;
      param_1[1] = param_1[3];
      *puVar20 = uVar14;
      param_1[3] = uVar2;
      if (*(uint *)(param_2 + -1) <= *(uint *)(param_1 + 3)) {
        return;
      }
      uVar14 = *puVar20;
      uVar2 = param_1[3];
      uVar3 = param_2[-1];
      *puVar20 = *puVar23;
      param_1[3] = uVar3;
      *puVar23 = uVar14;
      param_2[-1] = uVar2;
      return;
    }
    if (*(uint *)(param_2 + -1) <= uVar9) {
      return;
    }
    uVar14 = *puVar20;
    uVar2 = param_1[3];
    uVar3 = param_2[-1];
    *puVar20 = *puVar23;
    param_1[3] = uVar3;
    *puVar23 = uVar14;
    param_2[-1] = uVar2;
    break;
  case 4:
    uVar9 = *(uint *)(param_1 + 3);
    puVar20 = param_1 + 2;
    puVar18 = param_1 + 4;
    uVar5 = *(uint *)(param_1 + 5);
    if (*(uint *)(param_1 + 1) < uVar9) {
      if (uVar9 < uVar5) {
        uVar14 = *param_1;
        uVar2 = param_1[1];
        *param_1 = *puVar18;
        param_1[1] = param_1[5];
        *puVar18 = uVar14;
        param_1[5] = uVar2;
      }
      else {
        uVar14 = *param_1;
        uVar2 = param_1[1];
        *param_1 = *puVar20;
        param_1[1] = param_1[3];
        *puVar20 = uVar14;
        param_1[3] = uVar2;
        if (*(uint *)(param_1 + 3) < uVar5) {
          uVar14 = *puVar20;
          uVar2 = param_1[3];
          *puVar20 = *puVar18;
          param_1[3] = param_1[5];
          *puVar18 = uVar14;
          param_1[5] = uVar2;
        }
      }
    }
    else if (uVar9 < uVar5) {
      uVar14 = *puVar20;
      uVar2 = param_1[3];
      *puVar20 = *puVar18;
      param_1[3] = param_1[5];
      *puVar18 = uVar14;
      param_1[5] = uVar2;
      if (*(uint *)(param_1 + 1) < *(uint *)(param_1 + 3)) {
        uVar14 = *param_1;
        uVar2 = param_1[1];
        *param_1 = *puVar20;
        param_1[1] = param_1[3];
        *puVar20 = uVar14;
        param_1[3] = uVar2;
      }
    }
    if (*(uint *)(param_2 + -1) <= *(uint *)(param_1 + 5)) {
      return;
    }
    uVar14 = *puVar18;
    uVar2 = param_1[5];
    uVar3 = param_2[-1];
    *puVar18 = *puVar23;
    param_1[5] = uVar3;
    *puVar23 = uVar14;
    param_2[-1] = uVar2;
    if (*(uint *)(param_1 + 5) <= *(uint *)(param_1 + 3)) {
      return;
    }
    uVar14 = *puVar20;
    uVar2 = param_1[3];
    *puVar20 = *puVar18;
    param_1[3] = param_1[5];
    *puVar18 = uVar14;
    param_1[5] = uVar2;
    break;
  case 5:
    FUN_71005f6a50(param_1,param_1 + 2,param_1 + 4,param_1 + 6,puVar23);
    return;
  default:
    goto switchD_71005f62dc_default;
  }
  if (*(uint *)(param_1 + 3) <= *(uint *)(param_1 + 1)) {
    return;
  }
  uVar14 = *param_1;
  uVar2 = param_1[1];
  *param_1 = param_1[2];
  param_1[1] = param_1[3];
  param_1[2] = uVar14;
  param_1[3] = uVar2;
  return;
switchD_71005f62dc_default:
  if ((long)uVar11 < 0x180) {
    puVar20 = param_1 + 2;
    if ((param_5 & 1) == 0) {
      if (param_1 == param_2 || puVar20 == param_2) {
        return;
      }
      do {
        puVar18 = puVar20;
        uVar9 = *(uint *)(param_1 + 3);
        if (*(uint *)(param_1 + 1) < uVar9) {
          uVar14 = *puVar18;
          uVar6 = *(undefined4 *)((long)param_1 + 0x1c);
          puVar20 = puVar18;
          do {
            puVar23 = puVar20;
            puVar20 = puVar23 + -2;
            *puVar23 = *puVar20;
            puVar23[1] = puVar23[-1];
          } while (*(uint *)(puVar23 + -3) < uVar9);
          *puVar20 = uVar14;
          *(uint *)(puVar23 + -1) = uVar9;
          *(undefined4 *)((long)puVar23 + -4) = uVar6;
        }
        puVar20 = puVar18 + 2;
        param_1 = puVar18;
      } while (puVar18 + 2 != param_2);
      return;
    }
    if (param_1 == param_2 || puVar20 == param_2) {
      return;
    }
    lVar10 = 0;
    puVar18 = param_1;
    goto LAB_71005f6404;
  }
  if (param_4 == 0) {
    if (param_1 == param_2) {
      return;
    }
    FUN_71005f6be0(param_1,param_2,param_2);
    return;
  }
  uVar9 = *(uint *)(param_2 + -1);
  uVar15 = (ulong)((long)uVar11 >> 4) >> 1;
  puVar20 = param_1 + uVar15 * 2;
  if (uVar11 < 0x801) {
    puVar12 = (uint *)(param_1 + 1);
    uVar5 = *puVar12;
    if (puVar12[uVar15 * 4] < uVar5) {
      if (uVar5 < uVar9) {
        local_70 = *puVar20;
        uStack_68 = puVar20[1];
        uVar14 = param_2[-1];
        *puVar20 = *puVar23;
        puVar20[1] = uVar14;
      }
      else {
        uVar14 = *puVar20;
        uVar2 = puVar20[1];
        uVar3 = param_1[1];
        *puVar20 = *param_1;
        puVar20[1] = uVar3;
        *param_1 = uVar14;
        param_1[1] = uVar2;
        if (*(uint *)(param_2 + -1) <= (uint)uVar2) goto LAB_71005f5e74;
        local_70 = *param_1;
        uStack_68 = param_1[1];
        uVar14 = param_2[-1];
        *param_1 = *puVar23;
        param_1[1] = uVar14;
      }
      *puVar23 = local_70;
      param_2[-1] = uStack_68;
    }
    else if (uVar5 < uVar9) {
      uVar14 = *param_1;
      uVar2 = param_1[1];
      uVar3 = param_2[-1];
      *param_1 = *puVar23;
      param_1[1] = uVar3;
      *puVar23 = uVar14;
      param_2[-1] = uVar2;
      if (puVar12[uVar15 * 4] < *(uint *)(param_1 + 1)) {
        uVar14 = *puVar20;
        uVar2 = puVar20[1];
        uVar3 = param_1[1];
        *puVar20 = *param_1;
        puVar20[1] = uVar3;
        *param_1 = uVar14;
        param_1[1] = uVar2;
        goto joined_r0x0071005f6068;
      }
    }
LAB_71005f5e74:
    if ((param_5 & 1) == 0) goto LAB_71005f606c;
LAB_71005f5e7c:
    uVar9 = *(uint *)(param_1 + 1);
  }
  else {
    puVar12 = (uint *)((long)(param_1 + 1) + uVar15 * 4 * 4);
    uVar5 = *puVar12;
    if (*(uint *)(param_1 + 1) < uVar5) {
      if (uVar5 < uVar9) {
        local_70 = *param_1;
        uStack_68 = param_1[1];
        uVar14 = param_2[-1];
        *param_1 = *puVar23;
        param_1[1] = uVar14;
      }
      else {
        uVar14 = *param_1;
        uVar2 = param_1[1];
        uVar3 = puVar20[1];
        *param_1 = *puVar20;
        param_1[1] = uVar3;
        *puVar20 = uVar14;
        puVar20[1] = uVar2;
        if (*(uint *)(param_2 + -1) <= *puVar12) goto LAB_71005f5da4;
        local_70 = *puVar20;
        uStack_68 = puVar20[1];
        uVar14 = param_2[-1];
        *puVar20 = *puVar23;
        puVar20[1] = uVar14;
      }
      *puVar23 = local_70;
      param_2[-1] = uStack_68;
    }
    else if (uVar5 < uVar9) {
      uVar14 = *puVar20;
      uVar2 = puVar20[1];
      uVar3 = param_2[-1];
      *puVar20 = *puVar23;
      puVar20[1] = uVar3;
      *puVar23 = uVar14;
      param_2[-1] = uVar2;
      if (*(uint *)(param_1 + 1) < *puVar12) {
        uVar14 = *param_1;
        uVar2 = param_1[1];
        uVar3 = puVar20[1];
        *param_1 = *puVar20;
        param_1[1] = uVar3;
        *puVar20 = uVar14;
        puVar20[1] = uVar2;
      }
    }
LAB_71005f5da4:
    puVar13 = param_1 + 2;
    puVar16 = (uint *)(puVar20 + -1);
    uVar9 = *puVar16;
    puVar17 = puVar20 + -2;
    if (*(uint *)(param_1 + 3) < uVar9) {
      if (uVar9 < *(uint *)(param_2 + -3)) {
        uVar14 = *puVar13;
        uVar2 = param_1[3];
        uVar3 = param_2[-3];
        *puVar13 = *puVar18;
        param_1[3] = uVar3;
        *puVar18 = uVar14;
        param_2[-3] = uVar2;
      }
      else {
        uVar14 = *puVar13;
        uVar2 = param_1[3];
        uVar3 = *(undefined8 *)puVar16;
        *puVar13 = *puVar17;
        param_1[3] = uVar3;
        *puVar17 = uVar14;
        *(undefined8 *)puVar16 = uVar2;
        if (*puVar16 < *(uint *)(param_2 + -3)) {
          uVar14 = *puVar17;
          uVar2 = *(undefined8 *)puVar16;
          uVar3 = param_2[-3];
          *puVar17 = *puVar18;
          *(undefined8 *)puVar16 = uVar3;
          *puVar18 = uVar14;
          param_2[-3] = uVar2;
        }
      }
    }
    else if (uVar9 < *(uint *)(param_2 + -3)) {
      uVar14 = *puVar17;
      uVar2 = *(undefined8 *)puVar16;
      uVar3 = param_2[-3];
      *puVar17 = *puVar18;
      *(undefined8 *)puVar16 = uVar3;
      *puVar18 = uVar14;
      param_2[-3] = uVar2;
      if (*(uint *)(param_1 + 3) < *puVar16) {
        uVar14 = *puVar13;
        uVar2 = param_1[3];
        uVar3 = *(undefined8 *)puVar16;
        *puVar13 = *puVar17;
        param_1[3] = uVar3;
        *puVar17 = uVar14;
        *(undefined8 *)puVar16 = uVar2;
      }
    }
    puVar13 = param_1 + 4;
    puVar19 = (uint *)(puVar20 + 3);
    uVar9 = *puVar19;
    puVar21 = puVar20 + 2;
    if (*(uint *)(param_1 + 5) < uVar9) {
      if (uVar9 < *(uint *)(param_2 + -5)) {
        uVar14 = *puVar13;
        uVar2 = param_1[5];
        uVar3 = param_2[-5];
        *puVar13 = *puVar24;
        param_1[5] = uVar3;
        *puVar24 = uVar14;
        param_2[-5] = uVar2;
      }
      else {
        uVar14 = *puVar13;
        uVar2 = param_1[5];
        uVar3 = *(undefined8 *)puVar19;
        *puVar13 = *puVar21;
        param_1[5] = uVar3;
        *puVar21 = uVar14;
        *(undefined8 *)puVar19 = uVar2;
        if (*puVar19 < *(uint *)(param_2 + -5)) {
          uVar14 = *puVar21;
          uVar2 = *(undefined8 *)puVar19;
          uVar3 = param_2[-5];
          *puVar21 = *puVar24;
          *(undefined8 *)puVar19 = uVar3;
          *puVar24 = uVar14;
          param_2[-5] = uVar2;
        }
      }
    }
    else if (uVar9 < *(uint *)(param_2 + -5)) {
      uVar14 = *puVar21;
      uVar2 = *(undefined8 *)puVar19;
      uVar3 = param_2[-5];
      *puVar21 = *puVar24;
      *(undefined8 *)puVar19 = uVar3;
      *puVar24 = uVar14;
      param_2[-5] = uVar2;
      if (*(uint *)(param_1 + 5) < *puVar19) {
        uVar14 = *puVar13;
        uVar2 = param_1[5];
        uVar3 = *(undefined8 *)puVar19;
        *puVar13 = *puVar21;
        param_1[5] = uVar3;
        *puVar21 = uVar14;
        *(undefined8 *)puVar19 = uVar2;
      }
    }
    uVar9 = *puVar12;
    if (*puVar16 < uVar9) {
      if (uVar9 < *puVar19) {
        local_70 = *puVar17;
        uStack_68 = *(undefined8 *)puVar16;
        *puVar17 = *puVar21;
        *(undefined8 *)puVar16 = *(undefined8 *)puVar19;
      }
      else {
        uVar14 = *puVar17;
        uVar2 = *(undefined8 *)puVar16;
        *puVar17 = *puVar20;
        *(undefined8 *)puVar16 = puVar20[1];
        *puVar20 = uVar14;
        puVar20[1] = uVar2;
        if (*puVar19 <= *puVar12) goto LAB_71005f604c;
        local_70 = *puVar20;
        uStack_68 = puVar20[1];
        *puVar20 = *puVar21;
        puVar20[1] = *(undefined8 *)puVar19;
      }
      *puVar21 = local_70;
      *(undefined8 *)puVar19 = uStack_68;
    }
    else if (uVar9 < *puVar19) {
      uVar14 = *puVar20;
      uVar2 = puVar20[1];
      *puVar20 = *puVar21;
      puVar20[1] = *(undefined8 *)puVar19;
      uVar9 = *puVar12;
      *puVar21 = uVar14;
      *(undefined8 *)puVar19 = uVar2;
      if (*puVar16 < uVar9) {
        uVar14 = *puVar17;
        uVar2 = *(undefined8 *)puVar16;
        *puVar17 = *puVar20;
        *(undefined8 *)puVar16 = puVar20[1];
        *puVar20 = uVar14;
        puVar20[1] = uVar2;
      }
    }
LAB_71005f604c:
    uVar14 = *param_1;
    uVar2 = param_1[1];
    uVar3 = puVar20[1];
    *param_1 = *puVar20;
    param_1[1] = uVar3;
    *puVar20 = uVar14;
    puVar20[1] = uVar2;
joined_r0x0071005f6068:
    if ((param_5 & 1) != 0) goto LAB_71005f5e7c;
LAB_71005f606c:
    uVar9 = *(uint *)(param_1 + 1);
    if (*(uint *)(param_1 + -1) <= uVar9) {
      puVar13 = param_1;
      if (*(uint *)(param_2 + -1) < uVar9) {
        do {
          puVar20 = puVar13 + 2;
          puVar12 = (uint *)(puVar13 + 3);
          puVar13 = puVar20;
        } while (uVar9 <= *puVar12);
      }
      else {
        do {
          puVar20 = puVar13 + 2;
          if (param_2 <= puVar20) break;
          puVar12 = (uint *)(puVar13 + 3);
          puVar13 = puVar20;
        } while (uVar9 <= *puVar12);
      }
      puVar13 = param_2;
      puVar17 = param_2;
      if (puVar20 < param_2) {
        do {
          puVar17 = puVar13 + -2;
          puVar12 = (uint *)(puVar13 + -1);
          puVar13 = puVar17;
        } while (*puVar12 < uVar9);
      }
      uVar14 = *param_1;
      uVar6 = *(undefined4 *)((long)param_1 + 0xc);
      if (puVar20 < puVar17) {
        do {
          uVar2 = *puVar20;
          uVar3 = puVar20[1];
          uVar4 = puVar17[1];
          *puVar20 = *puVar17;
          puVar20[1] = uVar4;
          *puVar17 = uVar2;
          puVar17[1] = uVar3;
          do {
            puVar12 = (uint *)(puVar20 + 3);
            puVar20 = puVar20 + 2;
          } while (uVar9 <= *puVar12);
          do {
            puVar12 = (uint *)(puVar17 + -1);
            puVar17 = puVar17 + -2;
          } while (*puVar12 < uVar9);
        } while (puVar20 < puVar17);
      }
      if (puVar20 + -2 != param_1) {
        uVar2 = puVar20[-1];
        *param_1 = puVar20[-2];
        param_1[1] = uVar2;
      }
      param_5 = 0;
      puVar20[-2] = uVar14;
      *(uint *)(puVar20 + -1) = uVar9;
      *(undefined4 *)((long)puVar20 - 4) = uVar6;
      param_4 = param_4 + -1;
      goto LAB_71005f5c28;
    }
  }
  param_4 = param_4 + -1;
  uVar14 = *param_1;
  uVar6 = *(undefined4 *)((long)param_1 + 0xc);
  lVar10 = 0;
  do {
    lVar1 = lVar10 + 0x10;
    lVar22 = lVar10 + 0x18;
    lVar10 = lVar1;
  } while (uVar9 < *(uint *)((long)param_1 + lVar22));
  puVar13 = (undefined8 *)((long)param_1 + lVar1);
  puVar20 = param_2;
  if (lVar1 == 0x10) {
    do {
      puVar17 = puVar20;
      if (puVar20 <= puVar13) break;
      puVar17 = puVar20 + -2;
      puVar12 = (uint *)(puVar20 + -1);
      puVar20 = puVar17;
    } while (*puVar12 <= uVar9);
  }
  else {
    do {
      puVar17 = puVar20 + -2;
      puVar12 = (uint *)(puVar20 + -1);
      puVar20 = puVar17;
    } while (*puVar12 <= uVar9);
  }
  puVar21 = puVar17;
  puVar20 = puVar13;
  if (puVar13 < puVar17) {
    do {
      uVar2 = *puVar20;
      uVar3 = puVar20[1];
      uVar4 = puVar21[1];
      *puVar20 = *puVar21;
      puVar20[1] = uVar4;
      *puVar21 = uVar2;
      puVar21[1] = uVar3;
      do {
        puVar12 = (uint *)(puVar20 + 3);
        puVar20 = puVar20 + 2;
      } while (uVar9 < *puVar12);
      do {
        puVar12 = (uint *)(puVar21 + -1);
        puVar21 = puVar21 + -2;
      } while (*puVar12 <= uVar9);
    } while (puVar20 < puVar21);
  }
  puVar21 = puVar20 + -2;
  if (puVar21 != param_1) {
    uVar2 = puVar20[-1];
    *param_1 = *puVar21;
    param_1[1] = uVar2;
  }
  puVar20[-2] = uVar14;
  *(uint *)(puVar20 + -1) = uVar9;
  *(undefined4 *)((long)puVar20 + -4) = uVar6;
  if (puVar13 < puVar17) goto LAB_71005f6198;
  bVar7 = FUN_71005f6650(param_1,puVar21);
  bVar8 = FUN_71005f6650(puVar20,param_2);
  if (!bVar8) goto code_r0x0071005f6194;
  param_2 = puVar21;
  if (bVar7) {
    return;
  }
  goto LAB_71005f5c14;
LAB_71005f6404:
  puVar23 = puVar20;
  uVar9 = *(uint *)(puVar18 + 3);
  if (*(uint *)(puVar18 + 1) < uVar9) {
    uVar14 = *puVar23;
    uVar6 = *(undefined4 *)((long)puVar18 + 0x1c);
    lVar1 = lVar10;
    do {
      lVar22 = lVar1;
      puVar20 = (undefined8 *)((long)param_1 + lVar22);
      puVar20[2] = *puVar20;
      puVar20[3] = puVar20[1];
      puVar18 = param_1;
      if (lVar22 == 0) goto LAB_71005f63e8;
      lVar1 = lVar22 + -0x10;
    } while (*(uint *)(puVar20 + -1) < uVar9);
    puVar18 = (undefined8 *)((long)param_1 + lVar22);
LAB_71005f63e8:
    *puVar18 = uVar14;
    *(uint *)(puVar18 + 1) = uVar9;
    *(undefined4 *)((long)puVar18 + 0xc) = uVar6;
  }
  lVar10 = lVar10 + 0x10;
  puVar20 = puVar23 + 2;
  puVar18 = puVar23;
  if (puVar23 + 2 == param_2) {
switchD_71005f62dc_caseD_0:
    return;
  }
  goto LAB_71005f6404;
code_r0x0071005f6194:
  if (!bVar7) {
LAB_71005f6198:
    FUN_71005f5be0(param_1,puVar21,param_3,param_4,param_5 & 1);
    param_5 = 0;
  }
  goto LAB_71005f5c28;
}



bool FUN_71005f6650(undefined8 *param_1,undefined8 *param_2)

{
  undefined8 *puVar1;
  undefined8 uVar2;
  uint uVar3;
  uint uVar4;
  undefined4 uVar5;
  long lVar6;
  undefined8 *puVar7;
  undefined8 *puVar8;
  long lVar9;
  undefined8 uVar10;
  int iVar11;
  undefined8 uVar12;
  long lVar13;
  
  switch((long)param_2 - (long)param_1 >> 4) {
  case 0:
  case 1:
    return true;
  case 2:
    if (*(uint *)(param_1 + 1) < *(uint *)(param_2 + -1)) {
      uVar12 = *param_1;
      uVar10 = param_1[1];
      uVar2 = param_2[-1];
      *param_1 = param_2[-2];
      param_1[1] = uVar2;
      param_2[-2] = uVar12;
      param_2[-1] = uVar10;
    }
    break;
  case 3:
    uVar3 = *(uint *)(param_1 + 3);
    puVar7 = param_1 + 2;
    puVar8 = param_2 + -2;
    if (*(uint *)(param_1 + 1) < uVar3) {
      if (uVar3 < *(uint *)(param_2 + -1)) {
        uVar12 = *param_1;
        uVar10 = param_1[1];
        uVar2 = param_2[-1];
        *param_1 = *puVar8;
        param_1[1] = uVar2;
        *puVar8 = uVar12;
        param_2[-1] = uVar10;
        return true;
      }
      uVar12 = *param_1;
      uVar10 = param_1[1];
      *param_1 = *puVar7;
      param_1[1] = param_1[3];
      *puVar7 = uVar12;
      param_1[3] = uVar10;
      if (*(uint *)(param_2 + -1) <= *(uint *)(param_1 + 3)) {
        return true;
      }
      uVar12 = *puVar7;
      uVar10 = param_1[3];
      uVar2 = param_2[-1];
      *puVar7 = *puVar8;
      param_1[3] = uVar2;
      *puVar8 = uVar12;
      param_2[-1] = uVar10;
      return true;
    }
    if (*(uint *)(param_2 + -1) <= uVar3) {
      return true;
    }
    uVar12 = *puVar7;
    uVar10 = param_1[3];
    uVar2 = param_2[-1];
    *puVar7 = *puVar8;
    param_1[3] = uVar2;
    *puVar8 = uVar12;
    param_2[-1] = uVar10;
    if (*(uint *)(param_1 + 3) <= *(uint *)(param_1 + 1)) {
      return true;
    }
    goto LAB_71005f69fc;
  case 4:
    uVar3 = *(uint *)(param_1 + 3);
    puVar7 = param_1 + 2;
    puVar8 = param_1 + 4;
    uVar4 = *(uint *)(param_1 + 5);
    if (*(uint *)(param_1 + 1) < uVar3) {
      if (uVar3 < uVar4) {
        uVar12 = *param_1;
        uVar10 = param_1[1];
        *param_1 = *puVar8;
        param_1[1] = param_1[5];
      }
      else {
        uVar12 = *puVar7;
        uVar10 = param_1[3];
        *puVar7 = *param_1;
        param_1[3] = param_1[1];
        *param_1 = uVar12;
        param_1[1] = uVar10;
        if (uVar4 <= *(uint *)(param_1 + 3)) goto LAB_71005f69a8;
        uVar12 = *puVar7;
        uVar10 = param_1[3];
        *puVar7 = *puVar8;
        param_1[3] = param_1[5];
      }
      *puVar8 = uVar12;
      param_1[5] = uVar10;
    }
    else if (uVar3 < uVar4) {
      uVar12 = *puVar7;
      uVar10 = param_1[3];
      *puVar7 = *puVar8;
      param_1[3] = param_1[5];
      *puVar8 = uVar12;
      param_1[5] = uVar10;
      if (*(uint *)(param_1 + 1) < *(uint *)(param_1 + 3)) {
        uVar12 = *param_1;
        uVar10 = param_1[1];
        *param_1 = *puVar7;
        param_1[1] = param_1[3];
        *puVar7 = uVar12;
        param_1[3] = uVar10;
      }
    }
LAB_71005f69a8:
    if (*(uint *)(param_1 + 5) < *(uint *)(param_2 + -1)) {
      uVar12 = *puVar8;
      uVar10 = param_1[5];
      uVar2 = param_2[-1];
      *puVar8 = param_2[-2];
      param_1[5] = uVar2;
      param_2[-2] = uVar12;
      param_2[-1] = uVar10;
      if (*(uint *)(param_1 + 3) < *(uint *)(param_1 + 5)) {
        uVar12 = *puVar7;
        uVar10 = param_1[3];
        *puVar7 = *puVar8;
        param_1[3] = param_1[5];
        *puVar8 = uVar12;
        param_1[5] = uVar10;
        if (*(uint *)(param_1 + 1) < *(uint *)(param_1 + 3)) {
LAB_71005f69fc:
          uVar12 = *param_1;
          uVar10 = param_1[1];
          *param_1 = param_1[2];
          param_1[1] = param_1[3];
          param_1[2] = uVar12;
          param_1[3] = uVar10;
          return true;
        }
      }
    }
    break;
  case 5:
    FUN_71005f6a50(param_1,param_1 + 2,param_1 + 4,param_1 + 6,param_2 + -2);
    return true;
  default:
    uVar3 = *(uint *)(param_1 + 3);
    puVar7 = param_1 + 4;
    puVar8 = param_1 + 2;
    uVar4 = *(uint *)(param_1 + 5);
    if (*(uint *)(param_1 + 1) < uVar3) {
      if (uVar3 < uVar4) {
        uVar12 = *param_1;
        uVar10 = param_1[1];
        *param_1 = *puVar7;
        param_1[1] = param_1[5];
        *puVar7 = uVar12;
        param_1[5] = uVar10;
      }
      else {
        uVar12 = *puVar8;
        uVar10 = param_1[3];
        *puVar8 = *param_1;
        param_1[3] = param_1[1];
        *param_1 = uVar12;
        param_1[1] = uVar10;
        if (*(uint *)(param_1 + 3) < uVar4) {
          uVar12 = *puVar8;
          uVar10 = param_1[3];
          *puVar8 = *puVar7;
          param_1[3] = param_1[5];
          *puVar7 = uVar12;
          param_1[5] = uVar10;
        }
      }
    }
    else if (uVar3 < uVar4) {
      uVar12 = *puVar8;
      uVar10 = param_1[3];
      *puVar8 = *puVar7;
      param_1[3] = param_1[5];
      *puVar7 = uVar12;
      param_1[5] = uVar10;
      if (*(uint *)(param_1 + 1) < *(uint *)(param_1 + 3)) {
        uVar12 = *param_1;
        uVar10 = param_1[1];
        *param_1 = *puVar8;
        param_1[1] = param_1[3];
        *puVar8 = uVar12;
        param_1[3] = uVar10;
      }
    }
    if (param_1 + 6 != param_2) {
      lVar9 = 0;
      iVar11 = 0;
      puVar8 = param_1 + 6;
      do {
        uVar3 = *(uint *)(puVar8 + 1);
        if (*(uint *)(puVar7 + 1) < uVar3) {
          uVar12 = *puVar8;
          uVar5 = *(undefined4 *)((long)puVar8 + 0xc);
          lVar6 = lVar9;
          do {
            lVar13 = lVar6;
            *(undefined8 *)((long)param_1 + lVar13 + 0x30) =
                 *(undefined8 *)((long)param_1 + lVar13 + 0x20);
            *(undefined8 *)((long)param_1 + lVar13 + 0x38) =
                 *(undefined8 *)((long)param_1 + lVar13 + 0x28);
            if (lVar13 == -0x20) {
              *param_1 = uVar12;
              *(uint *)(param_1 + 1) = uVar3;
              *(undefined4 *)((long)param_1 + 0xc) = uVar5;
              goto joined_r0x0071005f68b8;
            }
            lVar6 = lVar13 + -0x10;
          } while (*(uint *)((long)param_1 + lVar13 + 0x18) < uVar3);
          *(undefined8 *)((long)param_1 + lVar13 + 0x20) = uVar12;
          *(uint *)((long)param_1 + lVar13 + 0x28) = uVar3;
          *(undefined4 *)((long)param_1 + lVar13 + 0x2c) = uVar5;
joined_r0x0071005f68b8:
          iVar11 = iVar11 + 1;
          if (iVar11 == 8) {
            return puVar8 + 2 == param_2;
          }
        }
        puVar1 = puVar8 + 2;
        lVar9 = lVar9 + 0x10;
        puVar7 = puVar8;
        puVar8 = puVar1;
      } while (puVar1 != param_2);
    }
  }
  return true;
}



void FUN_71005f6a50(undefined8 *param_1,undefined8 *param_2,undefined8 *param_3,undefined8 *param_4,
                   undefined8 *param_5)

{
  undefined8 uVar1;
  uint uVar2;
  undefined8 uVar3;
  undefined8 uVar4;
  
  uVar2 = *(uint *)(param_2 + 1);
  if (*(uint *)(param_1 + 1) < uVar2) {
    if (uVar2 < *(uint *)(param_3 + 1)) {
      uVar1 = param_3[1];
      uVar4 = *param_1;
      uVar3 = param_1[1];
      *param_1 = *param_3;
      param_1[1] = uVar1;
    }
    else {
      uVar4 = *param_1;
      uVar3 = param_1[1];
      uVar1 = param_2[1];
      *param_1 = *param_2;
      param_1[1] = uVar1;
      *param_2 = uVar4;
      param_2[1] = uVar3;
      if (*(uint *)(param_3 + 1) <= *(uint *)(param_2 + 1)) goto LAB_71005f6aec;
      uVar4 = *param_2;
      uVar3 = param_2[1];
      uVar1 = param_3[1];
      *param_2 = *param_3;
      param_2[1] = uVar1;
    }
    *param_3 = uVar4;
    param_3[1] = uVar3;
  }
  else if (uVar2 < *(uint *)(param_3 + 1)) {
    uVar4 = *param_2;
    uVar3 = param_2[1];
    uVar1 = param_3[1];
    *param_2 = *param_3;
    param_2[1] = uVar1;
    *param_3 = uVar4;
    param_3[1] = uVar3;
    if (*(uint *)(param_1 + 1) < *(uint *)(param_2 + 1)) {
      uVar4 = *param_1;
      uVar3 = param_1[1];
      uVar1 = param_2[1];
      *param_1 = *param_2;
      param_1[1] = uVar1;
      *param_2 = uVar4;
      param_2[1] = uVar3;
    }
  }
LAB_71005f6aec:
  if (*(uint *)(param_3 + 1) < *(uint *)(param_4 + 1)) {
    uVar4 = *param_3;
    uVar3 = param_3[1];
    uVar1 = param_4[1];
    *param_3 = *param_4;
    param_3[1] = uVar1;
    *param_4 = uVar4;
    param_4[1] = uVar3;
    if (*(uint *)(param_2 + 1) < *(uint *)(param_3 + 1)) {
      uVar4 = *param_2;
      uVar3 = param_2[1];
      uVar1 = param_3[1];
      *param_2 = *param_3;
      param_2[1] = uVar1;
      *param_3 = uVar4;
      param_3[1] = uVar3;
      if (*(uint *)(param_1 + 1) < *(uint *)(param_2 + 1)) {
        uVar4 = *param_1;
        uVar3 = param_1[1];
        uVar1 = param_2[1];
        *param_1 = *param_2;
        param_1[1] = uVar1;
        *param_2 = uVar4;
        param_2[1] = uVar3;
      }
    }
  }
  if (*(uint *)(param_4 + 1) < *(uint *)(param_5 + 1)) {
    uVar4 = *param_4;
    uVar3 = param_4[1];
    uVar1 = param_5[1];
    *param_4 = *param_5;
    param_4[1] = uVar1;
    *param_5 = uVar4;
    param_5[1] = uVar3;
    if (*(uint *)(param_3 + 1) < *(uint *)(param_4 + 1)) {
      uVar4 = *param_3;
      uVar3 = param_3[1];
      uVar1 = param_4[1];
      *param_3 = *param_4;
      param_3[1] = uVar1;
      *param_4 = uVar4;
      param_4[1] = uVar3;
      if (*(uint *)(param_2 + 1) < *(uint *)(param_3 + 1)) {
        uVar4 = *param_2;
        uVar3 = param_2[1];
        uVar1 = param_3[1];
        *param_2 = *param_3;
        param_2[1] = uVar1;
        *param_3 = uVar4;
        param_3[1] = uVar3;
        if (*(uint *)(param_1 + 1) < *(uint *)(param_2 + 1)) {
          uVar4 = *param_1;
          uVar3 = param_1[1];
          uVar1 = param_2[1];
          *param_1 = *param_2;
          param_1[1] = uVar1;
          *param_2 = uVar4;
          param_2[1] = uVar3;
        }
      }
    }
  }
  return;
}



undefined8 * FUN_71005f6be0(undefined8 *param_1,undefined8 *param_2,undefined8 *param_3)

{
  bool bVar1;
  ulong uVar2;
  ulong uVar3;
  undefined8 uVar4;
  undefined4 uVar5;
  undefined8 uVar6;
  ulong uVar7;
  long lVar8;
  undefined8 *puVar9;
  ulong uVar10;
  undefined8 *puVar11;
  undefined8 uVar12;
  undefined8 *puVar13;
  ulong uVar14;
  uint uVar15;
  undefined8 *puVar16;
  undefined8 *puVar17;
  ulong uVar18;
  undefined8 *puVar19;
  
  if (param_1 != param_2) {
    uVar7 = (long)param_2 - (long)param_1;
    lVar8 = (long)uVar7 >> 4;
    if ((0x10 < (long)uVar7) && (0x1f < uVar7)) {
      uVar10 = lVar8 - 2U >> 1;
      uVar14 = uVar10;
      do {
        if ((long)uVar14 <= (long)uVar10) {
          uVar3 = uVar14 << 1 | 1;
          uVar2 = uVar14 * 2 + 2;
          puVar11 = param_1 + uVar3 * 2;
          uVar18 = uVar3;
          if ((long)uVar2 < lVar8) {
            uVar18 = uVar2;
            if (*(uint *)(puVar11 + 1) <= *(uint *)(puVar11 + 3)) {
              uVar18 = uVar3;
            }
            puVar11 = puVar11 + (ulong)(*(uint *)(puVar11 + 3) < *(uint *)(puVar11 + 1)) * 2;
          }
          puVar9 = param_1 + uVar14 * 2;
          uVar15 = *(uint *)(puVar9 + 1);
          if (*(uint *)(puVar11 + 1) <= uVar15) {
            uVar12 = *puVar9;
            uVar5 = *(undefined4 *)((long)puVar9 + 0xc);
            do {
              puVar13 = puVar11;
              uVar6 = puVar13[1];
              *puVar9 = *puVar13;
              puVar9[1] = uVar6;
              if ((long)uVar10 < (long)uVar18) break;
              uVar3 = uVar18 << 1 | 1;
              uVar2 = uVar18 * 2 + 2;
              puVar11 = param_1 + uVar3 * 2;
              uVar18 = uVar3;
              if ((long)uVar2 < lVar8) {
                uVar18 = uVar2;
                if (*(uint *)(puVar11 + 1) <= *(uint *)(puVar11 + 3)) {
                  uVar18 = uVar3;
                }
                puVar11 = puVar11 + (ulong)(*(uint *)(puVar11 + 3) < *(uint *)(puVar11 + 1)) * 2;
              }
              puVar9 = puVar13;
            } while (*(uint *)(puVar11 + 1) <= uVar15);
            *puVar13 = uVar12;
            *(uint *)(puVar13 + 1) = uVar15;
            *(undefined4 *)((long)puVar13 + 0xc) = uVar5;
          }
        }
        bVar1 = 0 < (long)uVar14;
        uVar14 = uVar14 - 1;
      } while (bVar1);
    }
    puVar11 = param_2;
    if (param_2 != param_3) {
      puVar9 = param_2;
      puVar11 = param_3;
      if ((long)uVar7 < 0x20) {
        do {
          if (*(uint *)(param_1 + 1) < *(uint *)(puVar9 + 1)) {
            uVar12 = *puVar9;
            uVar6 = puVar9[1];
            uVar4 = param_1[1];
            *puVar9 = *param_1;
            puVar9[1] = uVar4;
            *param_1 = uVar12;
            param_1[1] = uVar6;
          }
          puVar9 = puVar9 + 2;
        } while (puVar9 != param_3);
      }
      else {
        puVar9 = param_1 + 2;
        puVar13 = param_2;
        do {
          if (*(uint *)(param_1 + 1) < *(uint *)(puVar13 + 1)) {
            uVar12 = *puVar13;
            uVar6 = puVar13[1];
            uVar4 = param_1[1];
            *puVar13 = *param_1;
            puVar13[1] = uVar4;
            *param_1 = uVar12;
            param_1[1] = uVar6;
            if (uVar7 == 0x20) {
              uVar14 = 1;
              uVar15 = *(uint *)(param_1 + 1);
              puVar16 = puVar9;
              if (*(uint *)(param_1 + 3) <= uVar15) {
LAB_71005f6cf8:
                uVar12 = *param_1;
                uVar5 = *(undefined4 *)((long)param_1 + 0xc);
                puVar19 = param_1;
                do {
                  puVar17 = puVar16;
                  uVar6 = puVar17[1];
                  *puVar19 = *puVar17;
                  puVar19[1] = uVar6;
                  if ((long)(lVar8 - 2U >> 1) < (long)uVar14) break;
                  uVar2 = uVar14 << 1 | 1;
                  uVar10 = uVar14 * 2 + 2;
                  puVar16 = param_1 + uVar2 * 2;
                  uVar14 = uVar2;
                  if ((long)uVar10 < lVar8) {
                    uVar14 = uVar10;
                    if (*(uint *)(puVar16 + 1) <= *(uint *)(puVar16 + 3)) {
                      uVar14 = uVar2;
                    }
                    puVar16 = puVar16 + (ulong)(*(uint *)(puVar16 + 3) < *(uint *)(puVar16 + 1)) * 2
                    ;
                  }
                  puVar19 = puVar17;
                } while (*(uint *)(puVar16 + 1) <= uVar15);
                *puVar17 = uVar12;
                *(uint *)(puVar17 + 1) = uVar15;
                *(undefined4 *)((long)puVar17 + 0xc) = uVar5;
              }
            }
            else {
              uVar14 = 1;
              if (*(uint *)(param_1 + 5) < *(uint *)(param_1 + 3)) {
                uVar14 = 2;
              }
              uVar15 = *(uint *)(param_1 + 1);
              puVar16 = puVar9 + (ulong)(*(uint *)(param_1 + 5) < *(uint *)(param_1 + 3)) * 2;
              if (*(uint *)(puVar9 + (ulong)(*(uint *)(param_1 + 5) < *(uint *)(param_1 + 3)) * 2 +
                           1) <= uVar15) goto LAB_71005f6cf8;
            }
          }
          puVar13 = puVar13 + 2;
        } while (puVar13 != param_3);
      }
    }
    param_3 = puVar11;
    if (0x10 < (long)uVar7) {
      uVar7 = uVar7 >> 4;
      do {
        uVar12 = *param_1;
        uVar6 = param_1[1];
        uVar14 = 0;
        puVar11 = param_1;
        do {
          puVar9 = puVar11 + (uVar14 + 1) * 2;
          uVar2 = uVar14 << 1 | 1;
          uVar10 = uVar14 * 2 + 2;
          uVar14 = uVar2;
          if ((long)uVar10 < (long)uVar7) {
            uVar14 = uVar10;
            if (*(uint *)(puVar9 + 1) <= *(uint *)(puVar9 + 3)) {
              uVar14 = uVar2;
            }
            puVar9 = puVar9 + (ulong)(*(uint *)(puVar9 + 3) < *(uint *)(puVar9 + 1)) * 2;
          }
          uVar4 = puVar9[1];
          *puVar11 = *puVar9;
          puVar11[1] = uVar4;
          puVar11 = puVar9;
        } while ((long)uVar14 <= (long)(uVar7 - 2 >> 1));
        puVar11 = param_2 + -2;
        if (puVar9 == puVar11) {
          *puVar9 = uVar12;
          puVar9[1] = uVar6;
        }
        else {
          uVar4 = param_2[-1];
          *puVar9 = *puVar11;
          puVar9[1] = uVar4;
          *puVar11 = uVar12;
          param_2[-1] = uVar6;
          uVar14 = (long)puVar9 + (0x10 - (long)param_1);
          if (0x10 < (long)uVar14) {
            uVar14 = (uVar14 >> 4) - 2 >> 1;
            uVar15 = *(uint *)(puVar9 + 1);
            if (uVar15 < *(uint *)(param_1 + uVar14 * 2 + 1)) {
              uVar12 = *puVar9;
              uVar5 = *(undefined4 *)((long)puVar9 + 0xc);
              do {
                puVar13 = param_1 + uVar14 * 2;
                uVar6 = puVar13[1];
                *puVar9 = *puVar13;
                puVar9[1] = uVar6;
                if (uVar14 == 0) break;
                uVar14 = uVar14 - 1 >> 1;
                puVar9 = puVar13;
              } while (uVar15 < *(uint *)(param_1 + uVar14 * 2 + 1));
              *puVar13 = uVar12;
              *(uint *)(puVar13 + 1) = uVar15;
              *(undefined4 *)((long)puVar13 + 0xc) = uVar5;
            }
          }
        }
        bVar1 = 2 < (long)uVar7;
        param_2 = puVar11;
        uVar7 = uVar7 - 1;
      } while (bVar1);
    }
  }
  return param_3;
}



void FUN_71005f6fa4(undefined8 *param_1)

{
  param_1[1] = 0;
  param_1[2] = 0;
  *param_1 = 0;
  return;
}
