


void FUN_71005fc26c(long param_1)

{
  if ((*(byte *)(param_1 + 1) >> 1 & 1) == 0) {
    return;
  }
                    // WARNING: Could not recover jumptable at 0x0071005fc288. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)*DAT_7103a64a40)(*(undefined8 *)(param_1 + 8));
  return;
}



void FUN_71005fc2ac(long param_1,undefined8 *param_2)

{
  undefined8 uVar1;
  
  uVar1 = (*(code *)*DAT_7103a64a50)(*(undefined8 *)(param_1 + 8));
  *param_2 = uVar1;
  param_2[1] = 0;
  return;
}



void FUN_71005fc2e0(long param_1,undefined8 param_2,undefined8 param_3)

{
                    // WARNING: Could not recover jumptable at 0x0071005fc2f4. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)*DAT_7103a6fc68)(*(undefined8 *)(param_1 + 8),param_3);
  return;
}



void FUN_71005fc2f8(undefined8 *param_1)

{
  param_1[0x1a] = 0;
  param_1[0x1b] = 0;
  param_1[0x18] = 0;
  param_1[0x19] = 0;
  param_1[0x16] = 0;
  param_1[0x17] = 0;
  param_1[0x14] = 0;
  param_1[0x15] = 0;
  param_1[0x12] = 0;
  param_1[0x13] = 0;
  param_1[0x10] = 0;
  param_1[0x11] = 0;
  param_1[0xe] = 0;
  param_1[0xf] = 0;
  param_1[0xc] = 0;
  param_1[0xd] = 0;
  param_1[10] = 0;
  param_1[0xb] = 0;
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



void FUN_71005fc338(long param_1)

{
                    // WARNING: Could not recover jumptable at 0x0071005fc348. Too many branches
                    // WARNING: Treating indirect jump as call
  (*DAT_7103ff43c0)(*(undefined8 *)(param_1 + 0xb0));
  return;
}



void FUN_71005fc34c(long param_1,ulong param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 uVar1;
  undefined8 uVar2;
  
  uVar2 = *(undefined8 *)(param_1 + 0xb0);
  uVar1 = FUN_71006015a0(param_2 & 0xffffffff);
                    // WARNING: Could not recover jumptable at 0x0071005fc398. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)*DAT_7103a66d40)(uVar2,uVar1,param_4,param_3);
  return;
}



void FUN_71005fc39c(long param_1,ulong param_2,undefined4 param_3,undefined4 param_4,
                   undefined4 param_5,undefined4 param_6)

{
  undefined4 uVar1;
  undefined8 uVar2;
  
  uVar2 = *(undefined8 *)(param_1 + 0xb0);
  uVar1 = FUN_71006015a0(param_2 & 0xffffffff);
                    // WARNING: Could not recover jumptable at 0x0071005fc400. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)*DAT_7103a66ce0)(uVar2,uVar1,param_4,param_3,param_6,param_5);
  return;
}



void FUN_71005fc404(long param_1,ulong param_2,uint param_3,undefined8 param_4,undefined4 param_5,
                   undefined4 param_6)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined8 uVar3;
  undefined8 uVar4;
  
  uVar4 = *(undefined8 *)(param_1 + 0xb0);
  uVar1 = FUN_71006015a0(param_2 & 0xffffffff);
  uVar2 = FUN_71006015f4((ulong)param_3);
  uVar3 = ret_7100601614();
                    // WARNING: Could not recover jumptable at 0x0071005fc480. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)*DAT_7103a66a08)(uVar4,uVar1,uVar2,param_5,uVar3,param_6);
  return;
}



void FUN_71005fc484(long param_1,ulong param_2,uint param_3,undefined8 param_4,undefined4 param_5,
                   undefined4 param_6,undefined4 param_7,undefined4 param_8)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined8 uVar3;
  undefined8 uVar4;
  
  uVar4 = *(undefined8 *)(param_1 + 0xb0);
  uVar1 = FUN_71006015a0(param_2 & 0xffffffff);
  uVar2 = FUN_71006015f4((ulong)param_3);
  uVar3 = ret_7100601614();
                    // WARNING: Could not recover jumptable at 0x0071005fc518. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)*DAT_7103a66a00)(uVar4,uVar1,uVar2,param_5,uVar3,param_6,param_8,param_7);
  return;
}



void FUN_71005fc520(long param_1,long param_2)

{
  undefined8 *puVar1;
  uint uVar2;
  undefined8 uVar3;
  long lVar4;
  ulong uVar5;
  
  if (*(char *)(param_2 + 1) == '\0') {
    FUN_71005fc71c(param_1,param_2 + 0x50);
    puVar1 = DAT_7103a6fd20;
    uVar5 = (ulong)*(byte *)(param_2 + 0x4d);
    if (uVar5 != 0) {
      lVar4 = *(long *)(param_2 + 0x28);
      do {
        (*(code *)*puVar1)(*(undefined8 *)(param_1 + 0xb0),lVar4);
        uVar5 = uVar5 - 1;
        lVar4 = lVar4 + 8;
      } while (uVar5 != 0);
    }
    (*(code *)*DAT_7103a6fd28)(*(undefined8 *)(param_1 + 0xb0),param_2 + 0x34);
    (*(code *)*DAT_7103a6fd30)(*(undefined8 *)(param_1 + 0xb0),param_2 + 0x30);
    (*(code *)*DAT_7103a6fd38)(*(undefined8 *)(param_1 + 0xb0),param_2 + 0x38);
    (*(code *)*DAT_7103a6fd40)(*(undefined8 *)(param_1 + 0xb0),param_2 + 0x80);
    (*(code *)*DAT_7103a6fd48)(*(undefined8 *)(param_1 + 0xb0),3,*(undefined4 *)(param_2 + 0x88));
    (*(code *)*DAT_7103a6fd50)(*(undefined8 *)(param_1 + 0xb0),3,*(undefined4 *)(param_2 + 0x8c));
    puVar1 = DAT_7103a6fd58;
    (*(code *)*DAT_7103a6fd58)(*(undefined8 *)(param_1 + 0xb0),2,*(undefined4 *)(param_2 + 0x90));
    (*(code *)*puVar1)(*(undefined8 *)(param_1 + 0xb0),1,*(undefined4 *)(param_2 + 0x94));
    if ((*(ushort *)(param_2 + 0x9a) >> 3 & 1) == 0) {
      (*(code *)*DAT_7103a6fd60)(0,0x3f800000,*(undefined8 *)(param_1 + 0xb0),0);
    }
    (*(code *)*DAT_7103a678d8)
              (*(undefined8 *)(param_1 + 0xb0),*(undefined4 *)(param_2 + 0x10),
               *(undefined8 *)(param_2 + 0x20));
    (*(code *)*DAT_7103a678e0)
              (*(undefined8 *)(param_1 + 0xb0),*(undefined4 *)(param_2 + 0xc),
               *(undefined8 *)(param_2 + 0x18));
    if ((*(byte *)(param_2 + 2) & 1) != 0) {
      (*(code *)*DAT_7103a6fd68)(*(undefined8 *)(param_1 + 0xb0),*(undefined4 *)(param_2 + 0xa0));
    }
  }
  lVar4 = *(long *)(param_2 + 0xa8);
  if (lVar4 == 0) {
    uVar3 = 0;
  }
  else {
    uVar3 = *(undefined8 *)(lVar4 + 8);
    if ((*(byte *)(lVar4 + 1) & 1) == 0) {
      uVar2 = *(uint *)(lVar4 + 4);
      goto LAB_71005fc6f4;
    }
  }
  uVar2 = FUN_71006015c0(0x1ff);
LAB_71005fc6f4:
                    // WARNING: Could not recover jumptable at 0x0071005fc718. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)*DAT_7103a678d0)(*(undefined8 *)(param_1 + 0xb0),uVar3,uVar2);
  return;
}



void FUN_71005fc71c(long param_1,long param_2)

{
  byte bVar1;
  
  (*(code *)*DAT_7103a6fd70)(*(undefined8 *)(param_1 + 0xb0));
  (*(code *)*DAT_7103a6fd78)
            (*(undefined4 *)(param_2 + 0x28),*(undefined4 *)(param_2 + 0x20),
             *(undefined4 *)(param_2 + 0x24),*(undefined8 *)(param_1 + 0xb0));
  (*(code *)*DAT_7103a6fd80)(*(undefined8 *)(param_1 + 0xb0),param_2 + 4);
  bVar1 = *(byte *)(param_2 + 0x2d);
  if ((bVar1 & 1) != 0) {
    (*(code *)*DAT_7103a6fd88)(*(undefined8 *)(param_1 + 0xb0),*(undefined4 *)(param_2 + 0x1c));
    bVar1 = *(byte *)(param_2 + 0x2d);
  }
  (*DAT_7103ff44a0)(*(undefined8 *)(param_1 + 0xb0),(bVar1 >> 1 ^ 0xff) & 1);
  (*(code *)*DAT_7103a6fd98)
            (*(undefined8 *)(param_1 + 0xb0),(*(byte *)(param_2 + 0x2d) >> 2 ^ 0xff) & 1);
  if ((*(byte *)(param_1 + 1) >> 1 & 1) == 0) {
    return;
  }
                    // WARNING: Could not recover jumptable at 0x0071005fc814. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)*DAT_7103a6fda0)(*(undefined8 *)(param_1 + 0xb0),*(byte *)(param_2 + 0x2d) >> 3 & 1);
  return;
}



void FUN_71005fc820(long param_1,long *param_2)

{
  undefined8 *puVar1;
  long lVar2;
  ulong uVar3;
  
  puVar1 = DAT_7103a6fd20;
  uVar3 = (ulong)*(byte *)((long)param_2 + 0x25);
  if (uVar3 != 0) {
    lVar2 = *param_2;
    do {
      (*(code *)*puVar1)(*(undefined8 *)(param_1 + 0xb0),lVar2);
      lVar2 = lVar2 + 8;
      uVar3 = uVar3 - 1;
    } while (uVar3 != 0);
  }
  (*(code *)*DAT_7103a6fd28)(*(undefined8 *)(param_1 + 0xb0),(long)param_2 + 0xc);
  (*(code *)*DAT_7103a6fd30)(*(undefined8 *)(param_1 + 0xb0),param_2 + 1);
                    // WARNING: Could not recover jumptable at 0x0071005fc8c0. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)*DAT_7103a6fd38)(*(undefined8 *)(param_1 + 0xb0),param_2 + 2);
  return;
}



void FUN_71005fc8c4(long param_1,long param_2)

{
  undefined8 *puVar1;
  
  (*(code *)*DAT_7103a6fd40)(*(undefined8 *)(param_1 + 0xb0));
  (*(code *)*DAT_7103a6fd48)(*(undefined8 *)(param_1 + 0xb0),3,*(undefined4 *)(param_2 + 8));
  (*(code *)*DAT_7103a6fd50)(*(undefined8 *)(param_1 + 0xb0),3,*(undefined4 *)(param_2 + 0xc));
  puVar1 = DAT_7103a6fd58;
  (*(code *)*DAT_7103a6fd58)(*(undefined8 *)(param_1 + 0xb0),2,*(undefined4 *)(param_2 + 0x10));
  (*(code *)*puVar1)(*(undefined8 *)(param_1 + 0xb0),1,*(undefined4 *)(param_2 + 0x14));
  if ((*(ushort *)(param_2 + 0x1a) >> 3 & 1) == 0) {
                    // WARNING: Could not recover jumptable at 0x0071005fc988. Too many branches
                    // WARNING: Treating indirect jump as call
    (*(code *)*DAT_7103a6fd60)(0,0x3f800000,*(undefined8 *)(param_1 + 0xb0),0);
    return;
  }
  return;
}



void FUN_71005fc99c(long param_1,long param_2)

{
  (*(code *)*DAT_7103a678d8)
            (*(undefined8 *)(param_1 + 0xb0),*(undefined4 *)(param_2 + 8),
             *(undefined8 *)(param_2 + 0x18));
                    // WARNING: Could not recover jumptable at 0x0071005fc9ec. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)*DAT_7103a678e0)
            (*(undefined8 *)(param_1 + 0xb0),*(undefined4 *)(param_2 + 4),
             *(undefined8 *)(param_2 + 0x10));
  return;
}



void FUN_71005fc9f0(long param_1,long param_2,ulong param_3)

{
  uint uVar1;
  undefined8 uVar2;
  
  if (param_2 == 0) {
    uVar2 = 0;
  }
  else {
    uVar2 = *(undefined8 *)(param_2 + 8);
    if ((*(byte *)(param_2 + 1) & 1) == 0) {
      uVar1 = *(uint *)(param_2 + 4);
      goto LAB_71005fca28;
    }
  }
  uVar1 = FUN_71006015c0(param_3 & 0xffffffff);
LAB_71005fca28:
                    // WARNING: Could not recover jumptable at 0x0071005fca44. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)*DAT_7103a678d0)(*(undefined8 *)(param_1 + 0xb0),uVar2,uVar1);
  return;
}



void FUN_71005fca50(long param_1,uint param_2,long *param_3,long param_4)

{
  undefined8 uVar1;
  undefined8 uVar2;
  ulong uVar3;
  undefined8 *puVar4;
  undefined8 *puVar5;
  long lVar6;
  undefined8 local_90 [16];
  
  puVar4 = local_90;
  local_90[0xe] = 0;
  local_90[0xf] = 0;
  local_90[0xc] = 0;
  local_90[0xd] = 0;
  local_90[10] = 0;
  local_90[0xb] = 0;
  local_90[8] = 0;
  local_90[9] = 0;
  local_90[6] = 0;
  local_90[7] = 0;
  local_90[4] = 0;
  local_90[5] = 0;
  local_90[2] = 0;
  local_90[3] = 0;
  local_90[0] = 0;
  local_90[1] = 0;
  if (0 < (int)param_2) {
    puVar5 = local_90 + 8;
    uVar3 = (ulong)param_2;
    do {
      lVar6 = *param_3;
      if (lVar6 != 0) {
        uVar1 = *(undefined8 *)(lVar6 + 0x10);
        *puVar5 = *(undefined8 *)(lVar6 + 8);
        *puVar4 = uVar1;
      }
      puVar4 = puVar4 + 1;
      puVar5 = puVar5 + 1;
      param_3 = param_3 + 1;
      uVar3 = uVar3 - 1;
    } while (uVar3 != 0);
  }
  if (param_4 == 0) {
    uVar1 = 0;
    uVar2 = 0;
  }
  else {
    uVar1 = *(undefined8 *)(param_4 + 8);
    uVar2 = *(undefined8 *)(param_4 + 0x10);
  }
  (*(code *)*DAT_7103a67650)
            (*(undefined8 *)(param_1 + 0xb0),(ulong)param_2,local_90 + 8,local_90,uVar1,uVar2);
  return;
}



void FUN_71005fcafc(long param_1,undefined4 param_2,undefined8 param_3,undefined8 param_4,
                   undefined8 param_5)

{
  undefined8 uVar1;
  undefined8 uVar2;
  
  uVar2 = *(undefined8 *)(param_1 + 0xb0);
  uVar1 = ret_7100601614();
                    // WARNING: Could not recover jumptable at 0x0071005fcb48. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)*DAT_7103a678c0)(uVar2,param_2,uVar1,param_5);
  return;
}



void FUN_71005fcb4c(long param_1,long *param_2)

{
  long lVar1;
  uint uVar2;
  undefined8 *puVar3;
  undefined8 *puVar4;
  
  (*(code *)*DAT_7103a67658)
            ((float)(double)param_2[4],(float)(double)param_2[5],*(undefined8 *)(param_1 + 0xb0));
  puVar3 = DAT_7103a67660;
  (*(code *)*DAT_7103a67660)(*(undefined8 *)(param_1 + 0xb0),0,1,param_2 + 2);
  puVar4 = DAT_7103a67668;
  (*(code *)*DAT_7103a67668)(*(undefined8 *)(param_1 + 0xb0),0,1,param_2 + 6);
  if (1 < (int)param_2[1]) {
    uVar2 = (int)param_2[1] - 1;
    lVar1 = *param_2 + (ulong)uVar2 * 0x10;
    (*(code *)*puVar3)(*(undefined8 *)(param_1 + 0xb0),1,uVar2);
    (*(code *)*DAT_7103a6fda8)(*(undefined8 *)(param_1 + 0xb0),1,uVar2,lVar1);
                    // WARNING: Could not recover jumptable at 0x0071005fcc3c. Too many branches
                    // WARNING: Treating indirect jump as call
    (*(code *)*puVar4)(*(undefined8 *)(param_1 + 0xb0),1,uVar2,lVar1 + (ulong)uVar2 * 8);
    return;
  }
  return;
}



void FUN_71005fcc54(long param_1,long param_2,undefined4 *param_3,long param_4,undefined4 *param_5,
                   uint param_6)

{
  long lVar1;
  long lVar2;
  undefined8 *puVar3;
  undefined8 *puVar4;
  int iVar5;
  int *piVar6;
  undefined4 *puVar7;
  undefined8 local_b8;
  undefined8 uStack_b0;
  undefined8 local_a8;
  undefined8 uStack_a0;
  undefined4 local_98;
  undefined4 uStack_94;
  undefined4 local_90;
  undefined4 uStack_8c;
  undefined4 local_88;
  undefined4 uStack_84;
  undefined4 local_80;
  undefined4 uStack_7c;
  undefined4 local_78;
  undefined4 uStack_74;
  int local_70;
  int iStack_6c;
  undefined4 local_68;
  undefined4 local_64;
  undefined4 local_60;
  undefined4 uStack_5c;
  int local_58;
  undefined4 local_54;
  int local_38;
  undefined4 local_34;
  
  puVar3 = DAT_7103a6fdb8;
  iVar5 = (*(code *)*DAT_7103a6fdb8)(*(undefined8 *)(param_2 + 8));
  local_34 = param_3[1];
  local_54 = param_3[2];
  local_38 = param_3[4];
  local_58 = param_3[5];
  if (iVar5 == 3) {
    piVar6 = &local_38;
    puVar7 = &local_34;
LAB_71005fccd4:
    iVar5 = param_3[8];
    *puVar7 = param_3[7];
    if (iVar5 < 2) {
      iVar5 = 1;
    }
    *piVar6 = iVar5;
  }
  else if (iVar5 == 6 || iVar5 == 4) {
    piVar6 = &local_58;
    puVar7 = &local_54;
    goto LAB_71005fccd4;
  }
  iVar5 = (*(code *)*puVar3)(*(undefined8 *)(param_4 + 8));
  puVar3 = DAT_7103a64af8;
  uStack_5c = param_5[1];
  local_64 = param_5[2];
  local_60 = param_5[4];
  local_68 = param_5[5];
  if (iVar5 == 3) {
    lVar1 = -0x10;
    lVar2 = -0xc;
  }
  else {
    if ((iVar5 != 6) && (iVar5 != 4)) goto LAB_71005fcd4c;
    lVar1 = -0x18;
    lVar2 = -0x14;
  }
  iVar5 = param_5[8];
  *(undefined4 *)(&stack0xffffffffffffffb0 + lVar2) = param_5[7];
  if (iVar5 < 2) {
    iVar5 = 1;
  }
  *(int *)(&stack0xffffffffffffffb0 + lVar1) = iVar5;
LAB_71005fcd4c:
  local_80 = *param_3;
  uStack_7c = local_34;
  uStack_74 = param_3[3];
  local_78 = local_54;
  local_70 = local_38;
  iStack_6c = local_58;
  local_98 = *param_5;
  uStack_8c = param_5[3];
  local_a8 = 0;
  uStack_a0 = 0;
  uStack_94 = uStack_5c;
  local_90 = local_64;
  local_88 = local_60;
  uStack_84 = local_68;
  (*(code *)*DAT_7103a64af8)(&local_a8);
  puVar4 = DAT_7103a64b08;
  (*(code *)*DAT_7103a64b08)(&local_a8,*(undefined2 *)(param_3 + 6),1);
  local_b8 = 0;
  uStack_b0 = 0;
  (*(code *)*puVar3)(&local_b8);
  (*(code *)*puVar4)(&local_b8,*(undefined2 *)(param_5 + 6),1);
  (*(code *)*DAT_7103a6fdc0)
            (*(undefined8 *)(param_1 + 0xb0),*(undefined8 *)(param_4 + 8),&local_b8,&local_98,
             *(undefined8 *)(param_2 + 8),&local_a8,&local_80,param_6 & 1);
  return;
}



void FUN_71005fce28(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                   long param_5,long param_6,undefined4 *param_7)

{
  undefined4 local_20;
  undefined4 uStack_1c;
  undefined4 local_18;
  undefined4 uStack_14;
  
  local_20 = param_1;
  uStack_1c = param_2;
  local_18 = param_3;
  uStack_14 = param_4;
  FUN_71005fce54(param_5,param_6,&local_20,param_7);
  return;
}



void FUN_71005fce54(long param_1,long param_2,undefined8 param_3,undefined4 *param_4)

{
  undefined8 uVar1;
  long lVar2;
  bool bVar3;
  char cVar4;
  int iVar5;
  int iVar6;
  undefined4 local_7c;
  undefined4 local_78;
  int local_74;
  uint local_70;
  uint uStack_6c;
  undefined8 uStack_68;
  undefined4 local_60;
  int local_5c;
  int local_58;
  int local_54;
  
  uVar1 = *(undefined8 *)(param_2 + 8);
  lVar2 = *(long *)(param_2 + 0x10);
  local_60 = 0;
  local_70 = 0;
  uStack_6c = 0;
  uStack_68 = 0;
  local_74 = 0;
  if (lVar2 == 0) {
    local_70 = (*(code *)*DAT_7103a6fdb8)(uVar1);
    bVar3 = false;
  }
  else {
    local_78 = 0;
    (*(code *)*DAT_7103a6fdf0)(lVar2,&uStack_6c,&local_78);
    (*(code *)*DAT_7103a6fdf8)(lVar2,&local_70);
    local_7c = 0;
    cVar4 = (*(code *)*DAT_7103a6fe00)(lVar2,&local_7c,&local_74);
    bVar3 = cVar4 == '\x01';
  }
  iVar5 = (*(code *)*DAT_7103a6fe08)(uVar1);
  iVar6 = (*(code *)*DAT_7103a6fe10)(uVar1);
  local_58 = iVar6;
  local_54 = (*(code *)*DAT_7103a6fe18)(uVar1);
  local_5c = iVar5 >> (uStack_6c & 0x1f);
  if (local_5c < 2) {
    local_5c = 1;
  }
  if ((local_70 == 0) || (local_70 == 3)) {
LAB_71005fcfb4:
    if (param_4 != (undefined4 *)0x0) {
      if (local_70 == 3) {
        local_58 = param_4[1];
        uStack_68 = CONCAT44(*param_4,(undefined4)uStack_68);
      }
      else if ((local_70 & 0xfffffffd) == 4) {
        local_60 = *param_4;
        local_54 = param_4[1];
      }
      goto LAB_71005fd018;
    }
    if (!bVar3) goto LAB_71005fd018;
    if (local_70 == 3) {
      local_58 = local_74;
      goto LAB_71005fd018;
    }
    if ((local_70 & 0xfffffffd) != 4) goto LAB_71005fd018;
  }
  else {
    local_58 = iVar6 >> (uStack_6c & 0x1f);
    if (local_58 < 2) {
      local_58 = 1;
    }
    if (local_70 != 2) goto LAB_71005fcfb4;
    local_54 = local_54 >> (uStack_6c & 0x1f);
    if (local_54 < 2) {
      local_54 = 1;
    }
    if (!bVar3) goto LAB_71005fd018;
  }
  local_54 = local_74;
LAB_71005fd018:
  (*(code *)*DAT_7103a67648)(*(undefined8 *)(param_1 + 0xb0),uVar1,lVar2,&uStack_68,param_3,0xf);
  return;
}



void FUN_71005fd19c(long param_1,uint param_2)

{
  if ((param_2 & 0x49c0) != 0) {
                    // WARNING: Could not recover jumptable at 0x0071005fd1bc. Too many branches
                    // WARNING: Treating indirect jump as call
    (*(code *)*DAT_7103a633f0)(*(undefined8 *)(param_1 + 0xb0),1);
    return;
  }
  return;
}



void FUN_71005fd1c4(long param_1,uint param_2)

{
  if (((param_2 >> 6 & 0x48) != 0 || (param_2 & 0x4020) != 0) || (param_2 & 0x2050) != 0) {
                    // WARNING: Could not recover jumptable at 0x0071005fd200. Too many branches
                    // WARNING: Treating indirect jump as call
    (*(code *)*DAT_7103a633f0)(*(undefined8 *)(param_1 + 0xb0));
    return;
  }
  return;
}



void FUN_71005fd210(long param_1,undefined4 param_2,uint param_3,long param_4)

{
  ulong uVar1;
  undefined4 *puVar2;
  undefined8 *puVar3;
  undefined4 *puVar4;
  ulong uVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  undefined4 uVar8;
  undefined8 local_1b0;
  undefined8 uStack_1a8;
  undefined8 local_1a0;
  undefined8 uStack_198;
  undefined8 local_190;
  undefined8 uStack_188;
  undefined8 local_180;
  undefined8 uStack_178;
  undefined8 local_170;
  undefined8 uStack_168;
  undefined8 local_160;
  undefined8 uStack_158;
  undefined8 local_150;
  undefined8 uStack_148;
  undefined8 local_140;
  undefined8 uStack_138;
  undefined1 local_130 [8];
  undefined8 uStack_128;
  undefined8 local_120;
  undefined8 uStack_118;
  undefined8 local_110;
  undefined8 uStack_108;
  undefined8 local_100;
  undefined8 uStack_f8;
  undefined8 local_f0;
  undefined8 uStack_e8;
  undefined8 local_e0;
  undefined8 uStack_d8;
  undefined8 local_d0;
  undefined8 uStack_c8;
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
  undefined8 local_50;
  undefined8 uStack_48;
  undefined8 local_40;
  undefined8 uStack_38;
  
  puVar3 = &local_1b0;
  uVar5 = (ulong)param_3;
  local_40 = 0;
  uStack_38 = 0;
  local_50 = 0;
  uStack_48 = 0;
  local_60 = 0;
  uStack_58 = 0;
  local_70 = 0;
  uStack_68 = 0;
  local_80 = 0;
  uStack_78 = 0;
  local_90 = 0;
  uStack_88 = 0;
  local_a0 = 0;
  uStack_98 = 0;
  local_b0 = 0;
  uStack_a8 = 0;
  local_c0 = 0;
  uStack_b8 = 0;
  local_d0 = 0;
  uStack_c8 = 0;
  local_e0 = 0;
  uStack_d8 = 0;
  local_f0 = 0;
  uStack_e8 = 0;
  local_100 = 0;
  uStack_f8 = 0;
  local_110 = 0;
  uStack_108 = 0;
  local_120 = 0;
  uStack_118 = 0;
  local_130 = (undefined1  [8])0x0;
  uStack_128 = 0;
  local_140 = 0;
  uStack_138 = 0;
  local_150 = 0;
  uStack_148 = 0;
  local_160 = 0;
  uStack_158 = 0;
  local_170 = 0;
  uStack_168 = 0;
  local_180 = 0;
  uStack_178 = 0;
  local_190 = 0;
  uStack_188 = 0;
  local_1a0 = 0;
  uStack_198 = 0;
  local_1b0 = 0;
  uStack_1a8 = 0;
  if (0 < (int)param_3) {
    puVar2 = (undefined4 *)(param_4 + 0xc);
    puVar4 = (undefined4 *)local_130;
    uVar1 = uVar5;
    do {
      uVar1 = uVar1 - 1;
      *puVar4 = puVar2[-3];
      uVar7 = *puVar2;
      uVar8 = puVar2[1];
      uVar6 = puVar2[2];
      *(undefined8 *)(puVar4 + 1) = *(undefined8 *)(puVar2 + -2);
      puVar4[3] = uVar7;
      puVar2 = puVar2 + 0xc;
      *(undefined4 *)puVar3 = uVar8;
      puVar4 = puVar4 + 4;
      *(undefined4 *)((long)puVar3 + 4) = uVar6;
      puVar3 = (undefined8 *)((long)puVar3 + 8);
    } while (uVar1 != 0);
  }
  (*(code *)*DAT_7103a67660)(*(undefined8 *)(param_1 + 0xb0),param_2,uVar5,local_130);
  (*(code *)*DAT_7103a6fda8)(*(undefined8 *)(param_1 + 0xb0),param_2,uVar5,&local_1b0);
  return;
}



void FUN_71005fd340(long param_1,undefined8 param_2,uint param_3,long param_4)

{
  undefined4 uVar1;
  ulong uVar2;
  long lVar3;
  undefined4 *puVar4;
  undefined1 local_120 [8];
  undefined8 uStack_118;
  undefined8 local_110;
  undefined8 uStack_108;
  undefined8 local_100;
  undefined8 uStack_f8;
  undefined8 local_f0;
  undefined8 uStack_e8;
  undefined8 local_e0;
  undefined8 uStack_d8;
  undefined8 local_d0;
  undefined8 uStack_c8;
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
  undefined8 local_50;
  undefined8 uStack_48;
  undefined8 local_40;
  undefined8 uStack_38;
  undefined8 local_30;
  undefined8 uStack_28;
  
  puVar4 = (undefined4 *)local_120;
  local_30 = 0;
  uStack_28 = 0;
  local_40 = 0;
  uStack_38 = 0;
  local_50 = 0;
  uStack_48 = 0;
  local_60 = 0;
  uStack_58 = 0;
  local_70 = 0;
  uStack_68 = 0;
  local_80 = 0;
  uStack_78 = 0;
  local_90 = 0;
  uStack_88 = 0;
  local_a0 = 0;
  uStack_98 = 0;
  local_b0 = 0;
  uStack_a8 = 0;
  local_c0 = 0;
  uStack_b8 = 0;
  local_d0 = 0;
  uStack_c8 = 0;
  local_e0 = 0;
  uStack_d8 = 0;
  local_f0 = 0;
  uStack_e8 = 0;
  local_100 = 0;
  uStack_f8 = 0;
  local_110 = 0;
  uStack_108 = 0;
  local_120 = (undefined1  [8])0x0;
  uStack_118 = 0;
  if (0 < (int)param_3) {
    lVar3 = param_4 + 8;
    uVar2 = (ulong)param_3;
    do {
      uVar2 = uVar2 - 1;
      *puVar4 = *(undefined4 *)(lVar3 + -8);
      uVar1 = *(undefined4 *)(lVar3 + 4);
      *(undefined8 *)(puVar4 + 1) = *(undefined8 *)(lVar3 + -4);
      lVar3 = lVar3 + 0x20;
      puVar4[3] = uVar1;
      puVar4 = puVar4 + 4;
    } while (uVar2 != 0);
  }
  (*(code *)*DAT_7103a67668)(*(undefined8 *)(param_1 + 0xb0),param_2,(ulong)param_3,local_120);
  return;
}



void FUN_71005fd3f4(long param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                   undefined8 param_5,undefined8 param_6)

{
  undefined8 uVar1;
  undefined8 uVar2;
  
  uVar2 = *(undefined8 *)(param_1 + 0xb0);
  uVar1 = ret_7100601614();
                    // WARNING: Could not recover jumptable at 0x0071005fd458. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)*DAT_7103a6fe70)(uVar2,uVar1,param_3,param_4,param_5,param_6);
  return;
}



void FUN_71005fd45c(long param_1,undefined4 param_2,uint param_3,undefined4 *param_4,
                   undefined4 *param_5)

{
  undefined4 uVar1;
  undefined8 uVar2;
  undefined8 uVar3;
  
  uVar2 = (*DAT_7103ff3700)(**(undefined8 **)(param_1 + 8),*param_4,*param_5);
  uVar3 = *(undefined8 *)(param_1 + 0xb0);
  uVar1 = FUN_71006015b0((ulong)param_3);
                    // WARNING: Could not recover jumptable at 0x0071005fd4d0. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)*DAT_7103a6fe78)(uVar3,uVar1,param_2,uVar2);
  return;
}



void FUN_71005fd4d4(long param_1,undefined4 param_2,ulong param_3,undefined8 param_4,
                   undefined8 param_5)

{
  undefined4 uVar1;
  undefined8 uVar2;
  undefined8 uVar3;
  
  uVar3 = *(undefined8 *)(param_1 + 0xb0);
  uVar1 = FUN_71006015b0(param_3 & 0xffffffff);
  uVar2 = ret_7100601614();
                    // WARNING: Could not recover jumptable at 0x0071005fd53c. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)*DAT_7103a678c8)(uVar3,uVar1,param_2,uVar2,param_5);
  return;
}



void FUN_71005fd540(long param_1,undefined4 param_2,ulong param_3,undefined8 param_4,
                   undefined8 param_5)

{
  undefined4 uVar1;
  undefined8 uVar2;
  undefined8 uVar3;
  
  uVar3 = *(undefined8 *)(param_1 + 0xb0);
  uVar1 = FUN_71006015b0(param_3 & 0xffffffff);
  uVar2 = ret_7100601614();
                    // WARNING: Could not recover jumptable at 0x0071005fd5a8. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)*DAT_7103a68da0)(uVar3,uVar1,param_2,uVar2,param_5);
  return;
}



uint FUN_71005fd5b0(uint param_1,uint param_2)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  
  uVar1 = param_2 - 0x1a;
  if (uVar1 < 0x21) {
    if (param_2 - 0x27 < 0x14) {
      uVar3 = *(uint *)(&DAT_710329b708 + (long)(int)(param_2 - 0x27) * 4);
    }
    else {
      uVar3 = 4;
    }
    iVar2 = param_1 + uVar3;
    param_1 = 0;
    if (uVar3 != 0) {
      param_1 = (iVar2 - 1U) / uVar3;
    }
  }
  if (uVar1 < 0x22) {
    return *(int *)(&DAT_710329b758 + (long)(int)uVar1 * 4) * param_1;
  }
  if ((int)param_2 < 3) {
    return param_1;
  }
  if (10 < param_2) {
    if (param_2 < 0x15) {
      return param_1 * 4;
    }
    if (0x17 < param_2) {
      iVar2 = 0xc;
      if (param_2 != 0x18) {
        iVar2 = 0x10;
      }
      return iVar2 * param_1;
    }
    return param_1 * 8;
  }
  return param_1 * 2;
}



ulong FUN_71005fd670(int param_1,uint param_2,uint param_3)

{
  bool bVar1;
  ulong uVar2;
  uint uVar3;
  uint uVar4;
  
  if (param_1 == 3) {
    return 2;
  }
  if (param_1 != 2) {
    if (param_1 == 1) {
      uVar3 = 4;
      if ((param_2 & 1) == 0) {
        uVar3 = 0;
      }
      return (ulong)uVar3;
    }
    uVar2 = thunk_EXT_FUN_02e95df0();
    return uVar2;
  }
  bVar1 = (param_3 & 1) == 0;
  uVar3 = 6;
  if (bVar1) {
    uVar3 = 1;
  }
  uVar4 = 7;
  if (bVar1) {
    uVar4 = 5;
  }
  if ((param_2 & 1) != 0) {
    uVar3 = uVar4;
  }
  return (ulong)uVar3;
}



undefined4 FUN_71005fd6d0(long param_1,ulong param_2,uint param_3,long param_4)

{
  bool bVar1;
  uint uVar2;
  int iVar3;
  ulong uVar4;
  ulong uVar5;
  int iVar6;
  long lVar7;
  ulong uVar8;
  long *plVar9;
  long lVar10;
  long lVar11;
  uint *puVar12;
  
  if (param_1 == 0) {
    return 0xffffffff;
  }
  lVar10 = *(long *)(param_1 + *(long *)(&DAT_710329b678 + (param_2 & 0xffffffff) * 8));
  if (lVar10 != 0) {
    if ((int)param_3 < 6) {
      lVar11 = *(long *)(lVar10 + *(long *)(&DAT_710329b6a8 + (ulong)param_3 * 8));
      lVar7 = lVar10;
    }
    else {
      lVar7 = *(long *)(lVar10 + 0x58);
      if (lVar7 == 0) {
        return 0xffffffff;
      }
      lVar11 = *(long *)(lVar7 + *(long *)(&DAT_7102ebfb10 + (ulong)(param_3 - 6) * 8));
    }
    if (lVar11 == 0) {
      return 0xffffffff;
    }
    if (param_4 == 0) {
      uVar4 = 0;
    }
    else {
      uVar4 = thunk_EXT_FUN_02e95df0(lVar7,param_4);
    }
    uVar5 = (ulong)*(ushort *)(lVar11 + 0xc);
    puVar12 = (uint *)((int *)(lVar11 + 8) + uVar5 * 4);
    uVar2 = *puVar12;
    if (*(int *)(lVar11 + 8) < (int)*puVar12) {
      do {
        uVar8 = (long)((ulong)uVar2 << 0x20) >> 0x23;
        if (uVar8 < uVar4) {
          uVar8 = (ulong)(*(byte *)(param_4 + uVar4 + ~uVar8) >> ((ulong)uVar2 & 7)) & 1;
        }
        else {
          uVar8 = 0;
        }
        uVar5 = (ulong)*(ushort *)(lVar11 + 8 + uVar5 * 0x10 + uVar8 * 2 + 4);
        puVar12 = (uint *)(lVar11 + 8 + uVar5 * 0x10);
        bVar1 = (int)uVar2 < (int)*puVar12;
        uVar2 = *puVar12;
      } while (bVar1);
    }
    if (uVar4 != **(ushort **)(puVar12 + 2)) {
      return 0xffffffff;
    }
    iVar3 = thunk_EXT_FUN_02e95df0(*(ushort **)(puVar12 + 2) + 1,param_4);
    if (iVar3 != 0) {
      return 0xffffffff;
    }
    iVar3 = (int)((ulong)((long)puVar12 + (-0x18 - lVar11)) >> 4);
    if (iVar3 < 0) {
      return 0xffffffff;
    }
    if ((int)param_3 < 6) {
      if (param_3 == 0) {
        iVar6 = 0;
        goto LAB_71005fd874;
      }
      plVar9 = (long *)(&DAT_710329b6d8 + (ulong)param_3 * 8);
      lVar7 = lVar10;
    }
    else {
      lVar7 = *(long *)(lVar10 + 0x58);
      if (lVar7 == 0) {
        return 0xffffffff;
      }
      plVar9 = (long *)(&DAT_7102ec04f0 + (ulong)(param_3 - 6) * 8);
    }
    iVar6 = *(int *)(lVar7 + *plVar9);
    if (-1 < iVar6) {
LAB_71005fd874:
      return *(undefined4 *)(*(long *)(lVar10 + 0x38) + (ulong)(uint)(iVar6 + iVar3) * 4);
    }
  }
  return 0xffffffff;
}



undefined8 FUN_71005fd894(void)

{
  return 0x1000;
}



undefined8 FUN_71005fd89c(void)

{
  return 0x1000;
}



void FUN_71005fd8a4(undefined8 param_1)

{
  thunk_EXT_FUN_02e95df0(param_1,0,0x120);
  return;
}
