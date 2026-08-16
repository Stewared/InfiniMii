
bool FUN_71019c9690(int *param_1,int *param_2,int *param_3)

{
  int iVar1;
  undefined8 *puVar2;
  long *plVar3;
  uint uVar4;
  uint uVar5;
  ulong uVar6;
  long lVar7;
  int *piVar8;
  undefined8 *puVar9;
  int iVar10;
  
  iVar1 = FUN_71019c9020(param_2,param_1);
  if ((iVar1 != 9) && (iVar1 = FUN_71019c9020(param_3,param_1), iVar1 != 9)) {
    return false;
  }
  puVar9 = DAT_7103a59c40;
  uVar4 = param_1[1];
  if ((int)uVar4 < 0) {
LAB_71019c9728:
    puVar2 = FUN_7100baff84();
  }
  else {
    lVar7 = *(long *)((uint *)*DAT_7103a59c40 + 2);
    if (*(uint *)*DAT_7103a59c40 <= uVar4) {
      uVar4 = 0;
      if (lVar7 != 0) goto LAB_71019c96fc;
      goto LAB_71019c9728;
    }
    if (lVar7 == 0) goto LAB_71019c9728;
LAB_71019c96fc:
    lVar7 = lVar7 + (ulong)uVar4 * 0x10;
    if ((*(int *)(lVar7 + 4) != *param_1) ||
       (puVar2 = *(undefined8 **)(lVar7 + 8), puVar2 == (undefined8 *)0x0)) goto LAB_71019c9728;
  }
  iVar1 = *(int *)((long)puVar2 + 0xbc);
  if ((iVar1 == 0) || (plVar3 = (long *)((long)iVar1 + (long)puVar2 + 0xbc), plVar3 == (long *)0x0))
  {
    plVar3 = FUN_7100cb5368();
    uVar4 = *(uint *)((long)plVar3 + 0x34);
    if (-1 < (int)uVar4) goto LAB_71019c9744;
LAB_71019c978c:
    puVar2 = FUN_7100baff84();
  }
  else {
    uVar4 = *(uint *)((long)plVar3 + 0x34);
    if ((int)uVar4 < 0) goto LAB_71019c978c;
LAB_71019c9744:
    lVar7 = *(long *)((uint *)*puVar9 + 2);
    if (*(uint *)*puVar9 <= uVar4) {
      uVar4 = 0;
      if (lVar7 != 0) goto LAB_71019c975c;
      goto LAB_71019c978c;
    }
    if (lVar7 == 0) goto LAB_71019c978c;
LAB_71019c975c:
    lVar7 = lVar7 + (ulong)uVar4 * 0x10;
    if ((*(int *)(lVar7 + 4) != (int)plVar3[6]) ||
       (puVar2 = *(undefined8 **)(lVar7 + 8), puVar2 == (undefined8 *)0x0)) goto LAB_71019c978c;
  }
  iVar1 = *(int *)(puVar2 + 0x12);
  if ((iVar1 == 0) ||
     (plVar3 = (long *)((long)iVar1 + (long)(puVar2 + 0x12)), plVar3 == (long *)0x0)) {
    plVar3 = FUN_7100d59ce0();
  }
  if ((int)plVar3[5] < 2) {
    return false;
  }
  uVar5 = param_2[1];
  iVar1 = *param_3;
  uVar4 = param_3[1];
  if ((int)uVar5 < 0) {
LAB_71019c981c:
    piVar8 = &DAT_71040104d0;
  }
  else {
    lVar7 = *(long *)((uint *)*puVar9 + 2);
    if (lVar7 == 0) goto LAB_71019c981c;
    if (*(uint *)*puVar9 <= uVar5) {
      uVar5 = 0;
    }
    if (*(int *)(lVar7 + (ulong)uVar5 * 0x10 + 4) != *param_2) goto LAB_71019c981c;
    puVar2 = *(undefined8 **)(lVar7 + (ulong)uVar5 * 0x10 + 8);
    if (puVar2 == (undefined8 *)0x0) {
      puVar2 = FUN_7100baff84();
    }
    iVar10 = *(int *)((long)puVar2 + 0xac);
    piVar8 = DAT_7103a59b68;
    if ((iVar10 != 0) && (lVar7 = (long)iVar10 + (long)puVar2 + 0xac, lVar7 != 0)) {
      piVar8 = (int *)(lVar7 + 0x38);
    }
  }
  uVar6 = (ulong)*(uint *)(plVar3 + 5);
  if (0 < (int)*(uint *)(plVar3 + 5)) {
    puVar2 = (undefined8 *)plVar3[6];
    do {
      if (*piVar8 == *(int *)*puVar2) {
        iVar10 = 0;
        goto joined_r0x0071019c986c;
      }
      puVar2 = puVar2 + 1;
      uVar6 = uVar6 - 1;
    } while (uVar6 != 0);
  }
  iVar10 = 1;
joined_r0x0071019c986c:
  if (-1 < (int)uVar4) {
    lVar7 = *(long *)((uint *)*puVar9 + 2);
    if (lVar7 != 0) {
      if (*(uint *)*puVar9 <= uVar4) {
        uVar4 = 0;
      }
      if (*(int *)(lVar7 + (ulong)uVar4 * 0x10 + 4) == iVar1) {
        puVar9 = *(undefined8 **)(lVar7 + (ulong)uVar4 * 0x10 + 8);
        if (puVar9 == (undefined8 *)0x0) {
          puVar9 = FUN_7100baff84();
        }
        iVar1 = *(int *)((long)puVar9 + 0xac);
        lVar7 = (long)iVar1 + (long)puVar9 + 0xac;
        if (iVar1 != 0 && lVar7 != 0) {
          piVar8 = (int *)(lVar7 + 0x38);
          goto LAB_71019c98c0;
        }
      }
    }
  }
  piVar8 = &DAT_71040104d0;
LAB_71019c98c0:
  uVar4 = *(uint *)(plVar3 + 5);
  uVar6 = (ulong)uVar4;
  if (0 < (int)uVar4) {
    puVar9 = (undefined8 *)plVar3[6];
    do {
      if (*piVar8 == *(int *)*puVar9) {
        iVar1 = 0;
        goto LAB_71019c9908;
      }
      uVar6 = uVar6 - 1;
      puVar9 = puVar9 + 1;
    } while (uVar6 != 0);
  }
  iVar1 = 1;
LAB_71019c9908:
  return iVar1 + iVar10 <= (int)(*(int *)((long)plVar3 + 0x2c) - uVar4);
}



uint FUN_71019c9980(int *param_1,int *param_2)

{
  int iVar1;
  ushort uVar2;
  uint uVar3;
  undefined8 *puVar4;
  undefined8 *puVar5;
  undefined8 uVar6;
  long lVar7;
  uint *puVar8;
  uint local_28 [2];
  
  uVar3 = param_2[1];
  puVar5 = DAT_7103a59c40;
  if ((int)uVar3 < 0) {
LAB_71019c99f8:
    puVar8 = &DAT_71040104d0;
  }
  else {
    lVar7 = *(long *)((uint *)*DAT_7103a59c40 + 2);
    if (lVar7 == 0) goto LAB_71019c99f8;
    if (*(uint *)*DAT_7103a59c40 <= uVar3) {
      uVar3 = 0;
    }
    if (*(int *)(lVar7 + (ulong)uVar3 * 0x10 + 4) != *param_2) goto LAB_71019c99f8;
    puVar4 = *(undefined8 **)(lVar7 + (ulong)uVar3 * 0x10 + 8);
    if (puVar4 == (undefined8 *)0x0) {
      puVar4 = FUN_7100baff84();
      puVar5 = &DAT_71040e7d48;
    }
    iVar1 = *(int *)((long)puVar4 + 0xac);
    lVar7 = (long)iVar1 + (long)puVar4 + 0xac;
    if (iVar1 == 0 || lVar7 == 0) goto LAB_71019c99f8;
    puVar8 = (uint *)(lVar7 + 0x38);
  }
  local_28[0] = *puVar8;
  uVar3 = param_1[1];
  if ((int)uVar3 < 0) {
LAB_71019c9a5c:
    puVar5 = FUN_7100baff84();
  }
  else {
    lVar7 = *(long *)((uint *)*puVar5 + 2);
    if (*(uint *)*puVar5 <= uVar3) {
      uVar3 = 0;
      if (lVar7 != 0) goto LAB_71019c9a28;
      goto LAB_71019c9a5c;
    }
    if (lVar7 == 0) goto LAB_71019c9a5c;
LAB_71019c9a28:
    lVar7 = lVar7 + (ulong)uVar3 * 0x10;
    if ((*(int *)(lVar7 + 4) != *param_1) ||
       (puVar5 = *(undefined8 **)(lVar7 + 8), puVar5 == (undefined8 *)0x0)) goto LAB_71019c9a5c;
  }
  iVar1 = *(int *)(puVar5 + 0xf);
  if ((iVar1 != 0) && (lVar7 = (long)iVar1 + (long)(puVar5 + 0xf), lVar7 != 0)) {
    local_28[1] = 1;
    uVar2 = FUN_7100e38b38(lVar7,local_28,local_28 + 1);
    if ((uVar2 & 1) != 0) {
      uVar3 = 0xf;
      goto LAB_71019c9ab8;
    }
  }
  uVar3 = FUN_71019c9020(param_1,param_2);
  if (uVar3 < 8) {
    uVar3 = (uint)*(undefined8 *)(&DAT_71032b4608 + (long)(int)uVar3 * 8);
  }
  else {
    uVar3 = 0;
  }
LAB_71019c9ab8:
  uVar6 = FUN_71019c9b00(param_1,param_2,uVar3,0);
  return (uint)uVar6 & 1;
}



// WARNING: Type propagation algorithm not settling

undefined8 FUN_71019c9b00(int *param_1,int *param_2,uint param_3,int param_4)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  undefined8 *puVar4;
  ulong uVar5;
  long lVar6;
  long lVar7;
  uint *puVar8;
  long lVar9;
  long lVar10;
  uint uVar11;
  uint uVar12;
  long lVar13;
  uint *puVar14;
  long lVar15;
  int *piVar16;
  uint local_70;
  uint uStack_6c;
  uint local_68;
  uint local_64;
  
  if (param_3 == 0) {
    return 0;
  }
  uVar11 = param_1[1];
  if ((int)uVar11 < 0) {
    return 0;
  }
  lVar6 = *(long *)(DAT_71040e7d48 + 2);
  if (lVar6 == 0) {
    return 0;
  }
  uVar12 = *DAT_71040e7d48;
  if (uVar12 <= uVar11) {
    uVar11 = 0;
  }
  if (*(int *)(lVar6 + (ulong)uVar11 * 0x10 + 4) != *param_1) {
    return 0;
  }
  uVar2 = param_2[1];
  if ((int)uVar2 < 0) {
    return 0;
  }
  uVar3 = uVar2;
  if (uVar12 <= uVar2) {
    uVar3 = 0;
  }
  if (*(int *)(lVar6 + (ulong)uVar3 * 0x10 + 4) != *param_2) {
    return 0;
  }
  lVar15 = *(long *)(lVar6 + (ulong)uVar11 * 0x10 + 8);
  if (lVar15 != 0) {
    piVar16 = (int *)(lVar15 + 0x78);
    iVar1 = *piVar16;
    lVar15 = 0;
    if (iVar1 != 0) {
      lVar15 = (long)iVar1 + (long)piVar16;
    }
    if (uVar12 <= uVar2) {
      uVar2 = 0;
    }
    goto LAB_71019c9bbc;
  }
  puVar4 = FUN_7100baff84();
  iVar1 = *(int *)(puVar4 + 0xf);
  uVar2 = param_2[1];
  lVar15 = 0;
  if (iVar1 != 0) {
    lVar15 = (long)iVar1 + (long)(puVar4 + 0xf);
  }
  if ((int)uVar2 < 0) {
LAB_71019c9c34:
    puVar4 = FUN_7100baff84();
  }
  else {
    lVar6 = *(long *)(DAT_71040e7d48 + 2);
    if (*DAT_71040e7d48 <= uVar2) {
      uVar2 = 0;
      if (lVar6 != 0) goto LAB_71019c9bbc;
      goto LAB_71019c9c34;
    }
    if (lVar6 == 0) goto LAB_71019c9c34;
LAB_71019c9bbc:
    if ((*(int *)(lVar6 + (ulong)uVar2 * 0x10 + 4) != *param_2) ||
       (puVar4 = *(undefined8 **)(lVar6 + (ulong)uVar2 * 0x10 + 8), puVar4 == (undefined8 *)0x0))
    goto LAB_71019c9c34;
  }
  iVar1 = *(int *)(puVar4 + 0xf);
  lVar6 = 0;
  if (iVar1 != 0) {
    lVar6 = (long)iVar1 + (long)(puVar4 + 0xf);
  }
  uVar11 = param_1[1];
  if (((int)uVar11 < 0) || (lVar7 = *(long *)(DAT_71040e7d48 + 2), lVar7 == 0)) {
LAB_71019c9cac:
    puVar8 = &DAT_71040104d0;
  }
  else {
    if (*DAT_71040e7d48 <= uVar11) {
      uVar11 = 0;
    }
    if (*(int *)(lVar7 + (ulong)uVar11 * 0x10 + 4) != *param_1) goto LAB_71019c9cac;
    puVar4 = *(undefined8 **)(lVar7 + (ulong)uVar11 * 0x10 + 8);
    if (puVar4 == (undefined8 *)0x0) {
      puVar4 = FUN_7100baff84();
    }
    iVar1 = *(int *)((long)puVar4 + 0xac);
    puVar8 = DAT_7103a59b68;
    if ((iVar1 != 0) && (lVar7 = (long)iVar1 + (long)puVar4 + 0xac, lVar7 != 0)) {
      puVar8 = (uint *)(lVar7 + 0x38);
    }
  }
  uVar11 = *puVar8;
  uVar12 = param_2[1];
  if (((int)uVar12 < 0) || (lVar7 = *(long *)(DAT_71040e7d48 + 2), lVar7 == 0)) {
LAB_71019c9d1c:
    puVar8 = &DAT_71040104d0;
  }
  else {
    if (*DAT_71040e7d48 <= uVar12) {
      uVar12 = 0;
    }
    if (*(int *)(lVar7 + (ulong)uVar12 * 0x10 + 4) != *param_2) goto LAB_71019c9d1c;
    puVar4 = *(undefined8 **)(lVar7 + (ulong)uVar12 * 0x10 + 8);
    if (puVar4 == (undefined8 *)0x0) {
      puVar4 = FUN_7100baff84();
    }
    iVar1 = *(int *)((long)puVar4 + 0xac);
    puVar8 = DAT_7103a59b68;
    if ((iVar1 != 0) && (lVar7 = (long)iVar1 + (long)puVar4 + 0xac, lVar7 != 0)) {
      puVar8 = (uint *)(lVar7 + 0x38);
    }
  }
  uVar12 = *puVar8;
  if (lVar15 == 0) {
    return 0;
  }
  if (lVar6 == 0) {
    return 0;
  }
  if (0x45 < uVar11) {
    return 0;
  }
  if (0x45 < uVar12) {
    return 0;
  }
  local_68 = uVar12;
  if (((param_3 & 1) != 0) &&
     (local_70 = uVar12, uStack_6c = uVar11, uVar5 = FUN_7101d8b410(&uStack_6c,&local_70),
     (uVar5 & 1) == 0)) {
    return 0;
  }
  if ((param_3 >> 1 & 1) != 0) {
    uVar2 = FUN_7100e369bc(lVar15,&local_68);
    if (7 < uVar2) {
      return 0;
    }
    uVar2 = FUN_7100e36b50(lVar15,&local_68);
    if (1 < uVar2) {
      return 0;
    }
  }
  if ((param_3 >> 4 & 1) != 0) {
    uVar2 = param_1[1];
    if ((int)uVar2 < 0) {
LAB_71019c9df0:
      puVar4 = FUN_7100baff84();
    }
    else {
      lVar7 = *(long *)(DAT_71040e7d48 + 2);
      if (*DAT_71040e7d48 <= uVar2) {
        uVar2 = 0;
        if (lVar7 != 0) goto LAB_71019c9d88;
        goto LAB_71019c9df0;
      }
      if (lVar7 == 0) goto LAB_71019c9df0;
LAB_71019c9d88:
      lVar7 = lVar7 + (ulong)uVar2 * 0x10;
      if ((*(int *)(lVar7 + 4) != *param_1) ||
         (puVar4 = *(undefined8 **)(lVar7 + 8), puVar4 == (undefined8 *)0x0)) goto LAB_71019c9df0;
    }
    iVar1 = *(int *)((long)puVar4 + 0xac);
    uVar2 = 0;
    if ((iVar1 != 0) && (lVar7 = (long)iVar1 + (long)puVar4 + 0xac, lVar7 != 0)) {
      iVar1 = *(int *)(lVar7 + 0x34a0);
      if (iVar1 == 1) {
        uVar2 = 1;
      }
      else if (iVar1 == 2) {
        uVar2 = 0;
      }
      else {
        uVar2 = FUN_7101d8bbf0(param_1);
      }
    }
    uVar3 = param_2[1];
    if ((int)uVar3 < 0) {
LAB_71019c9e8c:
      puVar4 = FUN_7100baff84();
      piVar16 = (int *)((long)puVar4 + 0xac);
      iVar1 = *piVar16;
    }
    else {
      lVar7 = *(long *)(DAT_71040e7d48 + 2);
      if (*DAT_71040e7d48 <= uVar3) {
        uVar3 = 0;
        if (lVar7 != 0) goto LAB_71019c9e58;
        goto LAB_71019c9e8c;
      }
      if (lVar7 == 0) goto LAB_71019c9e8c;
LAB_71019c9e58:
      lVar7 = lVar7 + (ulong)uVar3 * 0x10;
      if ((*(int *)(lVar7 + 4) != *param_2) || (lVar7 = *(long *)(lVar7 + 8), lVar7 == 0))
      goto LAB_71019c9e8c;
      piVar16 = (int *)(lVar7 + 0xac);
      iVar1 = *piVar16;
    }
    if (((iVar1 != 0) && ((long)iVar1 + (long)piVar16 != 0)) &&
       (iVar1 = *(int *)((long)iVar1 + (long)piVar16 + 0x34a0), iVar1 != 2)) {
      if (iVar1 == 1) {
        if ((uVar2 & 1) == 0) {
          return 0;
        }
        goto LAB_71019c9ec0;
      }
      uVar3 = FUN_7101d8bbf0(param_2);
      uVar2 = uVar2 ^ uVar3;
    }
    if ((uVar2 & 1) != 0) {
      return 0;
    }
  }
LAB_71019c9ec0:
  if ((param_3 >> 5 & 1) == 0) goto LAB_71019c9ec4;
  uVar2 = param_1[1];
  if ((int)uVar2 < 0) {
LAB_71019ca2b8:
    puVar4 = FUN_7100baff84();
  }
  else {
    lVar7 = *(long *)(DAT_71040e7d48 + 2);
    if (*DAT_71040e7d48 <= uVar2) {
      uVar2 = 0;
      if (lVar7 != 0) goto LAB_71019c9f80;
      goto LAB_71019ca2b8;
    }
    if (lVar7 == 0) goto LAB_71019ca2b8;
LAB_71019c9f80:
    lVar7 = lVar7 + (ulong)uVar2 * 0x10;
    if ((*(int *)(lVar7 + 4) != *param_1) ||
       (puVar4 = *(undefined8 **)(lVar7 + 8), puVar4 == (undefined8 *)0x0)) goto LAB_71019ca2b8;
  }
  iVar1 = *(int *)((long)puVar4 + 0xac);
  uVar2 = 0;
  if ((iVar1 != 0) && (lVar7 = (long)iVar1 + (long)puVar4 + 0xac, lVar7 != 0)) {
    iVar1 = *(int *)(lVar7 + 0x34a0);
    if (iVar1 == 1) {
      uVar2 = 1;
    }
    else if (iVar1 == 2) {
      uVar2 = 0;
    }
    else {
      uVar2 = FUN_7101d8bbf0(param_1);
    }
  }
  uVar3 = param_2[1];
  if ((int)uVar3 < 0) {
LAB_71019ca34c:
    puVar4 = FUN_7100baff84();
  }
  else {
    lVar7 = *(long *)(DAT_71040e7d48 + 2);
    if (*DAT_71040e7d48 <= uVar3) {
      uVar3 = 0;
      if (lVar7 != 0) goto LAB_71019ca320;
      goto LAB_71019ca34c;
    }
    if (lVar7 == 0) goto LAB_71019ca34c;
LAB_71019ca320:
    lVar7 = lVar7 + (ulong)uVar3 * 0x10;
    if ((*(int *)(lVar7 + 4) != *param_2) ||
       (puVar4 = *(undefined8 **)(lVar7 + 8), puVar4 == (undefined8 *)0x0)) goto LAB_71019ca34c;
  }
  iVar1 = *(int *)((long)puVar4 + 0xac);
  if (iVar1 == 0) {
    return 0;
  }
  lVar7 = (long)iVar1 + (long)puVar4 + 0xac;
  if (lVar7 == 0) {
    return 0;
  }
  iVar1 = *(int *)(lVar7 + 0x34a0);
  if (iVar1 == 1) {
    uVar3 = 1;
  }
  else {
    if (iVar1 == 2) {
      return 0;
    }
    uVar3 = FUN_7101d8bbf0(param_2);
  }
  if ((uVar2 & uVar3 & 1) == 0) {
    return 0;
  }
LAB_71019c9ec4:
  puVar8 = DAT_7103a59b68;
  if (param_4 == 0) {
    if ((((param_3 >> 2 & 1) != 0) &&
        (((*(uint *)(lVar15 + 0x2c) < 0x46 && (*(uint *)(lVar15 + 0x2c) != uVar12)) ||
         ((*(uint *)(lVar15 + 0x30) < 0x46 && (*(uint *)(lVar15 + 0x30) != uVar12)))))) ||
       ((((param_3 >> 3 & 1) != 0 && (*(uint *)(lVar6 + 0x30) < 0x46)) &&
        (*(uint *)(lVar6 + 0x30) != uVar11)))) {
      return 0;
    }
  }
  else {
    lVar7 = *(long *)(*DAT_7103a59c30 + 0x19a7f8);
    if (0 < *(int *)(lVar7 + 8)) {
      if ((param_3 >> 2 & 1) == 0) {
        if ((param_3 >> 3 & 1) == 0) {
          lVar6 = 0;
          do {
            lVar15 = *(long *)(*(long *)(lVar7 + 0x10) + lVar6 * 8);
            uVar11 = *(uint *)(lVar15 + 0x404);
            if ((-1 < (int)uVar11) && (lVar13 = *(long *)(DAT_71040e7d48 + 2), lVar13 != 0)) {
              if (*DAT_71040e7d48 <= uVar11) {
                uVar11 = 0;
              }
              if ((*(int *)(lVar13 + (ulong)uVar11 * 0x10 + 4) == *(int *)(lVar15 + 0x400)) &&
                 (*(long *)(lVar13 + (ulong)uVar11 * 0x10 + 8) == 0)) {
                FUN_7100baff84();
              }
            }
            lVar6 = lVar6 + 1;
          } while (lVar6 < *(int *)(lVar7 + 8));
        }
        else {
          lVar13 = 0;
          do {
            lVar15 = *(long *)(*(long *)(lVar7 + 0x10) + lVar13 * 8);
            uVar2 = *(uint *)(lVar15 + 0x404);
            puVar14 = puVar8;
            if ((-1 < (int)uVar2) && (lVar9 = *(long *)(DAT_71040e7d48 + 2), lVar9 != 0)) {
              if (*DAT_71040e7d48 <= uVar2) {
                uVar2 = 0;
              }
              if (*(int *)(lVar9 + (ulong)uVar2 * 0x10 + 4) == *(int *)(lVar15 + 0x400)) {
                puVar4 = *(undefined8 **)(lVar9 + (ulong)uVar2 * 0x10 + 8);
                if (puVar4 == (undefined8 *)0x0) {
                  puVar4 = FUN_7100baff84();
                }
                iVar1 = *(int *)((long)puVar4 + 0xac);
                lVar15 = (long)iVar1 + (long)puVar4 + 0xac;
                if (iVar1 != 0 && lVar15 != 0) {
                  puVar14 = (uint *)(lVar15 + 0x38);
                }
              }
            }
            local_64 = *puVar14;
            if (((local_64 < 0x46 && local_64 != uVar11) && local_64 != uVar12) &&
               (iVar1 = FUN_7100e369bc(lVar6,&local_64), iVar1 == 6)) {
LAB_71019ca29c:
              if (*(long *)(*(long *)(lVar7 + 0x10) + lVar13 * 8) == 0) {
                return 1;
              }
              return 0;
            }
            lVar13 = lVar13 + 1;
          } while (lVar13 < *(int *)(lVar7 + 8));
        }
      }
      else if ((param_3 >> 3 & 1) == 0) {
        lVar13 = 0;
        do {
          lVar6 = *(long *)(*(long *)(lVar7 + 0x10) + lVar13 * 8);
          uVar2 = *(uint *)(lVar6 + 0x404);
          puVar14 = puVar8;
          if ((-1 < (int)uVar2) && (lVar9 = *(long *)(DAT_71040e7d48 + 2), lVar9 != 0)) {
            if (*DAT_71040e7d48 <= uVar2) {
              uVar2 = 0;
            }
            if (*(int *)(lVar9 + (ulong)uVar2 * 0x10 + 4) == *(int *)(lVar6 + 0x400)) {
              puVar4 = *(undefined8 **)(lVar9 + (ulong)uVar2 * 0x10 + 8);
              if (puVar4 == (undefined8 *)0x0) {
                puVar4 = FUN_7100baff84();
              }
              iVar1 = *(int *)((long)puVar4 + 0xac);
              lVar6 = (long)iVar1 + (long)puVar4 + 0xac;
              if (iVar1 != 0 && lVar6 != 0) {
                puVar14 = (uint *)(lVar6 + 0x38);
              }
            }
          }
          local_64 = *puVar14;
          if (((local_64 < 0x46 && local_64 != uVar11) && local_64 != uVar12) &&
             ((iVar1 = FUN_7100e369bc(lVar15,&local_64), iVar1 == 4 ||
              (iVar1 = FUN_7100e369bc(lVar15,&local_64), iVar1 == 6)))) goto LAB_71019ca29c;
          lVar13 = lVar13 + 1;
        } while (lVar13 < *(int *)(lVar7 + 8));
      }
      else {
        lVar13 = 0;
        do {
          lVar9 = *(long *)(*(long *)(lVar7 + 0x10) + lVar13 * 8);
          uVar2 = *(uint *)(lVar9 + 0x404);
          puVar14 = puVar8;
          if ((-1 < (int)uVar2) && (lVar10 = *(long *)(DAT_71040e7d48 + 2), lVar10 != 0)) {
            if (*DAT_71040e7d48 <= uVar2) {
              uVar2 = 0;
            }
            if (*(int *)(lVar10 + (ulong)uVar2 * 0x10 + 4) == *(int *)(lVar9 + 0x400)) {
              puVar4 = *(undefined8 **)(lVar10 + (ulong)uVar2 * 0x10 + 8);
              if (puVar4 == (undefined8 *)0x0) {
                puVar4 = FUN_7100baff84();
              }
              iVar1 = *(int *)((long)puVar4 + 0xac);
              lVar9 = (long)iVar1 + (long)puVar4 + 0xac;
              if (iVar1 != 0 && lVar9 != 0) {
                puVar14 = (uint *)(lVar9 + 0x38);
              }
            }
          }
          local_64 = *puVar14;
          if (((local_64 < 0x46 && local_64 != uVar11) && local_64 != uVar12) &&
             (((iVar1 = FUN_7100e369bc(lVar6,&local_64), iVar1 == 6 ||
               (iVar1 = FUN_7100e369bc(lVar15,&local_64), iVar1 == 4)) ||
              (iVar1 = FUN_7100e369bc(lVar15,&local_64), iVar1 == 6)))) goto LAB_71019ca29c;
          lVar13 = lVar13 + 1;
        } while (lVar13 < *(int *)(lVar7 + 8));
      }
    }
  }
  return 1;
}



undefined4 FUN_71019ca3d0(int *param_1,int *param_2,ulong param_3)

{
  ushort uVar1;
  int iVar2;
  undefined8 *puVar3;
  undefined8 *puVar4;
  undefined4 uVar5;
  long lVar6;
  uint *puVar7;
  uint uVar8;
  uint local_18 [2];
  
  uVar8 = param_2[1];
  puVar4 = DAT_7103a59c40;
  if ((int)uVar8 < 0) {
LAB_71019ca44c:
    puVar7 = &DAT_71040104d0;
  }
  else {
    lVar6 = *(long *)((uint *)*DAT_7103a59c40 + 2);
    if (lVar6 == 0) goto LAB_71019ca44c;
    if (*(uint *)*DAT_7103a59c40 <= uVar8) {
      uVar8 = 0;
    }
    if (*(int *)(lVar6 + (ulong)uVar8 * 0x10 + 4) != *param_2) goto LAB_71019ca44c;
    puVar3 = *(undefined8 **)(lVar6 + (ulong)uVar8 * 0x10 + 8);
    if (puVar3 == (undefined8 *)0x0) {
      puVar3 = FUN_7100baff84();
      puVar4 = &DAT_71040e7d48;
    }
    iVar2 = *(int *)((long)puVar3 + 0xac);
    lVar6 = (long)iVar2 + (long)puVar3 + 0xac;
    if (iVar2 == 0 || lVar6 == 0) goto LAB_71019ca44c;
    puVar7 = (uint *)(lVar6 + 0x38);
  }
  local_18[0] = *puVar7;
  uVar8 = param_1[1];
  if (-1 < (int)uVar8) {
    lVar6 = *(long *)((uint *)*puVar4 + 2);
    if (*(uint *)*puVar4 <= uVar8) {
      uVar8 = 0;
    }
    if (((lVar6 != 0) && (lVar6 = lVar6 + (ulong)uVar8 * 0x10, *(int *)(lVar6 + 4) == *param_1)) &&
       (puVar4 = *(undefined8 **)(lVar6 + 8), puVar4 != (undefined8 *)0x0)) goto LAB_71019ca4b4;
  }
  puVar4 = FUN_7100baff84();
LAB_71019ca4b4:
  iVar2 = *(int *)(puVar4 + 0xf);
  if ((iVar2 != 0) && (lVar6 = (long)iVar2 + (long)(puVar4 + 0xf), lVar6 != 0)) {
    local_18[1] = 1;
    uVar1 = FUN_7100e38b38(lVar6,local_18,local_18 + 1);
    if ((uVar1 & 1) != 0) {
      if ((param_3 & 1) != 0) {
        return 0x1f;
      }
      return 0xf;
    }
  }
  iVar2 = FUN_71019c9020(param_1,param_2);
  if (1 < iVar2 - 4U) {
    if (iVar2 == 6) {
      return 0x23;
    }
    if (iVar2 != 7) {
      return 0;
    }
  }
  uVar5 = 0x13;
  if ((param_3 & 1) == 0) {
    uVar5 = 3;
  }
  return uVar5;
}



bool FUN_71019ca560(int *param_1,int *param_2)

{
  long lVar1;
  int iVar2;
  bool bVar3;
  uint uVar4;
  undefined8 *puVar5;
  
  uVar4 = FUN_71019c9980(param_1,param_2);
  if (((uVar4 & 1) == 0) ||
     ((uVar4 = FUN_71019c9020(param_1,param_2), uVar4 != 0xffffffff &&
      ((1 << (ulong)(uVar4 & 0x1f) & 0x50U) != 0)))) {
    return false;
  }
  uVar4 = param_1[1];
  if (-1 < (int)uVar4) {
    if (*DAT_71040e7d48 <= uVar4) {
      uVar4 = 0;
    }
    if (((*(long *)(DAT_71040e7d48 + 2) != 0) &&
        (lVar1 = *(long *)(DAT_71040e7d48 + 2) + (ulong)uVar4 * 0x10,
        *(int *)(lVar1 + 4) == *param_1)) &&
       (puVar5 = *(undefined8 **)(lVar1 + 8), puVar5 != (undefined8 *)0x0)) goto LAB_71019ca608;
  }
  puVar5 = FUN_7100baff84();
LAB_71019ca608:
  iVar2 = *(int *)(puVar5 + 0xf);
  bVar3 = false;
  if ((iVar2 != 0) && (lVar1 = (long)iVar2 + (long)(puVar5 + 0xf), lVar1 != 0)) {
    bVar3 = 0x45 < *(uint *)(lVar1 + 0x28);
  }
  return bVar3;
}



bool FUN_71019ca640(int *param_1,int *param_2)

{
  int iVar1;
  bool bVar2;
  uint uVar3;
  undefined8 *puVar4;
  undefined8 *puVar5;
  long *plVar6;
  long lVar7;
  long lVar8;
  
  uVar3 = FUN_71019c9980(param_1,param_2);
  if (((uVar3 & 1) == 0) ||
     ((uVar3 = FUN_71019c9020(param_1,param_2), puVar5 = DAT_7103a59c40, uVar3 != 0xffffffff &&
      ((1 << (ulong)(uVar3 & 0x1f) & 0x50U) != 0)))) {
    return false;
  }
  uVar3 = param_1[1];
  if ((int)uVar3 < 0) {
LAB_71019ca6e4:
    puVar4 = FUN_7100baff84();
  }
  else {
    lVar7 = *(long *)((uint *)*DAT_7103a59c40 + 2);
    if (*(uint *)*DAT_7103a59c40 <= uVar3) {
      uVar3 = 0;
      if (lVar7 != 0) goto LAB_71019ca6b8;
      goto LAB_71019ca6e4;
    }
    if (lVar7 == 0) goto LAB_71019ca6e4;
LAB_71019ca6b8:
    lVar7 = lVar7 + (ulong)uVar3 * 0x10;
    if ((*(int *)(lVar7 + 4) != *param_1) ||
       (puVar4 = *(undefined8 **)(lVar7 + 8), puVar4 == (undefined8 *)0x0)) goto LAB_71019ca6e4;
  }
  iVar1 = *(int *)(puVar4 + 0xf);
  uVar3 = param_2[1];
  lVar7 = 0;
  if (iVar1 != 0) {
    lVar7 = (long)iVar1 + (long)(puVar4 + 0xf);
  }
  if (-1 < (int)uVar3) {
    lVar8 = *(long *)((uint *)*puVar5 + 2);
    if (*(uint *)*puVar5 <= uVar3) {
      uVar3 = 0;
    }
    if (((lVar8 != 0) && (lVar8 = lVar8 + (ulong)uVar3 * 0x10, *(int *)(lVar8 + 4) == *param_2)) &&
       (puVar5 = *(undefined8 **)(lVar8 + 8), puVar5 != (undefined8 *)0x0)) goto LAB_71019ca748;
  }
  puVar5 = FUN_7100baff84();
LAB_71019ca748:
  iVar1 = *(int *)((long)puVar5 + 0xac);
  if ((iVar1 == 0) || (plVar6 = (long *)((long)iVar1 + (long)puVar5 + 0xac), plVar6 == (long *)0x0))
  {
    plVar6 = FUN_7100bafffc();
  }
  bVar2 = false;
  if (lVar7 != 0) {
    bVar2 = false;
    if (*(uint *)(plVar6 + 7) < 0x46) {
      bVar2 = *(uint *)(lVar7 + 0x28) < 0x46 && *(uint *)(lVar7 + 0x28) != *(uint *)(plVar6 + 7);
    }
  }
  return bVar2;
}



bool FUN_71019ca7a0(int *param_1)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  undefined8 *puVar7;
  long lVar8;
  int iVar9;
  uint local_4;
  
  uVar2 = param_1[1];
  if ((int)uVar2 < 0) {
    return false;
  }
  lVar8 = *(long *)(DAT_71040e7d48 + 2);
  if (lVar8 != 0) {
    if (*DAT_71040e7d48 <= uVar2) {
      uVar2 = 0;
    }
    if (*(int *)(lVar8 + (ulong)uVar2 * 0x10 + 4) == *param_1) {
      puVar7 = *(undefined8 **)(lVar8 + (ulong)uVar2 * 0x10 + 8);
      if (puVar7 == (undefined8 *)0x0) {
        puVar7 = FUN_7100baff84();
      }
      iVar6 = *(int *)(puVar7 + 0xf);
      lVar8 = (long)iVar6 + (long)(puVar7 + 0xf);
      if ((iVar6 != 0 && lVar8 != 0) && (local_4 = *(uint *)(lVar8 + 0x2c), local_4 < 0x46)) {
        iVar6 = FUN_7100e36ce4(lVar8,&local_4);
        lVar8 = FUN_7100bd09b0(*DAT_7103a59ec8);
        uVar2 = *(uint *)(lVar8 + 0x2c);
        if (uVar2 != 0) {
          uVar4 = 0;
          if (uVar2 != 0) {
            uVar4 = 0xe197afdf / uVar2;
          }
          uVar4 = 0xe197afdf - uVar4 * uVar2;
          uVar5 = uVar4;
          do {
            iVar3 = *(int *)(*(long *)(lVar8 + 0x20) +
                            (-(ulong)(uVar5 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar5 << 4));
            if (iVar3 == -0x1e685021) {
              lVar8 = *(long *)(*(long *)(lVar8 + 0x20) + (long)(int)uVar5 * 0x10 + 8);
              if (lVar8 != 0) {
                iVar9 = *(int *)(lVar8 + 8);
                goto LAB_71019ca8a0;
              }
              break;
            }
            iVar9 = 0;
            if (iVar3 == 0) goto LAB_71019ca8a0;
            uVar1 = 0;
            if ((int)(uVar5 + 1) < (int)uVar2) {
              uVar1 = uVar5 + 1;
            }
            uVar5 = uVar1;
          } while (uVar1 != uVar4);
        }
        iVar9 = 0;
LAB_71019ca8a0:
        return iVar9 <= iVar6;
      }
    }
  }
  return false;
}



void FUN_71019ca8d0(uint *param_1,int *param_2)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  undefined8 *puVar7;
  uint uVar8;
  long lVar9;
  int iVar10;
  uint local_14;
  
  uVar2 = param_2[1];
  uVar8 = DAT_71040104d0;
  if ((-1 < (int)uVar2) && (lVar9 = *(long *)(DAT_71040e7d48 + 2), lVar9 != 0)) {
    if (*DAT_71040e7d48 <= uVar2) {
      uVar2 = 0;
    }
    if (*(int *)(lVar9 + (ulong)uVar2 * 0x10 + 4) == *param_2) {
      puVar7 = *(undefined8 **)(lVar9 + (ulong)uVar2 * 0x10 + 8);
      if (puVar7 == (undefined8 *)0x0) {
        puVar7 = FUN_7100baff84();
      }
      iVar6 = *(int *)(puVar7 + 0xf);
      lVar9 = (long)iVar6 + (long)(puVar7 + 0xf);
      uVar8 = DAT_71040104d0;
      if ((iVar6 != 0 && lVar9 != 0) && (uVar2 = *(uint *)(lVar9 + 0x28), uVar2 < 0x46)) {
        local_14 = uVar2;
        iVar6 = FUN_7100e36ce4(lVar9,&local_14);
        lVar9 = FUN_7100bd09b0(*DAT_7103a59ec8);
        uVar8 = *(uint *)(lVar9 + 0x2c);
        if (uVar8 != 0) {
          uVar4 = 0;
          if (uVar8 != 0) {
            uVar4 = 0x87765674 / uVar8;
          }
          uVar4 = 0x87765674 - uVar4 * uVar8;
          uVar5 = uVar4;
          do {
            iVar3 = *(int *)(*(long *)(lVar9 + 0x20) +
                            (-(ulong)(uVar5 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar5 << 4));
            if (iVar3 == -0x7889a98c) {
              lVar9 = *(long *)(*(long *)(lVar9 + 0x20) + (long)(int)uVar5 * 0x10 + 8);
              if (lVar9 != 0) {
                iVar10 = *(int *)(lVar9 + 8);
                goto LAB_71019ca9e4;
              }
              break;
            }
            iVar10 = 0;
            if (iVar3 == 0) goto LAB_71019ca9e4;
            uVar1 = 0;
            if ((int)(uVar5 + 1) < (int)uVar8) {
              uVar1 = uVar5 + 1;
            }
            uVar5 = uVar1;
          } while (uVar1 != uVar4);
        }
        iVar10 = 0;
LAB_71019ca9e4:
        uVar8 = *DAT_7103a59b68;
        if (iVar10 <= iVar6) {
          uVar8 = uVar2;
        }
      }
    }
  }
  *param_1 = uVar8;
  return;
}



undefined8 FUN_71019caa20(int *param_1,int *param_2)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  long *plVar5;
  int iVar6;
  uint uVar7;
  undefined8 *puVar8;
  ulong uVar9;
  uint uVar10;
  long lVar11;
  long lVar12;
  uint *puVar13;
  long lVar14;
  int iVar15;
  uint local_44;
  uint local_28;
  uint local_24;
  
  uVar10 = param_1[1];
  if ((int)uVar10 < 0) {
    return 0;
  }
  lVar11 = *(long *)(DAT_71040e7d48 + 2);
  if (lVar11 == 0) {
    return 0;
  }
  if (*DAT_71040e7d48 <= uVar10) {
    uVar10 = 0;
  }
  if (*(int *)(lVar11 + (ulong)uVar10 * 0x10 + 4) != *param_1) {
    return 0;
  }
  uVar7 = param_2[1];
  if ((int)uVar7 < 0) {
    return 0;
  }
  if (*DAT_71040e7d48 <= uVar7) {
    uVar7 = 0;
  }
  if (*(int *)(lVar11 + (ulong)uVar7 * 0x10 + 4) != *param_2) {
    return 0;
  }
  puVar8 = *(undefined8 **)(lVar11 + (ulong)uVar10 * 0x10 + 8);
  if (puVar8 == (undefined8 *)0x0) {
    puVar8 = FUN_7100baff84();
  }
  iVar6 = *(int *)(puVar8 + 0xf);
  lVar11 = (long)iVar6 + (long)(puVar8 + 0xf);
  if (iVar6 == 0 || lVar11 == 0) {
    return 0;
  }
  uVar10 = param_2[1];
  if ((int)uVar10 < 0) {
LAB_71019cab1c:
    puVar8 = FUN_7100baff84();
  }
  else {
    lVar14 = *(long *)(DAT_71040e7d48 + 2);
    if (*DAT_71040e7d48 <= uVar10) {
      uVar10 = 0;
      if (lVar14 != 0) goto LAB_71019caae0;
      goto LAB_71019cab1c;
    }
    if (lVar14 == 0) goto LAB_71019cab1c;
LAB_71019caae0:
    lVar14 = lVar14 + (ulong)uVar10 * 0x10;
    if ((*(int *)(lVar14 + 4) != *param_2) ||
       (puVar8 = *(undefined8 **)(lVar14 + 8), puVar8 == (undefined8 *)0x0)) goto LAB_71019cab1c;
  }
  iVar6 = *(int *)(puVar8 + 0xf);
  if (iVar6 == 0) {
    return 0;
  }
  lVar14 = (long)iVar6 + (long)(puVar8 + 0xf);
  if (lVar14 == 0) {
    return 0;
  }
  uVar10 = param_2[1];
  if (((int)uVar10 < 0) || (lVar12 = *(long *)(DAT_71040e7d48 + 2), lVar12 == 0)) {
LAB_71019cab9c:
    puVar13 = &DAT_71040104d0;
  }
  else {
    if (*DAT_71040e7d48 <= uVar10) {
      uVar10 = 0;
    }
    if (*(int *)(lVar12 + (ulong)uVar10 * 0x10 + 4) != *param_2) goto LAB_71019cab9c;
    puVar8 = *(undefined8 **)(lVar12 + (ulong)uVar10 * 0x10 + 8);
    if (puVar8 == (undefined8 *)0x0) {
      puVar8 = FUN_7100baff84();
    }
    iVar6 = *(int *)((long)puVar8 + 0xac);
    puVar13 = DAT_7103a59b68;
    if ((iVar6 != 0) && (lVar12 = (long)iVar6 + (long)puVar8 + 0xac, lVar12 != 0)) {
      puVar13 = (uint *)(lVar12 + 0x38);
    }
  }
  local_24 = *puVar13;
  uVar9 = FUN_71019e45c0(param_1,(int *)&local_24);
  if ((uVar9 & 1) != 0) {
    return 0;
  }
  uVar10 = param_2[1];
  if ((-1 < (int)uVar10) && (lVar12 = *(long *)(DAT_71040e7d48 + 2), lVar12 != 0)) {
    if (*DAT_71040e7d48 <= uVar10) {
      uVar10 = 0;
    }
    if (*(int *)(lVar12 + (ulong)uVar10 * 0x10 + 4) == *param_2) {
      puVar8 = *(undefined8 **)(lVar12 + (ulong)uVar10 * 0x10 + 8);
      if (puVar8 == (undefined8 *)0x0) {
        puVar8 = FUN_7100baff84();
      }
      iVar6 = *(int *)((long)puVar8 + 0xac);
      puVar13 = DAT_7103a59b68;
      if ((iVar6 != 0) && (lVar12 = (long)iVar6 + (long)puVar8 + 0xac, lVar12 != 0)) {
        puVar13 = (uint *)(lVar12 + 0x38);
      }
      goto LAB_71019cac28;
    }
  }
  puVar13 = &DAT_71040104d0;
LAB_71019cac28:
  local_28 = *puVar13;
  iVar6 = FUN_7100e36e78(lVar11,&local_28);
  plVar5 = DAT_7103a59ec8;
  lVar11 = FUN_7100bd09b0(*DAT_7103a59ec8);
  uVar10 = *(uint *)(lVar11 + 0x2c);
  if (uVar10 != 0) {
    uVar7 = 0;
    if (uVar10 != 0) {
      uVar7 = 0xf9eedd97 / uVar10;
    }
    uVar7 = 0xf9eedd97 - uVar7 * uVar10;
    uVar4 = uVar7;
    do {
      iVar3 = *(int *)(*(long *)(lVar11 + 0x20) +
                      (-(ulong)(uVar4 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar4 << 4));
      if (iVar3 == -0x6112269) {
        lVar11 = *(long *)(*(long *)(lVar11 + 0x20) + (long)(int)uVar4 * 0x10 + 8);
        if (lVar11 != 0) {
          iVar15 = *(int *)(lVar11 + 8);
LAB_71019cacbc:
          if (iVar15 < iVar6) {
            return 0;
          }
          goto LAB_71019cace0;
        }
        break;
      }
      iVar15 = 0;
      if (iVar3 == 0) goto LAB_71019cacbc;
      uVar1 = 0;
      if ((int)(uVar4 + 1) < (int)uVar10) {
        uVar1 = uVar4 + 1;
      }
      uVar4 = uVar1;
    } while (uVar1 != uVar7);
  }
  if (0 < iVar6) {
    return 0;
  }
LAB_71019cace0:
  local_44 = *(uint *)(lVar14 + 0x2c);
  if (local_44 < 0x46) {
    uVar7 = FUN_7100e36ce4(lVar14,&local_44);
    lVar11 = FUN_7100bd09b0(*plVar5);
    uVar10 = *(uint *)(lVar11 + 0x2c);
    if (uVar10 != 0) {
      uVar4 = 0;
      if (uVar10 != 0) {
        uVar4 = 0x537d7673 / uVar10;
      }
      uVar4 = 0x537d7673 - uVar4 * uVar10;
      uVar1 = uVar4;
      do {
        iVar3 = *(int *)(*(long *)(lVar11 + 0x20) +
                        (-(ulong)(uVar1 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar1 << 4));
        iVar6 = 0;
        if (iVar3 == 0) {
LAB_71019cad7c:
          if ((int)uVar7 < iVar6) {
            return 1;
          }
          return 0;
        }
        if (iVar3 == 0x537d7673) {
          lVar11 = *(long *)(*(long *)(lVar11 + 0x20) + (long)(int)uVar1 * 0x10 + 8);
          if (lVar11 != 0) {
            iVar6 = *(int *)(lVar11 + 8);
            goto LAB_71019cad7c;
          }
          break;
        }
        uVar2 = 0;
        if ((int)(uVar1 + 1) < (int)uVar10) {
          uVar2 = uVar1 + 1;
        }
        uVar1 = uVar2;
      } while (uVar2 != uVar4);
    }
    if (uVar7 < 0x80000000) {
      return 0;
    }
  }
  return 1;
}



void FUN_71019cb070(uint *param_1,uint *param_2,uint *param_3)

{
  long lVar1;
  long *plVar2;
  byte *pbVar3;
  int iVar4;
  long lVar5;
  long lVar6;
  undefined8 *puVar7;
  long *plVar8;
  uint local_38;
  uint uStack_34;
  
  pbVar3 = DAT_7103a5d688;
  plVar2 = DAT_7103a5d680;
  if (*(long *)(*DAT_7103a5a580 + 8) == 0) {
    lVar5 = 0;
  }
  else {
    lVar5 = *(long *)(*(long *)(*DAT_7103a5a580 + 8) + 0x150);
  }
  lVar1 = DAT_7103a59c60 + 0x10;
  do {
    lVar6 = lVar5;
    if (((((*(byte *)(lVar6 + 0x175) & 1) != 0) || (*(long *)(lVar6 + 0x10) == 0)) ||
        (plVar8 = *(long **)(lVar6 + 0x18), plVar8 == (long *)0x0)) ||
       ((*(int *)((long)plVar8 + 0xc) != *(int *)(lVar6 + 0x20) ||
        (puVar7 = (undefined8 *)*plVar8, puVar7 == (undefined8 *)0x0)))) break;
    if (((*pbVar3 & 1) == 0) && (iVar4 = thunk_EXT_FUN_02e95df0(pbVar3), iVar4 != 0)) {
      *plVar2 = lVar1;
      thunk_EXT_FUN_02e95df0(pbVar3);
    }
    lVar5 = (**(code **)*puVar7)(puVar7,plVar2);
  } while (lVar5 != 0);
  uStack_34 = *param_2;
  local_38 = *param_3;
  FUN_71019cb190(param_1,&uStack_34,&local_38,*(int *)(lVar6 + 0x14c));
  return;
}



// WARNING: Type propagation algorithm not settling

void FUN_71019cb190(uint *param_1,uint *param_2,uint *param_3,int param_4)

{
  bool bVar1;
  int *piVar2;
  undefined4 uVar3;
  uint uVar4;
  int iVar5;
  uint uVar6;
  long *******ppppppplVar7;
  long *******ppppppplVar8;
  undefined8 *******pppppppuVar9;
  undefined8 *******pppppppuVar10;
  undefined8 *******pppppppuVar11;
  undefined8 *******pppppppuVar12;
  undefined8 *******pppppppuVar13;
  undefined8 *******pppppppuVar14;
  undefined8 *******pppppppuVar15;
  undefined8 *******pppppppuVar16;
  undefined8 *******pppppppuVar17;
  undefined8 *******pppppppuVar18;
  undefined8 *******pppppppuVar19;
  undefined8 *******pppppppuVar20;
  undefined8 *******pppppppuVar21;
  undefined8 *******pppppppuVar22;
  undefined8 *******pppppppuVar23;
  undefined8 *******pppppppuVar24;
  undefined8 *******pppppppuVar25;
  undefined8 *******pppppppuVar26;
  undefined8 *******pppppppuVar27;
  undefined8 *******pppppppuVar28;
  undefined8 *******pppppppuVar29;
  undefined8 *******pppppppuVar30;
  undefined8 *******pppppppuVar31;
  undefined8 *******pppppppuVar32;
  undefined8 *******pppppppuVar33;
  undefined8 *******pppppppuVar34;
  undefined8 *******pppppppuVar35;
  undefined8 *******pppppppuVar36;
  undefined8 *******pppppppuVar37;
  undefined8 *******pppppppuVar38;
  undefined8 *******pppppppuVar39;
  undefined8 *******pppppppuVar40;
  undefined8 *******pppppppuVar41;
  undefined8 *******pppppppuVar42;
  undefined8 *******pppppppuVar43;
  undefined8 *******pppppppuVar44;
  undefined8 *******pppppppuVar45;
  undefined8 *******pppppppuVar46;
  undefined8 *******pppppppuVar47;
  undefined8 *******pppppppuVar48;
  undefined8 *******pppppppuVar49;
  undefined8 *******pppppppuVar50;
  undefined8 *******pppppppuVar51;
  undefined8 *******pppppppuVar52;
  undefined8 *******pppppppuVar53;
  undefined8 *******pppppppuVar54;
  undefined8 *******pppppppuVar55;
  undefined8 *******pppppppuVar56;
  undefined8 *******pppppppuVar57;
  undefined8 *******pppppppuVar58;
  undefined8 *******pppppppuVar59;
  undefined8 *******pppppppuVar60;
  undefined8 *******pppppppuVar61;
  undefined8 *******pppppppuVar62;
  undefined8 *******pppppppuVar63;
  undefined8 *******pppppppuVar64;
  undefined8 *******pppppppuVar65;
  undefined8 *******pppppppuVar66;
  undefined8 *******pppppppuVar67;
  undefined8 *******pppppppuVar68;
  undefined8 *******pppppppuVar69;
  undefined8 *******pppppppuVar70;
  undefined8 *******pppppppuVar71;
  undefined8 *******pppppppuVar72;
  undefined8 *******pppppppuVar73;
  undefined8 ******ppppppuVar74;
  undefined8 *****pppppuVar75;
  undefined8 ****ppppuVar76;
  undefined8 ***pppuVar77;
  undefined8 **ppuVar78;
  undefined8 uVar79;
  undefined8 uVar80;
  uint uVar81;
  long *plVar82;
  ushort uVar83;
  uint uVar84;
  int iVar85;
  int iVar86;
  uint uVar87;
  undefined8 *puVar88;
  undefined8 *puVar89;
  int *piVar90;
  long *plVar91;
  uint uVar92;
  long ******pppppplVar93;
  long *******ppppppplVar94;
  long lVar95;
  uint *puVar96;
  uint *puVar97;
  long lVar98;
  ulong uVar99;
  uint uVar100;
  long lVar101;
  uint *puVar102;
  undefined8 *puVar103;
  undefined8 uVar104;
  ulong uVar105;
  long *******ppppppplVar106;
  long lVar107;
  long *******ppppppplVar108;
  long *******ppppppplVar109;
  undefined8 local_7e8;
  undefined8 local_7e0;
  undefined8 **local_7d8;
  undefined8 **ppuStack_7d0;
  undefined8 *local_7c8;
  undefined8 local_7c0;
  undefined8 local_7b8 [2];
  undefined8 local_7a8;
  undefined8 *local_7a0;
  undefined8 **local_798;
  undefined8 **ppuStack_790;
  undefined8 *local_788;
  undefined8 local_780;
  undefined8 local_778;
  long ******pppppplStack_770;
  long *******local_768;
  long *******local_760;
  uint local_758;
  undefined8 *******local_750;
  undefined8 *******pppppppuStack_748;
  int local_740;
  undefined8 *******local_738 [3];
  undefined8 *******local_720 [3];
  undefined8 *******local_708 [3];
  undefined8 *******local_6f0 [3];
  undefined8 *******local_6d8 [3];
  undefined8 *******local_6c0 [3];
  undefined8 *******local_6a8 [3];
  undefined8 *******local_690 [3];
  undefined8 *******local_678 [3];
  undefined8 *******local_660 [3];
  undefined8 *******local_648 [3];
  undefined8 *******local_630 [3];
  undefined8 *******local_618 [3];
  undefined8 *******local_600 [3];
  undefined8 *******local_5e8 [3];
  undefined8 *******local_5d0 [3];
  undefined8 *******local_5b8 [3];
  undefined8 *******local_5a0 [3];
  undefined8 *******local_588 [3];
  undefined8 *******local_570 [3];
  undefined8 *******local_558 [3];
  undefined8 *******local_540 [3];
  undefined8 *******local_528 [3];
  undefined8 *******local_510 [3];
  undefined8 *******local_4f8 [3];
  undefined8 *******local_4e0 [3];
  undefined8 *******local_4c8 [3];
  undefined8 *******local_4b0 [3];
  undefined8 *******local_498 [3];
  undefined8 *******local_480 [3];
  undefined8 *******local_468 [3];
  undefined8 *******local_450 [3];
  undefined8 *******local_438 [3];
  undefined8 *******local_420 [3];
  undefined8 *******local_408 [3];
  undefined8 *******local_3f0 [3];
  undefined8 *******local_3d8 [3];
  undefined8 *******local_3c0 [3];
  undefined8 *******local_3a8 [3];
  undefined8 *******local_390 [3];
  undefined8 *******local_378 [3];
  undefined8 *******local_360 [3];
  undefined8 *******local_348 [3];
  undefined8 *******local_330 [3];
  undefined8 *******local_318 [3];
  undefined8 *******local_300 [3];
  undefined8 *******local_2e8 [3];
  undefined8 *******local_2d0 [3];
  undefined8 *******local_2b8 [3];
  undefined8 *******local_2a0 [3];
  undefined8 *******local_288 [3];
  undefined8 *******local_270 [3];
  undefined8 *******local_258 [3];
  undefined8 *******local_240 [3];
  undefined8 *******local_228 [3];
  undefined8 *******local_210 [3];
  undefined8 *******local_1f8 [3];
  undefined8 *******local_1e0 [3];
  undefined8 *******local_1c8 [3];
  undefined8 *******local_1b0 [3];
  undefined8 *******local_198 [3];
  undefined8 *******local_180 [3];
  undefined8 *******local_168 [3];
  undefined8 ******local_150 [3];
  undefined8 *****local_138 [3];
  undefined8 ****local_120 [3];
  undefined8 ***local_108 [3];
  undefined8 **local_f0 [3];
  undefined8 *local_d8 [3];
  undefined8 local_c0 [3];
  undefined8 local_a8;
  uint local_a0;
  uint uStack_9c;
  uint local_98;
  undefined8 local_94;
  uint *local_88;
  uint *puStack_80;
  uint local_74;
  uint local_70;
  uint local_6c [3];
  
  if (param_1 == (uint *)0x0) {
    return;
  }
  if (1 < (int)*param_1) {
    return;
  }
  local_798 = &local_788;
  local_788 = &local_780;
  local_7a8 = 0;
  local_7a0 = (undefined8 *)0x0;
  local_780 = 0;
  if (&local_778 != (undefined8 *)0x0) {
    local_7a8 = 0x200000000;
    local_7a0 = &local_778;
  }
  local_768 = (long *******)&local_768;
  local_758 = 0;
  local_738[0] = local_720;
  local_720[0] = local_708;
  local_c0[0] = 0;
  local_708[0] = local_6f0;
  uVar87 = *param_3;
  local_6d8[0] = local_6c0;
  local_750 = local_738;
  local_6a8[0] = local_690;
  local_678[0] = local_660;
  local_6f0[0] = local_6d8;
  local_648[0] = local_630;
  local_618[0] = local_600;
  local_6c0[0] = local_6a8;
  local_5e8[0] = local_5d0;
  local_5b8[0] = local_5a0;
  local_690[0] = local_678;
  local_588[0] = local_570;
  local_558[0] = local_540;
  local_660[0] = local_648;
  local_540[0] = local_528;
  local_528[0] = local_510;
  local_630[0] = local_618;
  local_510[0] = local_4f8;
  local_4f8[0] = local_4e0;
  local_600[0] = local_5e8;
  local_4e0[0] = local_4c8;
  local_4c8[0] = local_4b0;
  local_5d0[0] = local_5b8;
  local_4b0[0] = local_498;
  local_498[0] = local_480;
  local_5a0[0] = local_588;
  local_480[0] = local_468;
  local_468[0] = local_450;
  local_570[0] = local_558;
  local_450[0] = local_438;
  local_438[0] = local_420;
  local_420[0] = local_408;
  local_408[0] = local_3f0;
  local_3f0[0] = local_3d8;
  local_3d8[0] = local_3c0;
  local_3c0[0] = local_3a8;
  local_3a8[0] = local_390;
  local_390[0] = local_378;
  local_378[0] = local_360;
  local_360[0] = local_348;
  local_348[0] = local_330;
  local_330[0] = local_318;
  local_318[0] = local_300;
  local_300[0] = local_2e8;
  local_2e8[0] = local_2d0;
  local_2d0[0] = local_2b8;
  local_2b8[0] = local_2a0;
  local_2a0[0] = local_288;
  local_288[0] = local_270;
  local_270[0] = local_258;
  local_258[0] = local_240;
  local_240[0] = local_228;
  local_228[0] = local_210;
  local_210[0] = local_1f8;
  local_1f8[0] = local_1e0;
  local_1e0[0] = local_1c8;
  local_1c8[0] = local_1b0;
  local_1b0[0] = local_198;
  local_198[0] = local_180;
  local_180[0] = local_168;
  local_168[0] = local_150;
  local_150[0] = local_138;
  local_138[0] = local_120;
  local_120[0] = local_108;
  local_108[0] = local_f0;
  local_f0[0] = local_d8;
  local_d8[0] = local_c0;
  lVar101 = *DAT_7103a59c30;
  local_740 = 0x46;
  puVar102 = DAT_7103a59b30;
  if ((*param_2 < 0x46) &&
     (lVar95 = *(long *)(*(long *)(lVar101 + 0x19a8d8) + (ulong)*param_2 * 8 + 0x28), lVar95 != 0))
  {
    puVar102 = (uint *)(lVar95 + 0x400);
  }
  ppppppplVar109 = (long *******)&local_760;
  puVar96 = DAT_7103a59b30;
  if (uVar87 < 0x46) {
    lVar101 = *(long *)(lVar101 + 0x19a8d8);
    lVar95 = *(long *)(lVar101 + (ulong)uVar87 * 8 + 0x28);
    if (lVar95 != 0) {
      puVar96 = (uint *)(lVar95 + 0x400);
    }
  }
  else {
    lVar101 = *(long *)(lVar101 + 0x19a8d8);
  }
  lVar95 = 0x28;
  ppuStack_790 = local_798;
  local_760 = local_768;
  pppppppuStack_748 = local_750;
  do {
    lVar107 = *(long *)(lVar101 + lVar95);
    if (lVar107 != 0) {
      uVar84 = *(uint *)(lVar107 + 0x404);
      uVar92 = *(uint *)(lVar107 + 0x400);
      if ((uVar84 != puVar102[1] || uVar92 != *puVar102) &&
         (uVar84 != puVar96[1] || uVar92 != *puVar96)) {
        local_a8 = (long *******)CONCAT44(local_a8._4_4_,uVar87);
        if ((int)uVar84 < 0) {
LAB_71019cb570:
          puVar88 = FUN_7100baff84();
        }
        else {
          puVar97 = (uint *)*DAT_7103a59c40;
          if (*puVar97 <= uVar84) {
            uVar84 = 0;
            lVar98 = *(long *)(puVar97 + 2);
            if (lVar98 != 0) goto LAB_71019cb544;
            goto LAB_71019cb570;
          }
          lVar98 = *(long *)(puVar97 + 2);
          if (lVar98 == 0) goto LAB_71019cb570;
LAB_71019cb544:
          lVar98 = lVar98 + (ulong)uVar84 * 0x10;
          if ((*(uint *)(lVar98 + 4) != uVar92) ||
             (puVar88 = *(undefined8 **)(lVar98 + 8), puVar88 == (undefined8 *)0x0))
          goto LAB_71019cb570;
        }
        iVar85 = *(int *)(puVar88 + 0xf);
        if ((iVar85 != 0) && (lVar98 = (long)iVar85 + (long)(puVar88 + 0xf), lVar98 != 0)) {
          local_7e8 = CONCAT44(local_7e8._4_4_,1);
          uVar83 = FUN_7100e38b38(lVar98,(uint *)&local_a8,(uint *)&local_7e8);
          pppppppuVar9 = local_750;
          if (((uVar83 & 1) != 0) && ((int)local_758 < local_740)) {
            if (local_750 != (undefined8 *******)0x0) {
              local_750 = (undefined8 *******)*local_750;
            }
            *pppppppuVar9 = (undefined8 ******)0xffffffffffffffff;
            *(undefined4 *)pppppppuVar9 = *(undefined4 *)(lVar107 + 0x400);
            uVar3 = *(undefined4 *)(lVar107 + 0x404);
            ppppppplVar106 = pppppppuVar9 + 1;
            *ppppppplVar106 = (long ******)0x0;
            *(undefined4 *)((long)pppppppuVar9 + 4) = uVar3;
            *ppppppplVar106 = (long ******)local_768;
            pppppppuVar9[2] = &local_768;
            if (local_768 != (long *******)0x0) {
              local_768[1] = (long ******)ppppppplVar106;
            }
            local_758 = local_758 + 1;
            local_768 = ppppppplVar106;
          }
        }
      }
    }
    lVar95 = lVar95 + 8;
  } while (lVar95 != 600);
  uVar84 = thunk_EXT_FUN_02e95df0();
  local_7e8._0_4_ = (uVar84 ^ uVar84 >> 0x1e) * 0x6c078965 + 1;
  local_7e8._4_4_ = ((uint)local_7e8 ^ (uint)local_7e8 >> 0x1e) * 0x6c078965 + 2;
  uVar84 = (local_7e8._4_4_ ^ local_7e8._4_4_ >> 0x1e) * 0x6c078965 + 3;
  local_7e0 = (undefined8 *)CONCAT44((uVar84 ^ uVar84 >> 0x1e) * 0x6c078965 + 4,uVar84);
  FUN_71024d4e60((long *)&local_768,(uint *)&local_7e8);
  local_7e8 = CONCAT44(local_7e8._4_4_,uVar87);
  if ((int)local_758 < 2) goto LAB_71019cb68c;
  if (local_758 < 4) {
    ppppppplVar106 = local_768;
    if (local_758 != 2) goto LAB_71019cb67c;
  }
  else {
    ppppppplVar106 = local_760 + 1;
LAB_71019cb67c:
    ppppppplVar106 = (long *******)*ppppppplVar106;
  }
  while (ppppppplVar94 = ppppppplVar106, (long ********)ppppppplVar94 != &local_768) {
    ppppppplVar108 = (long *******)*ppppppplVar94;
    ppppppplVar106 = (long *******)ppppppplVar94[1];
    iVar85 = FUN_71019d0ae0((uint *)&local_7e8,(int *)(ppppppplVar108 + -1),
                            (int *)(ppppppplVar94 + -1));
    if (0 < iVar85) {
      do {
        ppppppplVar108 = (long *******)*ppppppplVar108;
        if ((long ********)ppppppplVar108 == &local_768) {
          ppppppplVar108 = (long *******)&local_768;
          pppppplVar93 = *ppppppplVar94;
          ppppppplVar7 = local_768;
          ppppppplVar8 = local_760;
          uVar87 = local_758;
          pppppppuVar9 = local_750;
          pppppppuVar10 = pppppppuStack_748;
          iVar85 = local_740;
          pppppppuVar11 = local_738[0];
          pppppppuVar12 = local_720[0];
          pppppppuVar13 = local_708[0];
          pppppppuVar14 = local_6f0[0];
          pppppppuVar15 = local_6d8[0];
          pppppppuVar16 = local_6c0[0];
          pppppppuVar17 = local_6a8[0];
          pppppppuVar18 = local_690[0];
          pppppppuVar19 = local_678[0];
          pppppppuVar20 = local_660[0];
          pppppppuVar21 = local_648[0];
          pppppppuVar22 = local_630[0];
          pppppppuVar23 = local_618[0];
          pppppppuVar24 = local_600[0];
          pppppppuVar25 = local_5e8[0];
          pppppppuVar26 = local_5d0[0];
          pppppppuVar27 = local_5b8[0];
          pppppppuVar28 = local_5a0[0];
          pppppppuVar29 = local_588[0];
          pppppppuVar30 = local_570[0];
          pppppppuVar31 = local_558[0];
          pppppppuVar32 = local_540[0];
          pppppppuVar33 = local_528[0];
          pppppppuVar34 = local_510[0];
          pppppppuVar35 = local_4f8[0];
          pppppppuVar36 = local_4e0[0];
          pppppppuVar37 = local_4c8[0];
          pppppppuVar38 = local_4b0[0];
          pppppppuVar39 = local_498[0];
          pppppppuVar40 = local_480[0];
          pppppppuVar41 = local_468[0];
          pppppppuVar42 = local_450[0];
          pppppppuVar43 = local_438[0];
          pppppppuVar44 = local_420[0];
          pppppppuVar45 = local_408[0];
          pppppppuVar46 = local_3f0[0];
          pppppppuVar47 = local_3d8[0];
          pppppppuVar48 = local_3c0[0];
          pppppppuVar49 = local_3a8[0];
          pppppppuVar50 = local_390[0];
          pppppppuVar51 = local_378[0];
          pppppppuVar52 = local_360[0];
          pppppppuVar53 = local_348[0];
          pppppppuVar54 = local_330[0];
          pppppppuVar55 = local_318[0];
          pppppppuVar56 = local_300[0];
          pppppppuVar57 = local_2e8[0];
          pppppppuVar58 = local_2d0[0];
          pppppppuVar59 = local_2b8[0];
          pppppppuVar60 = local_2a0[0];
          pppppppuVar61 = local_288[0];
          pppppppuVar62 = local_270[0];
          pppppppuVar63 = local_258[0];
          pppppppuVar64 = local_240[0];
          pppppppuVar65 = local_228[0];
          pppppppuVar66 = local_210[0];
          pppppppuVar67 = local_1f8[0];
          pppppppuVar68 = local_1e0[0];
          pppppppuVar69 = local_1c8[0];
          pppppppuVar70 = local_1b0[0];
          pppppppuVar71 = local_198[0];
          pppppppuVar72 = local_180[0];
          pppppppuVar73 = local_168[0];
          ppppppuVar74 = local_150[0];
          pppppuVar75 = local_138[0];
          ppppuVar76 = local_120[0];
          pppuVar77 = local_108[0];
          ppuVar78 = local_f0[0];
          puVar88 = local_d8[0];
          uVar104 = local_c0[0];
          uVar79 = local_a8;
          uVar84 = local_a0;
          uVar92 = uStack_9c;
          uVar100 = local_98;
          uVar80 = local_94;
          puVar102 = local_88;
          puVar96 = puStack_80;
          uVar4 = local_74;
          uVar6 = local_70;
          uVar81 = local_6c[0];
          goto joined_r0x0071019cb75c;
        }
        iVar85 = FUN_71019d0ae0((uint *)&local_7e8,(int *)(ppppppplVar108 + -1),
                                (int *)(ppppppplVar94 + -1));
      } while (0 < iVar85);
      pppppplVar93 = *ppppppplVar94;
      ppppppplVar7 = local_768;
      ppppppplVar8 = local_760;
      uVar87 = local_758;
      pppppppuVar9 = local_750;
      pppppppuVar10 = pppppppuStack_748;
      iVar85 = local_740;
      pppppppuVar11 = local_738[0];
      pppppppuVar12 = local_720[0];
      pppppppuVar13 = local_708[0];
      pppppppuVar14 = local_6f0[0];
      pppppppuVar15 = local_6d8[0];
      pppppppuVar16 = local_6c0[0];
      pppppppuVar17 = local_6a8[0];
      pppppppuVar18 = local_690[0];
      pppppppuVar19 = local_678[0];
      pppppppuVar20 = local_660[0];
      pppppppuVar21 = local_648[0];
      pppppppuVar22 = local_630[0];
      pppppppuVar23 = local_618[0];
      pppppppuVar24 = local_600[0];
      pppppppuVar25 = local_5e8[0];
      pppppppuVar26 = local_5d0[0];
      pppppppuVar27 = local_5b8[0];
      pppppppuVar28 = local_5a0[0];
      pppppppuVar29 = local_588[0];
      pppppppuVar30 = local_570[0];
      pppppppuVar31 = local_558[0];
      pppppppuVar32 = local_540[0];
      pppppppuVar33 = local_528[0];
      pppppppuVar34 = local_510[0];
      pppppppuVar35 = local_4f8[0];
      pppppppuVar36 = local_4e0[0];
      pppppppuVar37 = local_4c8[0];
      pppppppuVar38 = local_4b0[0];
      pppppppuVar39 = local_498[0];
      pppppppuVar40 = local_480[0];
      pppppppuVar41 = local_468[0];
      pppppppuVar42 = local_450[0];
      pppppppuVar43 = local_438[0];
      pppppppuVar44 = local_420[0];
      pppppppuVar45 = local_408[0];
      pppppppuVar46 = local_3f0[0];
      pppppppuVar47 = local_3d8[0];
      pppppppuVar48 = local_3c0[0];
      pppppppuVar49 = local_3a8[0];
      pppppppuVar50 = local_390[0];
      pppppppuVar51 = local_378[0];
      pppppppuVar52 = local_360[0];
      pppppppuVar53 = local_348[0];
      pppppppuVar54 = local_330[0];
      pppppppuVar55 = local_318[0];
      pppppppuVar56 = local_300[0];
      pppppppuVar57 = local_2e8[0];
      pppppppuVar58 = local_2d0[0];
      pppppppuVar59 = local_2b8[0];
      pppppppuVar60 = local_2a0[0];
      pppppppuVar61 = local_288[0];
      pppppppuVar62 = local_270[0];
      pppppppuVar63 = local_258[0];
      pppppppuVar64 = local_240[0];
      pppppppuVar65 = local_228[0];
      pppppppuVar66 = local_210[0];
      pppppppuVar67 = local_1f8[0];
      pppppppuVar68 = local_1e0[0];
      pppppppuVar69 = local_1c8[0];
      pppppppuVar70 = local_1b0[0];
      pppppppuVar71 = local_198[0];
      pppppppuVar72 = local_180[0];
      pppppppuVar73 = local_168[0];
      ppppppuVar74 = local_150[0];
      pppppuVar75 = local_138[0];
      ppppuVar76 = local_120[0];
      pppuVar77 = local_108[0];
      ppuVar78 = local_f0[0];
      puVar88 = local_d8[0];
      uVar104 = local_c0[0];
      uVar79 = local_a8;
      uVar84 = local_a0;
      uVar92 = uStack_9c;
      uVar100 = local_98;
      uVar80 = local_94;
      puVar102 = local_88;
      puVar96 = puStack_80;
      uVar4 = local_74;
      uVar6 = local_70;
      uVar81 = local_6c[0];
joined_r0x0071019cb75c:
      if (pppppplVar93 != (long ******)0x0) {
        pppppplVar93[1] = (long *****)ppppppplVar94[1];
      }
      if (ppppppplVar94[1] != (long ******)0x0) {
        *ppppppplVar94[1] = (long *****)*ppppppplVar94;
      }
      *ppppppplVar94 = (long ******)0x0;
      ppppppplVar94[1] = (long ******)0x0;
      pppppplVar93 = ppppppplVar108[1];
      local_760 = ppppppplVar8;
      local_758 = uVar87;
      local_750 = pppppppuVar9;
      pppppppuStack_748 = pppppppuVar10;
      local_740 = iVar85;
      local_738[0] = pppppppuVar11;
      local_720[0] = pppppppuVar12;
      local_708[0] = pppppppuVar13;
      local_6f0[0] = pppppppuVar14;
      local_6d8[0] = pppppppuVar15;
      local_6c0[0] = pppppppuVar16;
      local_6a8[0] = pppppppuVar17;
      local_690[0] = pppppppuVar18;
      local_678[0] = pppppppuVar19;
      local_660[0] = pppppppuVar20;
      local_648[0] = pppppppuVar21;
      local_630[0] = pppppppuVar22;
      local_618[0] = pppppppuVar23;
      local_600[0] = pppppppuVar24;
      local_5e8[0] = pppppppuVar25;
      local_5d0[0] = pppppppuVar26;
      local_5b8[0] = pppppppuVar27;
      local_5a0[0] = pppppppuVar28;
      local_588[0] = pppppppuVar29;
      local_570[0] = pppppppuVar30;
      local_558[0] = pppppppuVar31;
      local_540[0] = pppppppuVar32;
      local_528[0] = pppppppuVar33;
      local_510[0] = pppppppuVar34;
      local_4f8[0] = pppppppuVar35;
      local_4e0[0] = pppppppuVar36;
      local_4c8[0] = pppppppuVar37;
      local_4b0[0] = pppppppuVar38;
      local_498[0] = pppppppuVar39;
      local_480[0] = pppppppuVar40;
      local_468[0] = pppppppuVar41;
      local_450[0] = pppppppuVar42;
      local_438[0] = pppppppuVar43;
      local_420[0] = pppppppuVar44;
      local_408[0] = pppppppuVar45;
      local_3f0[0] = pppppppuVar46;
      local_3d8[0] = pppppppuVar47;
      local_3c0[0] = pppppppuVar48;
      local_3a8[0] = pppppppuVar49;
      local_390[0] = pppppppuVar50;
      local_378[0] = pppppppuVar51;
      local_360[0] = pppppppuVar52;
      local_348[0] = pppppppuVar53;
      local_330[0] = pppppppuVar54;
      local_318[0] = pppppppuVar55;
      local_300[0] = pppppppuVar56;
      local_2e8[0] = pppppppuVar57;
      local_2d0[0] = pppppppuVar58;
      local_2b8[0] = pppppppuVar59;
      local_2a0[0] = pppppppuVar60;
      local_288[0] = pppppppuVar61;
      local_270[0] = pppppppuVar62;
      local_258[0] = pppppppuVar63;
      local_240[0] = pppppppuVar64;
      local_228[0] = pppppppuVar65;
      local_210[0] = pppppppuVar66;
      local_1f8[0] = pppppppuVar67;
      local_1e0[0] = pppppppuVar68;
      local_1c8[0] = pppppppuVar69;
      local_1b0[0] = pppppppuVar70;
      local_198[0] = pppppppuVar71;
      local_180[0] = pppppppuVar72;
      local_168[0] = pppppppuVar73;
      local_150[0] = ppppppuVar74;
      local_138[0] = pppppuVar75;
      local_120[0] = ppppuVar76;
      local_108[0] = pppuVar77;
      local_f0[0] = ppuVar78;
      local_d8[0] = puVar88;
      local_c0[0] = uVar104;
      local_a8 = (long *******)uVar79;
      local_a0 = uVar84;
      uStack_9c = uVar92;
      local_98 = uVar100;
      local_94 = uVar80;
      local_88 = puVar102;
      puStack_80 = puVar96;
      local_74 = uVar4;
      local_70 = uVar6;
      local_6c[0] = uVar81;
      ppppppplVar108[1] = (long ******)ppppppplVar94;
      *ppppppplVar94 = (long ******)ppppppplVar108;
      ppppppplVar94[1] = pppppplVar93;
      local_768 = ppppppplVar7;
      if (pppppplVar93 != (long ******)0x0) {
        *pppppplVar93 = (long *****)ppppppplVar94;
      }
    }
  }
LAB_71019cb68c:
  puVar88 = DAT_7103a59c40;
  puVar102 = DAT_7103a59b68;
  if ((long ********)local_760 != &local_768) {
    ppppppplVar106 = local_760;
    if ((int)local_7a8 < local_7a8._4_4_) {
      ppppppplVar94 = local_760 + -1;
      iVar85 = (int)local_7a8;
      do {
        if (iVar85 < local_7a8._4_4_) {
          uVar87 = *(uint *)((long)ppppppplVar94 + 4);
          puVar96 = puVar102;
          if (-1 < (int)uVar87) {
            lVar101 = *(long *)((uint *)*puVar88 + 2);
            if (lVar101 != 0) {
              if (*(uint *)*puVar88 <= uVar87) {
                uVar87 = 0;
              }
              if (*(int *)(lVar101 + (ulong)uVar87 * 0x10 + 4) == *(int *)ppppppplVar94) {
                puVar89 = *(undefined8 **)(lVar101 + (ulong)uVar87 * 0x10 + 8);
                if (puVar89 == (undefined8 *)0x0) {
                  puVar89 = FUN_7100baff84();
                }
                iVar85 = *(int *)((long)puVar89 + 0xac);
                lVar101 = (long)iVar85 + (long)puVar89 + 0xac;
                if (iVar85 != 0 && lVar101 != 0) {
                  puVar96 = (uint *)(lVar101 + 0x38);
                }
              }
            }
          }
          ppuVar78 = local_798;
          iVar85 = (int)local_7a8;
          if ((int)local_7a8 < local_7a8._4_4_) {
            if (local_798 != (undefined8 **)0x0) {
              local_798 = (undefined8 **)*local_798;
            }
            *(uint *)ppuVar78 = *puVar96;
            if ((int)local_7a8 < local_7a8._4_4_) {
              local_7a0[(int)local_7a8] = ppuVar78;
              iVar85 = (int)local_7a8 + 1;
              local_7a8 = CONCAT44(local_7a8._4_4_,iVar85);
            }
          }
        }
        ppppppplVar106 = (long *******)ppppppplVar106[1];
        ppppppplVar94 = ppppppplVar106 + -1;
      } while (ppppppplVar94 != &pppppplStack_770);
    }
    else {
      do {
        ppppppplVar106 = (long *******)ppppppplVar106[1];
      } while (ppppppplVar106 + -1 != &pppppplStack_770);
    }
  }
  do {
    ppppppplVar106 = (long *******)*ppppppplVar109;
    ppppppplVar109 = ppppppplVar106 + 1;
  } while ((long ********)ppppppplVar106 != &local_768);
  uVar87 = *param_1;
  if (((int)local_7a8 != 0) && ((int)uVar87 < (int)param_1[1])) {
    lVar101 = (long)(int)local_7a8 << 3;
    puVar88 = local_7a0;
    do {
      if ((int)uVar87 < (int)param_1[1]) {
        puVar89 = *(undefined8 **)(param_1 + 4);
        uVar3 = *(undefined4 *)*puVar88;
        if (puVar89 != (undefined8 *)0x0) {
          *(undefined8 *)(param_1 + 4) = *puVar89;
        }
        *(undefined4 *)puVar89 = uVar3;
        uVar87 = *param_1;
        if ((int)uVar87 < (int)param_1[1]) {
          *(undefined8 **)(*(long *)(param_1 + 2) + (long)(int)uVar87 * 8) = puVar89;
          uVar87 = *param_1 + 1;
          *param_1 = uVar87;
        }
      }
      puVar88 = puVar88 + 1;
      lVar101 = lVar101 + -8;
    } while (lVar101 != 0);
  }
  plVar82 = DAT_7103a59ec8;
  plVar91 = DAT_7103a59c30;
  if ((int)uVar87 < (int)param_1[1]) {
    local_7e8 = 0;
    local_7e0 = (undefined8 *)0x0;
    local_7d8 = &local_7c8;
    local_7c8 = &local_7c0;
    local_7c0 = 0;
    if (local_7b8 != (undefined8 *)0x0) {
      local_7e8 = 0x200000000;
      local_7e0 = local_7b8;
    }
    local_768 = (long *******)&local_768;
    local_758 = 0;
    local_738[0] = local_720;
    local_720[0] = local_708;
    local_c0[0] = 0;
    local_708[0] = local_6f0;
    local_6d8[0] = local_6c0;
    uVar87 = *param_2;
    local_6a8[0] = local_690;
    local_678[0] = local_660;
    uVar84 = *param_3;
    local_648[0] = local_630;
    local_618[0] = local_600;
    local_5e8[0] = local_5d0;
    local_750 = local_738;
    local_5b8[0] = local_5a0;
    local_588[0] = local_570;
    local_558[0] = local_540;
    local_540[0] = local_528;
    local_6f0[0] = local_6d8;
    local_6c0[0] = local_6a8;
    local_690[0] = local_678;
    local_528[0] = local_510;
    local_510[0] = local_4f8;
    local_660[0] = local_648;
    local_4f8[0] = local_4e0;
    local_4e0[0] = local_4c8;
    local_630[0] = local_618;
    local_4c8[0] = local_4b0;
    local_4b0[0] = local_498;
    local_600[0] = local_5e8;
    local_498[0] = local_480;
    local_480[0] = local_468;
    local_5d0[0] = local_5b8;
    local_468[0] = local_450;
    local_450[0] = local_438;
    local_5a0[0] = local_588;
    local_438[0] = local_420;
    local_420[0] = local_408;
    local_570[0] = local_558;
    local_408[0] = local_3f0;
    local_3f0[0] = local_3d8;
    local_3d8[0] = local_3c0;
    local_3c0[0] = local_3a8;
    local_3a8[0] = local_390;
    local_390[0] = local_378;
    local_378[0] = local_360;
    local_360[0] = local_348;
    local_348[0] = local_330;
    local_330[0] = local_318;
    local_318[0] = local_300;
    local_300[0] = local_2e8;
    local_2e8[0] = local_2d0;
    local_2d0[0] = local_2b8;
    local_2b8[0] = local_2a0;
    local_2a0[0] = local_288;
    local_288[0] = local_270;
    local_270[0] = local_258;
    local_258[0] = local_240;
    local_240[0] = local_228;
    local_228[0] = local_210;
    local_210[0] = local_1f8;
    local_1f8[0] = local_1e0;
    local_1e0[0] = local_1c8;
    local_1c8[0] = local_1b0;
    local_1b0[0] = local_198;
    local_198[0] = local_180;
    local_180[0] = local_168;
    local_168[0] = local_150;
    local_150[0] = local_138;
    local_138[0] = local_120;
    local_120[0] = local_108;
    local_108[0] = local_f0;
    local_f0[0] = local_d8;
    local_d8[0] = local_c0;
    local_740 = 0x46;
    puVar102 = DAT_7103a59b30;
    if ((uVar84 < 0x46) &&
       (lVar101 = *(long *)(*(long *)(*DAT_7103a59c30 + 0x19a8d8) + (ulong)uVar84 * 8 + 0x28),
       lVar101 != 0)) {
      puVar102 = (uint *)(lVar101 + 0x400);
    }
    uVar92 = *puVar102;
    uVar100 = puVar102[1];
    ppuStack_7d0 = local_7d8;
    local_760 = local_768;
    pppppppuStack_748 = local_750;
    lVar101 = FUN_7100bd09b0(*DAT_7103a59ec8);
    uVar4 = *(uint *)(lVar101 + 0x2c);
    uVar6 = 0;
    if (uVar4 != 0) {
      uVar6 = 0xe18a984 / uVar4;
    }
    uVar99 = (ulong)(0xe18a984 - uVar6 * uVar4);
    lVar101 = *(long *)(lVar101 + 0x20);
    if (*(int *)(lVar101 + uVar99 * 0x10) != 0xe18a984) {
      do {
        uVar6 = 0;
        if ((int)uVar99 + 1 < (int)uVar4) {
          uVar6 = (int)uVar99 + 1;
        }
        uVar99 = (ulong)uVar6;
      } while (*(int *)(lVar101 + (-(ulong)(uVar6 >> 0x1f) & 0xfffffff000000000 | uVar99 << 4)) !=
               0xe18a984);
      uVar99 = (ulong)(int)uVar6;
    }
    iVar85 = *(int *)(*(long *)(lVar101 + uVar99 * 0x10 + 8) + 8);
    lVar101 = FUN_7100bd09b0(*plVar82);
    uVar4 = *(uint *)(lVar101 + 0x2c);
    uVar6 = 0;
    if (uVar4 != 0) {
      uVar6 = 0xb814392e / uVar4;
    }
    uVar6 = 0xb814392e - uVar6 * uVar4;
    uVar99 = (ulong)uVar6;
    lVar101 = *(long *)(lVar101 + 0x20);
    iVar5 = *(int *)(lVar101 + (-(ulong)(uVar6 >> 0x1f) & 0xfffffff000000000 | uVar99 << 4));
    while (iVar5 != -0x47ebc6d2) {
      uVar6 = 0;
      if ((int)uVar99 + 1 < (int)uVar4) {
        uVar6 = (int)uVar99 + 1;
      }
      uVar99 = (ulong)uVar6;
      iVar5 = *(int *)(lVar101 + (-(ulong)(uVar6 >> 0x1f) & 0xfffffff000000000 | uVar99 << 4));
    }
    iVar5 = *(int *)(*(long *)(lVar101 + (long)(int)uVar6 * 0x10 + 8) + 8);
    lVar101 = *plVar91;
    puVar102 = DAT_7103a59b30;
    if ((uVar87 < 0x46) &&
       (lVar95 = *(long *)(*(long *)(lVar101 + 0x19a8d8) + (ulong)uVar87 * 8 + 0x28), lVar95 != 0))
    {
      puVar102 = (uint *)(lVar95 + 0x400);
    }
    ppppppplVar109 = (long *******)&local_760;
    local_94 = CONCAT44(iVar5,iVar85);
    puVar96 = DAT_7103a59b30;
    if (uVar84 < 0x46) {
      lVar101 = *(long *)(lVar101 + 0x19a8d8);
      lVar95 = *(long *)(lVar101 + (ulong)uVar84 * 8 + 0x28);
      if (lVar95 != 0) {
        puVar96 = (uint *)(lVar95 + 0x400);
      }
    }
    else {
      lVar101 = *(long *)(lVar101 + 0x19a8d8);
    }
    local_a8 = (long *******)&local_768;
    lVar95 = 0x28;
    local_a0 = uVar92;
    uStack_9c = uVar100;
    local_98 = uVar84;
    local_88 = puVar102;
    puStack_80 = puVar96;
    do {
      lVar107 = *(long *)(lVar101 + lVar95);
      if (lVar107 != 0) {
        if ((*(uint *)(lVar107 + 0x404) != puVar102[1] || *(uint *)(lVar107 + 0x400) != *puVar102)
           && (*(uint *)(lVar107 + 0x404) != puVar96[1] || *(uint *)(lVar107 + 0x400) != *puVar96))
        {
          piVar2 = (int *)(lVar107 + 0x400);
          iVar86 = FUN_71019c9020(piVar2,(int *)&local_a0);
          if (iVar86 != 4) {
            uVar87 = *(uint *)(lVar107 + 0x404);
            local_70 = uVar84;
            if ((int)uVar87 < 0) {
LAB_71019cbdf0:
              puVar88 = FUN_7100baff84();
            }
            else {
              puVar97 = (uint *)*DAT_7103a59c40;
              if (*puVar97 <= uVar87) {
                uVar87 = 0;
                lVar98 = *(long *)(puVar97 + 2);
                if (lVar98 != 0) goto LAB_71019cbdc0;
                goto LAB_71019cbdf0;
              }
              lVar98 = *(long *)(puVar97 + 2);
              if (lVar98 == 0) goto LAB_71019cbdf0;
LAB_71019cbdc0:
              lVar98 = lVar98 + (ulong)uVar87 * 0x10;
              if ((*(int *)(lVar98 + 4) != *piVar2) ||
                 (puVar88 = *(undefined8 **)(lVar98 + 8), puVar88 == (undefined8 *)0x0))
              goto LAB_71019cbdf0;
            }
            iVar86 = *(int *)(puVar88 + 0xf);
            if ((iVar86 != 0) && (lVar98 = (long)iVar86 + (long)(puVar88 + 0xf), lVar98 != 0)) {
              local_6c[0] = 1;
              uVar83 = FUN_7100e38b38(lVar98,&local_70,local_6c);
              if ((uVar83 & 1) != 0) goto LAB_71019cbd40;
            }
            uVar87 = FUN_71019c9980(piVar2,(int *)&local_a0);
            if ((uVar87 & 1) != 0) {
              uVar87 = *(uint *)(lVar107 + 0x404);
              local_6c[0] = uVar84;
              if ((int)uVar87 < 0) {
LAB_71019cbe88:
                puVar88 = FUN_7100baff84();
              }
              else {
                puVar97 = (uint *)*DAT_7103a59c40;
                if (*puVar97 <= uVar87) {
                  uVar87 = 0;
                  lVar98 = *(long *)(puVar97 + 2);
                  if (lVar98 != 0) goto LAB_71019cbe58;
                  goto LAB_71019cbe88;
                }
                lVar98 = *(long *)(puVar97 + 2);
                if (lVar98 == 0) goto LAB_71019cbe88;
LAB_71019cbe58:
                lVar98 = lVar98 + (ulong)uVar87 * 0x10;
                if ((*(int *)(lVar98 + 4) != *piVar2) ||
                   (puVar88 = *(undefined8 **)(lVar98 + 8), puVar88 == (undefined8 *)0x0))
                goto LAB_71019cbe88;
              }
              iVar86 = *(int *)(puVar88 + 0xf);
              if ((iVar86 == 0) ||
                 (plVar91 = (long *)((long)iVar86 + (long)(puVar88 + 0xf)), plVar91 == (long *)0x0))
              {
                plVar91 = FUN_7100bcff3c();
              }
              iVar86 = FUN_7100e36ce4((long)plVar91,local_6c);
              if (iVar85 <= iVar86) {
                uVar87 = *(uint *)(lVar107 + 0x404);
                puVar97 = DAT_7103a59b68;
                if (-1 < (int)uVar87) {
                  lVar98 = *(long *)((uint *)*DAT_7103a59c40 + 2);
                  if (lVar98 != 0) {
                    if (*(uint *)*DAT_7103a59c40 <= uVar87) {
                      uVar87 = 0;
                    }
                    if (*(int *)(lVar98 + (ulong)uVar87 * 0x10 + 4) == *piVar2) {
                      lVar98 = *(long *)(lVar98 + (ulong)uVar87 * 0x10 + 8);
                      if (lVar98 == 0) {
                        puVar88 = FUN_7100baff84();
                        piVar90 = (int *)(puVar88 + 0xf);
                        iVar86 = *piVar90;
                      }
                      else {
                        piVar90 = (int *)(lVar98 + 0x78);
                        iVar86 = *piVar90;
                      }
                      puVar97 = DAT_7103a59b68;
                      if ((iVar86 != 0) && ((long)iVar86 + (long)piVar90 != 0)) {
                        puVar97 = (uint *)((long)iVar86 + (long)piVar90 + 0x28);
                      }
                    }
                  }
                }
                uVar87 = *puVar97;
                if (uVar87 < 0x46) {
                  uVar92 = *(uint *)(lVar107 + 0x404);
                  local_74 = uVar87;
                  if ((int)uVar92 < 0) {
LAB_71019cbfb0:
                    puVar88 = FUN_7100baff84();
                  }
                  else {
                    puVar97 = (uint *)*DAT_7103a59c40;
                    if (*puVar97 <= uVar92) {
                      uVar92 = 0;
                      lVar98 = *(long *)(puVar97 + 2);
                      if (lVar98 != 0) goto LAB_71019cbf80;
                      goto LAB_71019cbfb0;
                    }
                    lVar98 = *(long *)(puVar97 + 2);
                    if (lVar98 == 0) goto LAB_71019cbfb0;
LAB_71019cbf80:
                    lVar98 = lVar98 + (ulong)uVar92 * 0x10;
                    if ((*(int *)(lVar98 + 4) != *piVar2) ||
                       (puVar88 = *(undefined8 **)(lVar98 + 8), puVar88 == (undefined8 *)0x0))
                    goto LAB_71019cbfb0;
                  }
                  iVar86 = *(int *)(puVar88 + 0xf);
                  if ((iVar86 == 0) ||
                     (plVar91 = (long *)((long)iVar86 + (long)(puVar88 + 0xf)),
                     plVar91 == (long *)0x0)) {
                    plVar91 = FUN_7100bcff3c();
                  }
                  iVar86 = FUN_7100e36ce4((long)plVar91,&local_74);
                  if (iVar5 < iVar86) goto LAB_71019cbd40;
                }
                pppppppuVar9 = local_750;
                if ((int)local_758 < local_740) {
                  if (local_750 != (undefined8 *******)0x0) {
                    local_750 = (undefined8 *******)*local_750;
                  }
                  *pppppppuVar9 = (undefined8 ******)0xffffffffffffffff;
                  *(undefined4 *)pppppppuVar9 = *(undefined4 *)(lVar107 + 0x400);
                  uVar3 = *(undefined4 *)(lVar107 + 0x404);
                  ppppppplVar106 = pppppppuVar9 + 1;
                  *ppppppplVar106 = (long ******)0x0;
                  *(undefined4 *)((long)pppppppuVar9 + 4) = uVar3;
                  *ppppppplVar106 = (long ******)local_768;
                  pppppppuVar9[2] = &local_768;
                  if (local_768 != (long *******)0x0) {
                    local_768[1] = (long ******)ppppppplVar106;
                  }
                  local_758 = local_758 + 1;
                  local_768 = ppppppplVar106;
                }
              }
            }
          }
        }
      }
LAB_71019cbd40:
      lVar95 = lVar95 + 8;
    } while (lVar95 != 600);
    uVar87 = thunk_EXT_FUN_02e95df0();
    uVar87 = (uVar87 ^ uVar87 >> 0x1e) * 0x6c078965 + 1;
    uVar84 = (uVar87 ^ uVar87 >> 0x1e) * 0x6c078965 + 2;
    local_a8 = (long *******)CONCAT44(uVar84,uVar87);
    local_a0 = (uVar84 ^ uVar84 >> 0x1e) * 0x6c078965 + 3;
    uStack_9c = (local_a0 ^ local_a0 >> 0x1e) * 0x6c078965 + 4;
    FUN_71024d4e60((long *)&local_768,(uint *)&local_a8);
    puVar88 = DAT_7103a59c40;
    puVar102 = DAT_7103a59b68;
    if ((long ********)local_760 != &local_768) {
      ppppppplVar94 = local_760 + -1;
      ppppppplVar106 = local_760;
      do {
        uVar87 = *(uint *)((long)ppppppplVar94 + 4);
        puVar96 = puVar102;
        if (-1 < (int)uVar87) {
          lVar101 = *(long *)((uint *)*puVar88 + 2);
          if (lVar101 != 0) {
            if (*(uint *)*puVar88 <= uVar87) {
              uVar87 = 0;
            }
            if (*(int *)(lVar101 + (ulong)uVar87 * 0x10 + 4) == *(int *)ppppppplVar94) {
              puVar89 = *(undefined8 **)(lVar101 + (ulong)uVar87 * 0x10 + 8);
              if (puVar89 == (undefined8 *)0x0) {
                puVar89 = FUN_7100baff84();
              }
              iVar85 = *(int *)((long)puVar89 + 0xac);
              lVar101 = (long)iVar85 + (long)puVar89 + 0xac;
              if (iVar85 != 0 && lVar101 != 0) {
                puVar96 = (uint *)(lVar101 + 0x38);
              }
            }
          }
        }
        ppuVar78 = local_7d8;
        iVar85 = local_7e8._4_4_;
        uVar87 = (uint)local_7e8;
        if ((int)(uint)local_7e8 < (int)local_7e8._4_4_) {
          if (local_7d8 != (undefined8 **)0x0) {
            local_7d8 = (undefined8 **)*local_7d8;
          }
          *(uint *)ppuVar78 = *puVar96;
          if ((int)(uint)local_7e8 < (int)local_7e8._4_4_) {
            local_7e0[(int)(uint)local_7e8] = ppuVar78;
            uVar87 = (uint)local_7e8 + 1;
            local_7e8 = CONCAT44(local_7e8._4_4_,uVar87);
          }
        }
        if (iVar85 <= (int)uVar87) break;
        ppppppplVar106 = (long *******)ppppppplVar106[1];
        ppppppplVar94 = ppppppplVar106 + -1;
      } while (ppppppplVar94 != &pppppplStack_770);
    }
    do {
      puVar88 = DAT_7103a59c90;
      ppppppplVar106 = (long *******)*ppppppplVar109;
      ppppppplVar109 = ppppppplVar106 + 1;
    } while ((long ********)ppppppplVar106 != &local_768);
    if (((uint)local_7e8 != 0) && ((int)*param_1 < (int)param_1[1])) {
      lVar101 = (long)(int)(uint)local_7e8 << 3;
      puVar89 = local_7e0;
      do {
        if ((int)*param_1 < (int)param_1[1]) {
          puVar102 = (uint *)*puVar88;
          uVar3 = *(undefined4 *)*puVar89;
          uVar87 = *puVar102 ^ *puVar102 << 0xb;
          uVar84 = puVar102[3];
          *puVar102 = puVar102[1];
          puVar102[1] = puVar102[2];
          uVar87 = uVar87 >> 8 ^ uVar84 >> 0x13 ^ uVar87 ^ uVar84;
          puVar102[2] = uVar84;
          puVar102[3] = uVar87;
          if (((int)((ulong)uVar87 * 100 >> 0x20) < param_4) && ((int)*param_1 < (int)param_1[1])) {
            puVar103 = *(undefined8 **)(param_1 + 4);
            if (puVar103 != (undefined8 *)0x0) {
              *(undefined8 *)(param_1 + 4) = *puVar103;
            }
            *(undefined4 *)puVar103 = uVar3;
            if ((int)*param_1 < (int)param_1[1]) {
              *(undefined8 **)(*(long *)(param_1 + 2) + (long)(int)*param_1 * 8) = puVar103;
              *param_1 = *param_1 + 1;
            }
          }
        }
        puVar89 = puVar89 + 1;
        lVar101 = lVar101 + -8;
      } while (lVar101 != 0);
    }
  }
  uVar87 = thunk_EXT_FUN_02e95df0();
  if (1 < (int)*param_1) {
    uVar87 = (uVar87 ^ uVar87 >> 0x1e) * 0x6c078965 + 1;
    uVar84 = (uVar87 ^ uVar87 >> 0x1e) * 0x6c078965 + 2;
    uVar92 = (uVar84 ^ uVar84 >> 0x1e) * 0x6c078965 + 3;
    uVar99 = (ulong)*param_1;
    uVar100 = (uVar92 ^ uVar92 >> 0x1e) * 0x6c078965 + 4;
    do {
      uVar87 = uVar87 ^ uVar87 << 0xb;
      lVar95 = *(long *)(param_1 + 2);
      uVar4 = uVar87 >> 8 ^ uVar100 >> 0x13 ^ uVar87 ^ uVar100;
      lVar101 = (uVar99 - 1 & 0xffffffff) * 8;
      uVar104 = *(undefined8 *)(lVar95 + lVar101);
      uVar105 = uVar99 * uVar4 >> 0x1d & 0x7fffffff8;
      *(undefined8 *)(lVar95 + lVar101) = *(undefined8 *)(lVar95 + uVar105);
      *(undefined8 *)(*(long *)(param_1 + 2) + uVar105) = uVar104;
      bVar1 = 2 < uVar99;
      uVar99 = uVar99 - 1;
      uVar87 = uVar84;
      uVar84 = uVar92;
      uVar92 = uVar100;
      uVar100 = uVar4;
    } while (bVar1);
  }
  return;
}



void FUN_71019cc320(long *param_1,uint param_2,int param_3,ulong param_4,undefined8 param_5,
                   undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined8 param_9)

{
  undefined4 uVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  long lVar5;
  long *plVar6;
  uint *puVar7;
  char *pcVar8;
  uint uVar9;
  int *piVar10;
  char *local_98;
  byte *local_90;
  int local_88;
  byte local_84 [63];
  undefined1 local_45;
  char *local_28;
  
  puVar7 = (uint *)*DAT_7103a71180;
  if ((puVar7 == (uint *)0x0) || ((char)puVar7[0x10] == '\0')) {
    iVar4 = FUN_71024fcfa0();
    iVar2 = FUN_71024fd1e0();
    uVar3 = (iVar4 - iVar2) + iVar2 * 8;
    pcVar8 = "";
    if (uVar3 < 0x5b) {
      uVar9 = (uint)(char)(&DAT_71032c57c7)[uVar3];
      if ((char)(&DAT_71032c57c7)[uVar3] < '\0') {
        if (iVar4 - 1U < 6) {
          iVar2 = *(int *)(&DAT_71032b46c0 + (long)(int)(iVar4 - 1U) * 4);
        }
        else {
          iVar2 = 0;
        }
        if ((uint)(iVar2 + iVar4) < 0x5b) {
          pcVar8 = &DAT_71032c57c7 + (uint)(iVar2 + iVar4);
        }
        uVar9 = (int)*pcVar8 & ((int)*pcVar8 >> 0x1f ^ 0xffffffffU);
        goto joined_r0x0071019cc3a8;
      }
    }
    else {
      uVar9 = 0;
    }
    uVar9 = uVar9 & 0xff;
  }
  else {
    uVar9 = *puVar7;
  }
joined_r0x0071019cc3a8:
  uVar3 = 0;
  if ((((param_4 & 1) != 0) && (uVar3 = 0, (param_2 & 0xfffffffe) != 0)) && (uVar9 < 0xc)) {
    uVar3 = 0xbeeU >> (ulong)(uVar9 & 0x1f) & 1;
  }
  local_28 = "";
  if (param_2 + 1 < 0x10) {
    local_28 = *(char **)(DAT_7103a60938 + (ulong)(param_2 + 1) * 8 + 0xa8);
  }
  local_90 = local_84;
  local_45 = 0;
  local_84[0] = 0;
  pcVar8 = "_00";
  if (((uint)(uVar9 < 0xc) & 0xbccU >> (ulong)(uVar9 & 0x1f) & (uint)(param_3 == 1)) == 0) {
    pcVar8 = "";
  }
  local_98 = "_FormsOfAddress";
  if (uVar3 == 0) {
    local_98 = pcVar8;
  }
  local_88 = 0x40;
  FUN_7100e3c8a0((long *)&local_90,0x71030ce987,(long *)&local_28,(long *)&local_98,param_6,param_7,
                 param_8,param_9);
  lVar5 = *DAT_7103a5c248;
  *(undefined1 *)(DAT_71040e3d18 + DAT_71040e3d10 + -1) = 0;
  plVar6 = (long *)FUN_710293d5f0(lVar5,&DAT_71040e3d10);
  if (plVar6 != (long *)0x0) {
    local_90[(long)local_88 + -1] = 0;
    uVar3 = FUN_7102557b90(*plVar6,local_90);
    if (-1 < (int)uVar3) {
      if (uVar3 < *(uint *)(plVar6 + 1)) {
        iVar4 = FUN_7102557ca0(*plVar6,uVar3);
        iVar4 = iVar4 >> 1;
        if (*(uint *)(plVar6 + 1) <= uVar3) goto LAB_71019cc594;
LAB_71019cc558:
        iVar2 = *(int *)(*plVar6 + 0x24);
        if ((iVar2 == -1) ||
           (piVar10 = *(int **)(*(long *)(*plVar6 + 0x18) + (long)iVar2 * 0x18),
           *piVar10 <= (int)uVar3)) goto LAB_71019cc594;
        lVar5 = (long)piVar10 + (ulong)(uint)piVar10[uVar3 + 1];
      }
      else {
        iVar4 = 0;
        if (uVar3 < *(uint *)(plVar6 + 1)) goto LAB_71019cc558;
LAB_71019cc594:
        lVar5 = 0;
      }
      *(int *)(param_1 + 1) = iVar4;
      uVar1 = *(undefined4 *)((long)plVar6 + 0xc);
      *param_1 = lVar5;
      lVar5 = CONCAT44(uVar1,uVar3);
      goto LAB_71019cc5ac;
    }
  }
  lVar5 = -1;
  *param_1 = 0;
  *(undefined4 *)(param_1 + 1) = 0;
LAB_71019cc5ac:
  param_1[2] = lVar5;
  return;
}



void FUN_71019cc5d0(long *param_1,ulong param_2,int param_3,uint param_4,undefined8 param_5,
                   undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined8 param_9)

{
  undefined4 uVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  long *plVar5;
  ulong uVar6;
  long lVar7;
  int *piVar8;
  long alStack_128 [6];
  long local_f8;
  byte *local_f0;
  int local_e8;
  byte local_e4 [63];
  undefined1 local_a5;
  undefined *local_a0;
  long *plStack_98;
  undefined8 local_90;
  undefined1 local_88;
  long local_80;
  byte **ppbStack_78;
  undefined4 local_70;
  byte *local_68;
  undefined4 local_60;
  int iStack_54;
  undefined1 auStack_50 [32];
  
  uVar6 = (ulong)param_4;
  if ((uint)param_2 < 0xf) {
    lVar7 = *(long *)(&DAT_71032b4648 +
                     (-(param_2 >> 0x1f & 1) & 0xfffffff800000000 | (param_2 & 0xffffffff) << 3));
  }
  else {
    lVar7 = 0;
  }
  local_f8 = (&DAT_710398b9c8)[lVar7];
  FUN_71019cc7e0(alStack_128,(uint)param_2,param_3,param_4);
  local_a5 = 0;
  local_e8 = 0x40;
  local_f0 = local_e4;
  local_60 = 0x40;
  plStack_98 = &local_80;
  local_a0 = &DAT_71030ce987;
  ppbStack_78 = &local_68;
  local_88 = 0;
  local_90 = 0x400000000;
  local_80 = DAT_7103a71198 + 0x10;
  local_70 = 0;
  local_e4[0] = 0;
  local_68 = local_f0;
  FUN_71019d0c60((long *)&local_a0,&local_f8,alStack_128,uVar6,param_6,param_7,param_8,param_9);
  if (local_a0 != (undefined *)0x0) {
    local_88 = 0;
    while( true ) {
      if (local_90._4_4_ <= (int)local_90) break;
      FUN_71024fd620((long *)&local_a0,auStack_50,&iStack_54);
    }
  }
  lVar7 = *DAT_7103a5c248;
  *(undefined1 *)(DAT_71040e3d18 + DAT_71040e3d10 + -1) = 0;
  plVar5 = (long *)FUN_710293d5f0(lVar7,&DAT_71040e3d10);
  if (plVar5 != (long *)0x0) {
    local_f0[(long)local_e8 + -1] = 0;
    uVar3 = FUN_7102557b90(*plVar5,local_f0);
    if (-1 < (int)uVar3) {
      if (uVar3 < *(uint *)(plVar5 + 1)) {
        iVar4 = FUN_7102557ca0(*plVar5,uVar3);
        iVar4 = iVar4 >> 1;
        if (*(uint *)(plVar5 + 1) <= uVar3) goto LAB_71019cc7b0;
LAB_71019cc774:
        iVar2 = *(int *)(*plVar5 + 0x24);
        if ((iVar2 == -1) ||
           (piVar8 = *(int **)(*(long *)(*plVar5 + 0x18) + (long)iVar2 * 0x18),
           *piVar8 <= (int)uVar3)) goto LAB_71019cc7b0;
        lVar7 = (long)piVar8 + (ulong)(uint)piVar8[uVar3 + 1];
      }
      else {
        iVar4 = 0;
        if (uVar3 < *(uint *)(plVar5 + 1)) goto LAB_71019cc774;
LAB_71019cc7b0:
        lVar7 = 0;
      }
      *(int *)(param_1 + 1) = iVar4;
      uVar1 = *(undefined4 *)((long)plVar5 + 0xc);
      *param_1 = lVar7;
      lVar7 = CONCAT44(uVar1,uVar3);
      goto LAB_71019cc7c8;
    }
  }
  lVar7 = -1;
  *param_1 = 0;
  *(undefined4 *)(param_1 + 1) = 0;
LAB_71019cc7c8:
  param_1[2] = lVar7;
  return;
}



void FUN_71019cc7e0(long *param_1,uint param_2,int param_3,int param_4)

{
  uint uVar1;
  long lVar2;
  int iVar3;
  int iVar4;
  char *pcVar5;
  char *pcVar6;
  long lVar7;
  uint uVar8;
  int iVar9;
  
  iVar9 = param_4;
  if ((param_2 < 0xd) && ((1 << (ulong)(param_2 & 0x1f) & 0x1500U) != 0)) {
    iVar9 = param_3;
    param_3 = param_4;
  }
  if ((DAT_7105a064a0 == (uint *)0x0) || ((char)DAT_7105a064a0[0x10] == '\0')) {
    iVar3 = FUN_71024fcfa0();
    iVar4 = FUN_71024fd1e0();
    uVar1 = (iVar3 - iVar4) + iVar4 * 8;
    pcVar6 = "";
    if (uVar1 < 0x5b) {
      uVar8 = (uint)(char)(&DAT_71032c57c7)[uVar1];
      if ((char)(&DAT_71032c57c7)[uVar1] < '\0') {
        if (iVar3 - 1U < 6) {
          iVar4 = *(int *)(&DAT_71032b46c0 + (long)(int)(iVar3 - 1U) * 4);
        }
        else {
          iVar4 = 0;
        }
        if ((uint)(iVar4 + iVar3) < 0x5b) {
          pcVar6 = &DAT_71032c57c7 + (uint)(iVar4 + iVar3);
        }
        uVar8 = (int)*pcVar6 & ((int)*pcVar6 >> 0x1f ^ 0xffffffffU);
        goto LAB_71019cc8d4;
      }
    }
    else {
      uVar8 = 0;
    }
    uVar8 = uVar8 & 0xff;
  }
  else {
    uVar8 = *DAT_7105a064a0;
  }
LAB_71019cc8d4:
  if (uVar8 < 0xc && (1 << (ulong)(uVar8 & 0x1f) & 0xbccU) != 0) {
    if (param_3 == 0) {
      if (iVar9 == 0) goto LAB_71019cc93c;
    }
    else if ((param_3 == 1) && (iVar9 == 1)) {
      lVar7 = 1;
      goto LAB_71019cc940;
    }
    lVar7 = 2;
    if ((param_2 < 0xe && (0xffU >> (ulong)(param_2 & 0x1f) & 1) == 0) &&
        (param_3 != 0 || iVar9 != 1)) {
      lVar7 = 3;
    }
  }
  else {
LAB_71019cc93c:
    lVar7 = 0;
  }
LAB_71019cc940:
  pcVar6 = (char *)((long)param_1 + 0xc);
  *(undefined1 *)((long)(int)(&DAT_71040e3d68)[lVar7 * 0xc] + (&DAT_71040e3d60)[lVar7 * 6] + -1) = 0
  ;
  *param_1 = (long)pcVar6;
  *(undefined1 *)((long)param_1 + 0x2b) = 0;
  pcVar5 = (char *)(&DAT_71040e3d60)[lVar7 * 6];
  *(undefined4 *)(param_1 + 1) = 0x20;
  if (pcVar6 != pcVar5) {
    if ((pcVar5 == (char *)0x0) || (*pcVar5 == '\0')) {
LAB_71019cc9bc:
      lVar7 = 0;
    }
    else {
      lVar7 = 0;
      do {
        if (lVar7 == 0x400000) goto LAB_71019cc9bc;
        if (pcVar5[lVar7 + 1] == '\0') {
          lVar7 = lVar7 + 1;
          if ((int)lVar7 < 0x20) goto LAB_71019cc9c0;
          goto LAB_71019cc9f4;
        }
        lVar2 = lVar7 + 2;
        lVar7 = lVar7 + 2;
      } while (pcVar5[lVar2] != '\0');
      if (0x1f < (int)lVar7) {
LAB_71019cc9f4:
        lVar7 = 0x1f;
      }
    }
LAB_71019cc9c0:
    thunk_EXT_FUN_02e95df0(pcVar6,pcVar5,(long)(int)lVar7);
    pcVar6[(int)lVar7] = '\0';
  }
  return;
}



void FUN_71019cca00(long *param_1,uint param_2,int param_3,uint param_4,byte **param_5,ulong param_6
                   ,ushort *param_7,ulong param_8,undefined8 param_9)

{
  byte *pbVar1;
  uint uVar2;
  undefined4 uVar3;
  long *plVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  int iVar8;
  long lVar9;
  long *plVar10;
  byte **ppbVar11;
  ulong uVar12;
  int *piVar13;
  uint *puVar14;
  byte *pbVar15;
  uint uVar16;
  byte *local_1c30;
  int local_1c28;
  byte local_1c24 [63];
  undefined1 local_1be5;
  undefined2 local_1be4;
  undefined8 local_1be0;
  undefined4 local_1bd8;
  undefined1 local_1bd4;
  undefined8 local_1bd0;
  undefined8 uStack_1bc8;
  undefined8 local_1bc0;
  undefined1 local_1bb8;
  undefined2 local_1bb3;
  undefined2 *local_1bb0;
  undefined4 local_1ba8;
  undefined2 local_1ba4 [255];
  undefined2 local_19a6;
  undefined2 *local_19a0;
  undefined4 local_1998;
  undefined2 local_1994 [255];
  undefined2 local_1796;
  undefined8 local_1780;
  undefined4 local_1778;
  undefined1 local_1774;
  undefined4 local_1770;
  undefined2 *local_1768;
  undefined4 local_1760;
  undefined2 local_175c [2047];
  undefined2 local_75e;
  char *local_758;
  long *local_750;
  undefined8 local_748;
  undefined1 local_740;
  long local_738;
  byte **local_730;
  undefined4 local_728;
  int local_158;
  undefined8 local_d8;
  undefined8 local_d0;
  char *local_a8;
  byte *local_a0;
  undefined4 local_98;
  int iStack_8c;
  uint local_88 [10];
  
  iVar8 = (int)param_6;
  ppbVar11 = param_5;
  if (param_2 - 0xc < 2) {
    puVar14 = (uint *)*DAT_7103a71180;
    if ((puVar14 == (uint *)0x0) || ((char)puVar14[0x10] == '\0')) {
      iVar7 = FUN_71024fcfa0();
      iVar5 = FUN_71024fd1e0();
      uVar6 = (iVar7 - iVar5) + iVar5 * 8;
      pbVar15 = &DAT_71032c57c7;
      pbVar1 = &DAT_71032c57c7 + uVar6;
      if (0x5a < uVar6) {
        pbVar1 = pbVar15;
      }
      if ((char)*pbVar1 < '\0') {
        if (iVar7 - 1U < 6) {
          iVar5 = *(int *)(&DAT_71032b46c0 + (long)(int)(iVar7 - 1U) * 4);
        }
        else {
          iVar5 = 0;
        }
        if ((uint)(iVar5 + iVar7) < 0x5b) {
          pbVar15 = &DAT_71032c57c7 + (uint)(iVar5 + iVar7);
        }
        uVar6 = (int)(char)*pbVar15 & ((int)(char)*pbVar15 >> 0x1f ^ 0xffffffffU);
      }
      else {
        uVar6 = (uint)*pbVar1;
      }
    }
    else {
      uVar6 = *puVar14;
    }
    if ((uVar6 - 1 & 0xfffffff9) != 0) goto LAB_71019ccfc4;
    uVar6 = 10;
  }
  else {
    if ((param_2 != 6) && (param_2 != 4)) {
      if ((*DAT_7103a71180 == 0) || (*(char *)(*DAT_7103a71180 + 0x40) == '\0')) {
        FUN_71024fcfa0();
        FUN_71024fd1e0();
        ppbVar11 = param_5;
      }
      goto LAB_71019ccfc4;
    }
    uVar6 = param_2;
    if ((*DAT_7103a71180 == 0) || (*(char *)(*DAT_7103a71180 + 0x40) == '\0')) {
      FUN_71024fcfa0();
      FUN_71024fd1e0();
    }
  }
  plVar4 = DAT_7103a5c248;
  lVar9 = *DAT_7103a5c248;
  *(undefined1 *)(DAT_71040e3d18 + DAT_71040e3d10 + -1) = 0;
  plVar10 = (long *)FUN_710293d5f0(lVar9,&DAT_71040e3d10);
  if (plVar10 == (long *)0x0) goto LAB_71019ccfc4;
  if (uVar6 == 4) {
LAB_71019ccb88:
    local_a8 = (char *)(&DAT_710398b9c8)[uVar6 + 1];
    uVar12 = (ulong)param_4;
    FUN_71019cc7e0(&local_d8,param_2,param_3,param_4);
    local_1be5 = 0;
    local_1c28 = 0x40;
    local_1c30 = local_1c24;
    local_98 = 0x40;
    local_750 = &local_738;
    local_758 = "%s_Detail%s";
    local_740 = 0;
    local_738 = DAT_7103a71198 + 0x10;
    local_748 = 0xb00000000;
    local_728 = 0;
    local_1c24[0] = 0;
    local_730 = &local_a0;
    local_a0 = local_1c30;
    FUN_71019d0c60((long *)&local_758,(long *)&local_a8,&local_d8,uVar12,param_6,param_7,param_8,
                   param_9);
    if (local_758 != (char *)0x0) {
      local_740 = 0;
      while( true ) {
        if (local_748._4_4_ <= (int)local_748) break;
        FUN_71024fd620((long *)&local_758,(undefined1 *)local_88,&iStack_8c);
      }
    }
    local_1c30[(long)local_1c28 + -1] = 0;
    uVar6 = FUN_7102557b90(*plVar10,local_1c30);
    if ((int)uVar6 < 0) {
      uVar16 = 0;
LAB_71019cce2c:
      param_7 = (ushort *)0x0;
    }
    else {
      if (*(uint *)(plVar10 + 1) <= uVar6) {
        uVar16 = 0;
        if (uVar6 < *(uint *)(plVar10 + 1)) goto LAB_71019ccdf0;
        goto LAB_71019cce2c;
      }
      iVar7 = FUN_7102557ca0(*plVar10,uVar6);
      uVar16 = iVar7 >> 1;
      if (*(uint *)(plVar10 + 1) <= uVar6) goto LAB_71019cce2c;
LAB_71019ccdf0:
      iVar7 = *(int *)(*plVar10 + 0x24);
      if ((iVar7 == -1) ||
         (piVar13 = *(int **)(*(long *)(*plVar10 + 0x18) + (long)iVar7 * 0x18),
         *piVar13 <= (int)uVar6)) goto LAB_71019cce2c;
      param_7 = (ushort *)((long)piVar13 + (ulong)(uint)piVar13[uVar6 + 1]);
    }
    if (-1 < iVar8) {
      puVar14 = (uint *)*DAT_7103a59c90;
      uVar2 = puVar14[3];
      uVar6 = *puVar14 ^ *puVar14 << 0xb;
      *puVar14 = puVar14[1];
      puVar14[1] = puVar14[2];
      uVar6 = uVar6 >> 8 ^ uVar2 >> 0x13 ^ uVar6 ^ uVar2;
      puVar14[2] = uVar2;
      puVar14[3] = uVar6;
      FUN_710248ee54(&local_758,uVar6);
      local_88[0] = 0;
      local_a0 = (byte *)((ulong)local_a0 & 0xffffffff00000000);
      if (0x270e < iVar8) {
        iVar8 = 9999;
      }
      local_158 = iVar8;
      FUN_710293f8d0(&local_1c30,*plVar4,*DAT_7103a66378);
      local_1bb0 = local_1ba4;
      local_1be4 = 0;
      local_19a0 = local_1994;
      local_1994[0] = 0;
      local_1768 = local_175c;
      local_175c[0] = 0;
      iVar8 = *(int *)(param_5 + 1);
      param_9 = 0xffffffff;
      local_1c30 = (byte *)(DAT_7103a68c30 + 0x10);
      local_1be0 = 0;
      local_1ba8 = 0x100;
      ppbVar11 = &local_a0;
      local_1998 = 0x100;
      param_8 = (ulong)uVar16;
      local_1774 = 0xff;
      local_1760 = 0x800;
      pbVar15 = *param_5;
      local_1bd8 = 0;
      local_1bd4 = 0;
      local_1bb3 = 0;
      local_1bc0 = 0;
      local_1bb8 = 0;
      local_19a6 = 0;
      local_1ba4[0] = 0;
      local_1796 = 0;
      local_1780 = 0;
      local_1778 = 0;
      local_1770 = 0;
      local_75e = 0;
      local_1bd0 = 0;
      uStack_1bc8 = 0;
      (pbVar15 + (long)iVar8 * 2 + -2)[0] = 0;
      (pbVar15 + (long)iVar8 * 2 + -2)[1] = 0;
      param_6 = (ulong)*(uint *)(param_5 + 1);
      local_d8._2_1_ = 0;
      local_d8._0_2_ = 0;
      local_d0 = 0;
      FUN_7102497450((long *)&local_1c30,(undefined2 *)*param_5,local_88,(uint *)ppbVar11,param_6,
                     param_7,param_8,0xffffffff,1,(char *)&local_d8,(uint *)&local_758);
      ret_7100604C64();
      if (local_88[0] == 0) {
LAB_71019ccfc4:
        FUN_71019cc5d0(param_1,(ulong)param_2,param_3,param_4,ppbVar11,param_6,param_7,param_8,
                       param_9);
        return;
      }
      pbVar15 = *param_5;
      *(uint *)(param_1 + 1) = local_88[0];
      lVar9 = -1;
      iVar8 = *(int *)(param_5 + 1);
      (pbVar15 + (long)iVar8 * 2 + -2)[0] = 0;
      (pbVar15 + (long)iVar8 * 2 + -2)[1] = 0;
      *param_1 = (long)*param_5;
      goto LAB_71019cd06c;
    }
  }
  else {
    if (uVar6 != 10) {
      if (uVar6 != 6) goto LAB_71019ccfc4;
      goto LAB_71019ccb88;
    }
    local_a8 = s_Pair_GrandParentAndGrandChild_710398b997;
    uVar12 = (ulong)param_4;
    FUN_71019cc7e0(&local_d8,param_2,param_3,param_4);
    local_1be5 = 0;
    local_1c28 = 0x40;
    local_1c30 = local_1c24;
    local_98 = 0x40;
    local_750 = &local_738;
    local_758 = "%s_Detail%s";
    local_740 = 0;
    local_738 = DAT_7103a71198 + 0x10;
    local_748 = 0xb00000000;
    local_728 = 0;
    local_1c24[0] = 0;
    local_730 = &local_a0;
    local_a0 = local_1c30;
    FUN_71019d0c60((long *)&local_758,(long *)&local_a8,&local_d8,uVar12,param_6,param_7,param_8,
                   param_9);
    if (local_758 != (char *)0x0) {
      local_740 = 0;
      while( true ) {
        if (local_748._4_4_ <= (int)local_748) break;
        FUN_71024fd620((long *)&local_758,(undefined1 *)local_88,&iStack_8c);
      }
    }
    local_1c30[(long)local_1c28 + -1] = 0;
    uVar6 = FUN_7102557b90(*plVar10,local_1c30);
    if (-1 < (int)uVar6) {
      if (uVar6 < *(uint *)(plVar10 + 1)) {
        iVar8 = FUN_7102557ca0(*plVar10,uVar6);
        iVar8 = iVar8 >> 1;
        if (*(uint *)(plVar10 + 1) <= uVar6) goto LAB_71019cd054;
LAB_71019cd018:
        iVar7 = *(int *)(*plVar10 + 0x24);
        if ((iVar7 == -1) ||
           (piVar13 = *(int **)(*(long *)(*plVar10 + 0x18) + (long)iVar7 * 0x18),
           *piVar13 <= (int)uVar6)) goto LAB_71019cd054;
        lVar9 = (long)piVar13 + (ulong)(uint)piVar13[uVar6 + 1];
      }
      else {
        iVar8 = 0;
        if (uVar6 < *(uint *)(plVar10 + 1)) goto LAB_71019cd018;
LAB_71019cd054:
        lVar9 = 0;
      }
      *(int *)(param_1 + 1) = iVar8;
      uVar3 = *(undefined4 *)((long)plVar10 + 0xc);
      *param_1 = lVar9;
      lVar9 = CONCAT44(uVar3,uVar6);
      goto LAB_71019cd06c;
    }
  }
  *param_1 = 0;
  lVar9 = -1;
  *(undefined4 *)(param_1 + 1) = 0;
LAB_71019cd06c:
  param_1[2] = lVar9;
  return;
}



void FUN_71019cd080(long *param_1,uint param_2,int param_3,uint param_4,undefined8 param_5,
                   undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined8 param_9)

{
  byte *pbVar1;
  char *pcVar2;
  undefined4 uVar3;
  byte bVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  long lVar8;
  long *plVar9;
  undefined8 uVar10;
  ulong uVar11;
  uint *puVar12;
  byte *pbVar13;
  int *piVar14;
  long alStack_140 [6];
  char *local_110;
  byte *local_108;
  int local_100;
  byte local_fc [63];
  undefined1 local_bd;
  char *local_b8;
  long *plStack_b0;
  undefined8 local_a8;
  undefined1 local_a0;
  long local_98;
  byte **ppbStack_90;
  undefined4 local_88;
  byte *local_80;
  undefined4 local_78;
  undefined1 auStack_70 [32];
  int iStack_34;
  
  if (param_2 - 10 < 2) {
    piVar14 = (int *)*DAT_7103a71180;
    if ((piVar14 == (int *)0x0) || ((char)piVar14[0x10] == '\0')) {
      iVar7 = FUN_71024fcfa0();
      iVar5 = FUN_71024fd1e0();
      uVar6 = (iVar7 - iVar5) + iVar5 * 8;
      pbVar13 = &DAT_71032c57c7;
      pbVar1 = &DAT_71032c57c7 + uVar6;
      if (0x5a < uVar6) {
        pbVar1 = pbVar13;
      }
      bVar4 = *pbVar1;
      if ((char)bVar4 < '\0') {
        if (iVar7 - 1U < 6) {
          iVar5 = *(int *)(&DAT_71032b46c0 + (long)(int)(iVar7 - 1U) * 4);
        }
        else {
          iVar5 = 0;
        }
        if ((uint)(iVar5 + iVar7) < 0x5b) {
          pbVar13 = &DAT_71032c57c7 + (uint)(iVar5 + iVar7);
        }
        bVar4 = *pbVar13 & ((char)*pbVar13 >> 0x1f ^ 0xffU);
      }
      if (bVar4 != 0) goto LAB_71019cd2bc;
    }
    else if (*piVar14 != 0) goto LAB_71019cd2bc;
    iVar7 = 9;
  }
  else {
    if (1 < param_2 - 0xc) {
      if ((*DAT_7103a71180 == 0) || (*(char *)(*DAT_7103a71180 + 0x40) == '\0')) {
        FUN_71024fcfa0();
        FUN_71024fd1e0();
      }
      goto LAB_71019cd2bc;
    }
    puVar12 = (uint *)*DAT_7103a71180;
    if ((puVar12 == (uint *)0x0) || ((char)puVar12[0x10] == '\0')) {
      iVar7 = FUN_71024fcfa0();
      iVar5 = FUN_71024fd1e0();
      uVar6 = (iVar7 - iVar5) + iVar5 * 8;
      pbVar13 = &DAT_71032c57c7;
      pbVar1 = &DAT_71032c57c7 + uVar6;
      if (0x5a < uVar6) {
        pbVar1 = pbVar13;
      }
      if ((char)*pbVar1 < '\0') {
        if (iVar7 - 1U < 6) {
          iVar5 = *(int *)(&DAT_71032b46c0 + (long)(int)(iVar7 - 1U) * 4);
        }
        else {
          iVar5 = 0;
        }
        if ((uint)(iVar5 + iVar7) < 0x5b) {
          pbVar13 = &DAT_71032c57c7 + (uint)(iVar5 + iVar7);
        }
        uVar6 = (int)(char)*pbVar13 & ((int)(char)*pbVar13 >> 0x1f ^ 0xffffffffU);
      }
      else {
        uVar6 = (uint)*pbVar1;
      }
    }
    else {
      uVar6 = *puVar12;
    }
    if ((7 < uVar6) || ((0xabU >> (ulong)(uVar6 & 0x1f) & 1) == 0)) goto LAB_71019cd2bc;
    iVar7 = 10;
  }
  uVar10 = 1;
  lVar8 = *DAT_7103a5c248;
  *(undefined1 *)(DAT_71040e3d18 + DAT_71040e3d10 + -1) = 0;
  plVar9 = (long *)FUN_710293d5f0(lVar8,&DAT_71040e3d10);
  if (plVar9 == (long *)0x0) {
LAB_71019cd2bc:
    FUN_71019cc5d0(param_1,(ulong)param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
    return;
  }
  if (iVar7 == 10) {
    local_110 = s_Pair_GrandParentAndGrandChild_710398b997;
    uVar11 = (ulong)param_4;
    FUN_71019cc7e0(alStack_140,param_2,param_3,param_4);
    local_bd = 0;
    local_100 = 0x40;
    local_108 = local_fc;
    local_78 = 0x40;
    plStack_b0 = &local_98;
    local_b8 = "%s_Spoken%s";
    ppbStack_90 = &local_80;
    local_a0 = 0;
    local_a8 = 0xb00000000;
    local_98 = DAT_7103a71198 + 0x10;
    local_88 = 0;
    local_fc[0] = 0;
    local_80 = local_108;
    FUN_71019d0c60((long *)&local_b8,(long *)&local_110,alStack_140,uVar11,param_6,param_7,param_8,
                   param_9);
    if (local_b8 != (char *)0x0) {
      local_a0 = 0;
      while( true ) {
        if (local_a8._4_4_ <= (int)local_a8) break;
        FUN_71024fd620((long *)&local_b8,auStack_70,&iStack_34);
      }
    }
  }
  else {
    if (iVar7 != 9) goto LAB_71019cd2bc;
    local_bd = 0;
    local_108 = local_fc;
    local_100 = 0x40;
    pcVar2 = "Pair_Sibling_Spoken";
    if (param_4 == 1 && param_3 == 1) {
      pcVar2 = "Pair_Sister_Spoken";
    }
    local_fc[0] = 0;
    FUN_7100bc08f0((long *)&local_108,pcVar2,uVar10,param_5,param_6,param_7,param_8,param_9);
  }
  local_108[(long)local_100 + -1] = 0;
  uVar6 = FUN_7102557b90(*plVar9,local_108);
  if ((int)uVar6 < 0) {
    lVar8 = -1;
    *param_1 = 0;
    *(undefined4 *)(param_1 + 1) = 0;
    goto LAB_71019cd464;
  }
  if (uVar6 < *(uint *)(plVar9 + 1)) {
    iVar7 = FUN_7102557ca0(*plVar9,uVar6);
    iVar7 = iVar7 >> 1;
    if (*(uint *)(plVar9 + 1) <= uVar6) goto LAB_71019cd44c;
LAB_71019cd410:
    iVar5 = *(int *)(*plVar9 + 0x24);
    if ((iVar5 == -1) ||
       (piVar14 = *(int **)(*(long *)(*plVar9 + 0x18) + (long)iVar5 * 0x18), *piVar14 <= (int)uVar6)
       ) goto LAB_71019cd44c;
    lVar8 = (long)piVar14 + (ulong)(uint)piVar14[uVar6 + 1];
  }
  else {
    iVar7 = 0;
    if (uVar6 < *(uint *)(plVar9 + 1)) goto LAB_71019cd410;
LAB_71019cd44c:
    lVar8 = 0;
  }
  *(int *)(param_1 + 1) = iVar7;
  uVar3 = *(undefined4 *)((long)plVar9 + 0xc);
  *param_1 = lVar8;
  lVar8 = CONCAT44(uVar3,uVar6);
LAB_71019cd464:
  param_1[2] = lVar8;
  return;
}



undefined4 FUN_71019cd490(int *param_1,int *param_2)

{
  int iVar1;
  undefined4 uVar2;
  long *plVar3;
  long lVar4;
  undefined8 *puVar5;
  uint *puVar6;
  uint uVar7;
  uint local_14;
  
  uVar7 = param_2[1];
  if ((int)uVar7 < 0) {
LAB_71019cd4fc:
    puVar6 = &DAT_71040104d0;
  }
  else {
    lVar4 = *(long *)((uint *)*DAT_7103a59c40 + 2);
    if (lVar4 == 0) goto LAB_71019cd4fc;
    if (*(uint *)*DAT_7103a59c40 <= uVar7) {
      uVar7 = 0;
    }
    if (*(int *)(lVar4 + (ulong)uVar7 * 0x10 + 4) != *param_2) goto LAB_71019cd4fc;
    puVar5 = *(undefined8 **)(lVar4 + (ulong)uVar7 * 0x10 + 8);
    if (puVar5 == (undefined8 *)0x0) {
      puVar5 = FUN_7100baff84();
    }
    iVar1 = *(int *)((long)puVar5 + 0xac);
    lVar4 = (long)iVar1 + (long)puVar5 + 0xac;
    if (iVar1 == 0 || lVar4 == 0) goto LAB_71019cd4fc;
    puVar6 = (uint *)(lVar4 + 0x38);
  }
  local_14 = *puVar6;
  uVar7 = param_1[1];
  if (-1 < (int)uVar7) {
    lVar4 = *(long *)((uint *)*DAT_7103a59c40 + 2);
    if (*(uint *)*DAT_7103a59c40 <= uVar7) {
      uVar7 = 0;
    }
    if (((lVar4 != 0) && (lVar4 = lVar4 + (ulong)uVar7 * 0x10, *(int *)(lVar4 + 4) == *param_1)) &&
       (puVar5 = *(undefined8 **)(lVar4 + 8), puVar5 != (undefined8 *)0x0)) goto LAB_71019cd564;
  }
  puVar5 = FUN_7100baff84();
LAB_71019cd564:
  iVar1 = *(int *)(puVar5 + 0xf);
  if ((iVar1 == 0) || (plVar3 = (long *)((long)iVar1 + (long)(puVar5 + 0xf)), plVar3 == (long *)0x0)
     ) {
    plVar3 = FUN_7100bcff3c();
  }
  uVar2 = FUN_7100e36ce4((long)plVar3,&local_14);
  return uVar2;
}



undefined4 FUN_71019cd5c0(int *param_1,int *param_2)

{
  int iVar1;
  undefined4 uVar2;
  undefined8 *puVar3;
  undefined8 *puVar4;
  long *plVar5;
  uint uVar6;
  long lVar7;
  uint local_24;
  
  puVar4 = DAT_7103a59c40;
  uVar6 = param_2[1];
  if ((int)uVar6 < 0) {
LAB_71019cd628:
    puVar3 = FUN_7100baff84();
  }
  else {
    lVar7 = *(long *)((uint *)*DAT_7103a59c40 + 2);
    if (*(uint *)*DAT_7103a59c40 <= uVar6) {
      uVar6 = 0;
      if (lVar7 != 0) goto LAB_71019cd5fc;
      goto LAB_71019cd628;
    }
    if (lVar7 == 0) goto LAB_71019cd628;
LAB_71019cd5fc:
    lVar7 = lVar7 + (ulong)uVar6 * 0x10;
    if ((*(int *)(lVar7 + 4) != *param_2) ||
       (puVar3 = *(undefined8 **)(lVar7 + 8), puVar3 == (undefined8 *)0x0)) goto LAB_71019cd628;
  }
  iVar1 = *(int *)((long)puVar3 + 0xac);
  if ((iVar1 == 0) || (plVar5 = (long *)((long)iVar1 + (long)puVar3 + 0xac), plVar5 == (long *)0x0))
  {
    plVar5 = FUN_7100bafffc();
  }
  local_24 = *(uint *)(plVar5 + 7);
  uVar6 = param_1[1];
  if (-1 < (int)uVar6) {
    lVar7 = *(long *)((uint *)*puVar4 + 2);
    if (*(uint *)*puVar4 <= uVar6) {
      uVar6 = 0;
    }
    if (((lVar7 != 0) && (lVar7 = lVar7 + (ulong)uVar6 * 0x10, *(int *)(lVar7 + 4) == *param_1)) &&
       (puVar4 = *(undefined8 **)(lVar7 + 8), puVar4 != (undefined8 *)0x0)) goto LAB_71019cd69c;
  }
  puVar4 = FUN_7100baff84();
LAB_71019cd69c:
  iVar1 = *(int *)(puVar4 + 0xf);
  if ((iVar1 == 0) || (plVar5 = (long *)((long)iVar1 + (long)(puVar4 + 0xf)), plVar5 == (long *)0x0)
     ) {
    plVar5 = FUN_7100bcff3c();
  }
  iVar1 = FUN_7100e36ce4((long)plVar5,&local_24);
  uVar2 = FUN_7100e3c7c0(iVar1);
  return uVar2;
}



int FUN_71019cd7f0(int param_1,uint param_2)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  char cVar5;
  uint uVar6;
  uint uVar7;
  long *plVar8;
  int iVar9;
  int iVar10;
  long lVar11;
  
  lVar11 = FUN_7100deffe0(*DAT_7103a59ec8);
  plVar8 = DAT_7103a5d850;
  if ((param_2 != 0) && (uVar2 = *(uint *)(lVar11 + 0x2c), uVar2 != 0)) {
    uVar6 = 0;
    if (uVar2 != 0) {
      uVar6 = param_2 / uVar2;
    }
    uVar6 = param_2 - uVar6 * uVar2;
    uVar7 = uVar6;
    do {
      uVar4 = *(uint *)(*(long *)(lVar11 + 0x20) +
                       (-(ulong)(uVar7 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar7 << 4));
      if (uVar4 == param_2) {
        lVar11 = *(long *)(*(long *)(lVar11 + 0x20) + (long)(int)uVar7 * 0x10 + 8);
        if (lVar11 == 0) {
          return param_1;
        }
        iVar3 = *(int *)(lVar11 + 8);
        cVar5 = *(char *)(lVar11 + 0xc);
        if (*DAT_7103a5d850 == 0) {
          iVar9 = 200;
        }
        else {
          iVar9 = FUN_7100e3eab0(*DAT_7103a5d850);
        }
        if (cVar5 == '\0') {
          iVar10 = 0;
        }
        else {
          iVar9 = FUN_7100e3c7c0(param_1);
          lVar11 = *plVar8;
          if (lVar11 == 0) {
            iVar9 = 100;
            iVar10 = 100;
          }
          else {
            if (iVar9 == 0) {
              iVar10 = 0;
            }
            else {
              iVar10 = FUN_7100e3ebb0(lVar11,iVar9 + -1);
              iVar10 = iVar10 + 1;
              lVar11 = *plVar8;
              if (lVar11 == 0) {
                iVar9 = 100;
                goto LAB_71019cd8f0;
              }
            }
            iVar9 = FUN_7100e3ebb0(lVar11,iVar9);
          }
        }
LAB_71019cd8f0:
        iVar3 = iVar3 + param_1;
        iVar1 = iVar3;
        if (iVar9 <= iVar3) {
          iVar1 = iVar9;
        }
        if (iVar10 <= iVar3) {
          return iVar1;
        }
        return iVar10;
      }
      if (uVar4 == 0) {
        return param_1;
      }
      uVar4 = 0;
      if ((int)(uVar7 + 1) < (int)uVar2) {
        uVar4 = uVar7 + 1;
      }
      uVar7 = uVar4;
    } while (uVar4 != uVar6);
  }
  return param_1;
}



uint FUN_71019cd930(int *param_1,int *param_2)

{
  int iVar1;
  uint uVar2;
  long *plVar3;
  undefined8 *puVar4;
  long lVar5;
  long lVar6;
  int local_18;
  int iStack_14;
  
  uVar2 = param_1[1];
  if ((int)uVar2 < 0) {
LAB_71019cd99c:
    puVar4 = FUN_7100baff84();
  }
  else {
    lVar5 = *(long *)(DAT_71040e7d48 + 2);
    if (*DAT_71040e7d48 <= uVar2) {
      uVar2 = 0;
      if (lVar5 != 0) goto LAB_71019cd970;
      goto LAB_71019cd99c;
    }
    if (lVar5 == 0) goto LAB_71019cd99c;
LAB_71019cd970:
    lVar5 = lVar5 + (ulong)uVar2 * 0x10;
    if ((*(int *)(lVar5 + 4) != *param_1) ||
       (puVar4 = *(undefined8 **)(lVar5 + 8), puVar4 == (undefined8 *)0x0)) goto LAB_71019cd99c;
  }
  if (*(int *)((long)puVar4 + 0xac) == 0) {
    return 0;
  }
  if ((long)*(int *)((long)puVar4 + 0xac) == -0xac - (long)puVar4) {
    return 0;
  }
  uVar2 = param_1[1];
  if ((int)uVar2 < 0) {
LAB_71019cda14:
    puVar4 = FUN_7100baff84();
  }
  else {
    lVar5 = *(long *)(DAT_71040e7d48 + 2);
    if (*DAT_71040e7d48 <= uVar2) {
      uVar2 = 0;
      if (lVar5 != 0) goto LAB_71019cd9e8;
      goto LAB_71019cda14;
    }
    if (lVar5 == 0) goto LAB_71019cda14;
LAB_71019cd9e8:
    lVar5 = lVar5 + (ulong)uVar2 * 0x10;
    if ((*(int *)(lVar5 + 4) != *param_1) ||
       (puVar4 = *(undefined8 **)(lVar5 + 8), puVar4 == (undefined8 *)0x0)) goto LAB_71019cda14;
  }
  iVar1 = *(int *)((long)puVar4 + 0xac);
  if ((iVar1 == 0) || (plVar3 = (long *)((long)iVar1 + (long)puVar4 + 0xac), plVar3 == (long *)0x0))
  {
    plVar3 = FUN_7100bafffc();
  }
  lVar5 = plVar3[7];
  uVar2 = param_2[1];
  if ((int)uVar2 < 0) {
LAB_71019cda88:
    puVar4 = FUN_7100baff84();
  }
  else {
    lVar6 = *(long *)(DAT_71040e7d48 + 2);
    if (*DAT_71040e7d48 <= uVar2) {
      uVar2 = 0;
      if (lVar6 != 0) goto LAB_71019cda54;
      goto LAB_71019cda88;
    }
    if (lVar6 == 0) goto LAB_71019cda88;
LAB_71019cda54:
    lVar6 = lVar6 + (ulong)uVar2 * 0x10;
    if ((*(int *)(lVar6 + 4) != *param_2) ||
       (puVar4 = *(undefined8 **)(lVar6 + 8), puVar4 == (undefined8 *)0x0)) goto LAB_71019cda88;
  }
  if (*(int *)((long)puVar4 + 0xac) == 0) {
    return 0;
  }
  if ((long)*(int *)((long)puVar4 + 0xac) == -0xac - (long)puVar4) {
    return 0;
  }
  uVar2 = param_2[1];
  if (-1 < (int)uVar2) {
    if (*DAT_71040e7d48 <= uVar2) {
      uVar2 = 0;
    }
    if (((*(long *)(DAT_71040e7d48 + 2) != 0) &&
        (lVar6 = *(long *)(DAT_71040e7d48 + 2) + (ulong)uVar2 * 0x10,
        *(int *)(lVar6 + 4) == *param_2)) &&
       (puVar4 = *(undefined8 **)(lVar6 + 8), puVar4 != (undefined8 *)0x0)) goto LAB_71019cdb00;
  }
  puVar4 = FUN_7100baff84();
LAB_71019cdb00:
  iVar1 = *(int *)((long)puVar4 + 0xac);
  if ((iVar1 == 0) || (plVar3 = (long *)((long)iVar1 + (long)puVar4 + 0xac), plVar3 == (long *)0x0))
  {
    plVar3 = FUN_7100bafffc();
  }
  local_18 = (int)plVar3[7];
  iStack_14 = (int)lVar5;
  uVar2 = FUN_71019ce1f0(&iStack_14,&local_18);
  return uVar2;
}



undefined4 FUN_71019cdb40(undefined4 *param_1,int *param_2,int *param_3)

{
  long lVar1;
  bool bVar2;
  ushort uVar3;
  undefined4 uVar4;
  int iVar5;
  undefined4 uVar6;
  undefined8 *puVar7;
  uint uVar8;
  long lVar9;
  uint local_38;
  uint local_34;
  
  uVar8 = param_2[1];
  if ((int)uVar8 < 0) {
LAB_71019cdbb0:
    puVar7 = FUN_7100baff84();
  }
  else {
    lVar9 = *(long *)(DAT_71040e7d48 + 2);
    if (*DAT_71040e7d48 <= uVar8) {
      uVar8 = 0;
      if (lVar9 != 0) goto LAB_71019cdb84;
      goto LAB_71019cdbb0;
    }
    if (lVar9 == 0) goto LAB_71019cdbb0;
LAB_71019cdb84:
    lVar9 = lVar9 + (ulong)uVar8 * 0x10;
    if ((*(int *)(lVar9 + 4) != *param_2) ||
       (puVar7 = *(undefined8 **)(lVar9 + 8), puVar7 == (undefined8 *)0x0)) goto LAB_71019cdbb0;
  }
  iVar5 = *(int *)(puVar7 + 0xf);
  if (iVar5 == 0) {
    return 0;
  }
  lVar9 = (long)iVar5 + (long)(puVar7 + 0xf);
  if (lVar9 == 0) {
    return 0;
  }
  uVar8 = param_3[1];
  if (-1 < (int)uVar8) {
    if (*DAT_71040e7d48 <= uVar8) {
      uVar8 = 0;
    }
    if (((*(long *)(DAT_71040e7d48 + 2) != 0) &&
        (lVar1 = *(long *)(DAT_71040e7d48 + 2) + (ulong)uVar8 * 0x10,
        *(int *)(lVar1 + 4) == *param_3)) &&
       (puVar7 = *(undefined8 **)(lVar1 + 8), puVar7 != (undefined8 *)0x0)) goto LAB_71019cdc20;
  }
  puVar7 = FUN_7100baff84();
LAB_71019cdc20:
  iVar5 = *(int *)((long)puVar7 + 0xac);
  uVar4 = 0;
  if ((iVar5 != 0) && (lVar1 = (long)iVar5 + (long)puVar7 + 0xac, lVar1 != 0)) {
    local_34 = *(uint *)(lVar1 + 0x38);
    uVar4 = FUN_7100e369bc(lVar9,&local_34);
    *param_1 = uVar4;
    iVar5 = FUN_7100e36ce4(lVar9,&local_34);
    uVar4 = FUN_7100e3c7c0(iVar5);
    param_1[1] = uVar4;
    uVar4 = 1;
    local_38 = 1;
    uVar3 = FUN_7100e38b38(lVar9,&local_34,&local_38);
    *(byte *)((long)param_1 + 9) = (byte)uVar3 & 1;
    bVar2 = FUN_7100e38cfc(lVar9,&local_34);
    *(bool *)(param_1 + 2) = bVar2;
    uVar6 = FUN_7101da0280(param_3);
    param_1[3] = uVar6;
  }
  return uVar4;
}



void FUN_71019cdcc0(long *param_1,uint *param_2,undefined8 param_3,undefined8 param_4,
                   undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                   undefined8 param_9)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  long *plVar4;
  uint uVar5;
  int *piVar6;
  long lVar7;
  ulong uVar8;
  char *local_f8;
  char *local_f0;
  byte *local_e8;
  int local_e0;
  byte local_dc [63];
  undefined1 local_9d;
  char *local_98;
  long *plStack_90;
  undefined8 local_88;
  undefined1 local_80;
  long local_78;
  byte **ppbStack_70;
  undefined4 local_68;
  byte *local_60;
  undefined4 local_58;
  undefined1 auStack_50 [32];
  int iStack_14;
  
  local_e8 = (byte *)0x71030f1b55;
  plVar4 = (long *)FUN_710293d5f0(DAT_7105a08e80,&local_e8);
  if (plVar4 == (long *)0x0) {
LAB_71019ce1a4:
    uVar8 = 0xffffffffffffffff;
    *param_1 = 0;
    *(undefined4 *)(param_1 + 1) = 0;
    goto LAB_71019ce1d8;
  }
  if (*(char *)((long)param_2 + 9) == '\0') {
    uVar2 = *param_2;
    if (uVar2 == 0) {
      FUN_71019cc320(param_1,0,param_2[3],0,param_5,param_6,param_7,param_8,param_9);
      return;
    }
    if ((uVar2 == 0xffffffff) || ((1 << (ulong)(uVar2 & 0x1f) & 0x7f40U) == 0)) {
LAB_71019cdfe0:
      local_f0 = "";
      if (uVar2 + 1 < 0x10) {
        local_f0 = *(char **)(&DAT_7103917568 + (ulong)(uVar2 + 1) * 8);
      }
      local_e8 = local_dc;
      local_9d = 0;
      local_e0 = 0x40;
      local_58 = 0x40;
      local_80 = 0;
      local_f8 = "";
      if ((char)param_2[2] != '\0') {
        local_f8 = "_Fight";
      }
      plStack_90 = &local_78;
      local_88 = 0x700000000;
      local_98 = "%s%s_%d";
      ppbStack_70 = &local_60;
      local_78 = DAT_7103a71198 + 0x10;
      local_68 = 0;
      local_dc[0] = 0;
      local_60 = local_e8;
      FUN_71019d0768((long *)&local_98,(long *)&local_f0,(long *)&local_f8,param_2 + 1,param_6,
                     param_7,param_8,param_9);
      if (local_98 != (char *)0x0) {
        local_80 = 0;
        while( true ) {
          if (local_88._4_4_ <= (int)local_88) break;
          FUN_71024fd620((long *)&local_98,auStack_50,&iStack_14);
        }
      }
      goto LAB_71019ce0c4;
    }
    if (uVar2 - 10 < 4) {
      local_9d = 0;
      local_e8 = local_dc;
      local_f0 = "Family";
      local_e0 = 0x40;
      local_58 = 0x40;
      local_f8 = "";
      if ((char)param_2[2] != '\0') {
        local_f8 = "_Fight";
      }
      plStack_90 = &local_78;
      local_80 = 0;
      local_98 = "%s%s_%d";
      local_88 = 0x700000000;
      ppbStack_70 = &local_60;
      local_68 = 0;
      local_78 = DAT_7103a71198 + 0x10;
      local_dc[0] = 0;
      local_60 = local_e8;
      FUN_71019d0768((long *)&local_98,(long *)&local_f0,(long *)&local_f8,param_2 + 1,param_6,
                     param_7,param_8,param_9);
      if (local_98 != (char *)0x0) {
        local_80 = 0;
        while( true ) {
          if (local_88._4_4_ <= (int)local_88) break;
          FUN_71024fd620((long *)&local_98,auStack_50,&iStack_14);
        }
      }
      goto LAB_71019ce0c4;
    }
    if (1 < uVar2 - 8) goto LAB_71019cdfe0;
    local_9d = 0;
    local_e8 = local_dc;
    local_f0 = "ParentAndChild";
    local_e0 = 0x40;
    local_58 = 0x40;
    local_f8 = "";
    if ((char)param_2[2] != '\0') {
      local_f8 = "_Fight";
    }
    plStack_90 = &local_78;
    local_80 = 0;
    local_98 = "%s%s_%d";
    local_88 = 0x700000000;
    ppbStack_70 = &local_60;
    local_68 = 0;
    local_78 = DAT_7103a71198 + 0x10;
    local_dc[0] = 0;
    local_60 = local_e8;
    FUN_71019d0768((long *)&local_98,(long *)&local_f0,(long *)&local_f8,param_2 + 1,param_6,param_7
                   ,param_8,param_9);
    if (local_98 != (char *)0x0) {
      local_80 = 0;
      while( true ) {
        if (local_88._4_4_ <= (int)local_88) break;
        FUN_71024fd620((long *)&local_98,auStack_50,&iStack_14);
      }
    }
    local_e8[(long)local_e0 + -1] = 0;
    uVar2 = FUN_7102557b90(*plVar4,local_e8);
    if ((int)uVar2 < 0) goto LAB_71019ce1a4;
    uVar5 = *(uint *)(plVar4 + 1);
    uVar8 = (ulong)uVar2;
    if (uVar2 < uVar5) {
      iVar3 = FUN_7102557ca0(*plVar4,uVar2);
      uVar5 = *(uint *)(plVar4 + 1);
      iVar3 = iVar3 >> 1;
    }
    else {
      iVar3 = 0;
    }
    if (uVar2 < uVar5) goto LAB_71019ce120;
    goto LAB_71019ce1c0;
  }
  local_9d = 0;
  local_e8 = local_dc;
  local_f0 = "OnesideLove";
  local_e0 = 0x40;
  local_58 = 0x40;
  local_f8 = "";
  if ((char)param_2[2] != '\0') {
    local_f8 = "_Fight";
  }
  plStack_90 = &local_78;
  local_80 = 0;
  local_98 = "%s%s_%d";
  local_88 = 0x700000000;
  ppbStack_70 = &local_60;
  local_68 = 0;
  local_78 = DAT_7103a71198 + 0x10;
  local_dc[0] = 0;
  local_60 = local_e8;
  FUN_71019d0768((long *)&local_98,(long *)&local_f0,(long *)&local_f8,param_2 + 1,param_6,param_7,
                 param_8,param_9);
  if (local_98 != (char *)0x0) {
    local_80 = 0;
    while( true ) {
      if (local_88._4_4_ <= (int)local_88) break;
      FUN_71024fd620((long *)&local_98,auStack_50,&iStack_14);
    }
  }
LAB_71019ce0c4:
  local_e8[(long)local_e0 + -1] = 0;
  uVar2 = FUN_7102557b90(*plVar4,local_e8);
  if ((int)uVar2 < 0) goto LAB_71019ce1a4;
  uVar8 = (ulong)uVar2;
  if (uVar2 < *(uint *)(plVar4 + 1)) {
    iVar3 = FUN_7102557ca0(*plVar4,uVar2);
    iVar3 = iVar3 >> 1;
    if (*(uint *)(plVar4 + 1) <= uVar2) goto LAB_71019ce1c0;
LAB_71019ce120:
    iVar1 = *(int *)(*plVar4 + 0x24);
    if (iVar1 == -1) goto LAB_71019ce1c0;
    piVar6 = *(int **)(*(long *)(*plVar4 + 0x18) + (long)iVar1 * 0x18);
    if (*piVar6 <= (int)uVar8) goto LAB_71019ce1c0;
    lVar7 = (long)piVar6 + (ulong)(uint)piVar6[(int)uVar8 + 1];
  }
  else {
    iVar3 = 0;
    if (uVar2 < *(uint *)(plVar4 + 1)) goto LAB_71019ce120;
LAB_71019ce1c0:
    lVar7 = 0;
  }
  *(int *)(param_1 + 1) = iVar3;
  uVar2 = *(uint *)((long)plVar4 + 0xc);
  *param_1 = lVar7;
  uVar8 = uVar8 | (ulong)uVar2 << 0x20;
LAB_71019ce1d8:
  param_1[2] = uVar8;
  return;
}



uint FUN_71019ce1f0(int *param_1,int *param_2)

{
  long lVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  long lVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  ushort uVar10;
  int iVar11;
  uint uVar12;
  long lVar13;
  int *piVar14;
  
  iVar6 = *param_1;
  iVar7 = *param_2;
  iVar8 = *DAT_7103a59b68;
  iVar2 = iVar6;
  if (iVar7 <= iVar6) {
    iVar2 = iVar7;
  }
  iVar3 = iVar6;
  if (iVar6 <= iVar7) {
    iVar3 = iVar7;
  }
  if ((iVar2 != iVar8) && (iVar3 != iVar8 && iVar2 < iVar3)) {
    iVar11 = iVar2 + 2 + (iVar2 + 2) * iVar2;
    if (iVar11 < 0) {
      iVar11 = iVar11 + 1;
    }
    uVar12 = (iVar3 + iVar2 * 0x46) - (iVar11 >> 1);
    if (uVar12 < 0x96f) {
      lVar13 = *DAT_7103a5d850 + 0x40;
      piVar14 = (int *)(lVar13 + (ulong)uVar12 * 0x378);
      iVar11 = *piVar14;
      if ((iVar11 != iVar8) && (iVar9 = piVar14[1], iVar11 < iVar9 && iVar9 != iVar8)) {
        if (*(char *)(lVar13 + (ulong)uVar12 * 0x378 + 0x10) != '\0') {
          return 1;
        }
        if ((iVar6 != iVar7) && (iVar11 == iVar2 && iVar9 == iVar3)) {
          lVar13 = lVar13 + (ulong)uVar12 * 0x378;
          lVar1 = lVar13 + 0x18;
          lVar13 = lVar13 + 0x1c8;
          lVar5 = lVar1;
          if (iVar7 <= iVar6) {
            lVar5 = lVar13;
          }
          uVar10 = *(ushort *)(lVar5 + 4);
          if (iVar6 <= iVar7) {
            lVar1 = lVar13;
          }
          uVar12 = 2;
          if ((uVar10 & 2 & *(ushort *)(lVar1 + 4)) != 0) {
            uVar12 = 4;
          }
          uVar4 = 3;
          if ((uVar10 & 2) != 0) {
            uVar4 = uVar12;
          }
          return uVar4 & (int)((uint)(uVar10 | *(ushort *)(lVar1 + 4)) << 0x1e) >> 0x1f;
        }
      }
    }
  }
  return 0;
}



uint FUN_71019ce310(int *param_1,int *param_2)

{
  int iVar1;
  uint uVar2;
  long *plVar3;
  undefined8 *puVar4;
  long lVar5;
  long lVar6;
  int local_18;
  int iStack_14;
  
  uVar2 = param_1[1];
  if ((int)uVar2 < 0) {
LAB_71019ce37c:
    puVar4 = FUN_7100baff84();
  }
  else {
    lVar5 = *(long *)(DAT_71040e7d48 + 2);
    if (*DAT_71040e7d48 <= uVar2) {
      uVar2 = 0;
      if (lVar5 != 0) goto LAB_71019ce350;
      goto LAB_71019ce37c;
    }
    if (lVar5 == 0) goto LAB_71019ce37c;
LAB_71019ce350:
    lVar5 = lVar5 + (ulong)uVar2 * 0x10;
    if ((*(int *)(lVar5 + 4) != *param_1) ||
       (puVar4 = *(undefined8 **)(lVar5 + 8), puVar4 == (undefined8 *)0x0)) goto LAB_71019ce37c;
  }
  if (*(int *)((long)puVar4 + 0xac) == 0) {
    return 0;
  }
  if ((long)*(int *)((long)puVar4 + 0xac) == -0xac - (long)puVar4) {
    return 0;
  }
  uVar2 = param_1[1];
  if ((int)uVar2 < 0) {
LAB_71019ce3f4:
    puVar4 = FUN_7100baff84();
  }
  else {
    lVar5 = *(long *)(DAT_71040e7d48 + 2);
    if (*DAT_71040e7d48 <= uVar2) {
      uVar2 = 0;
      if (lVar5 != 0) goto LAB_71019ce3c8;
      goto LAB_71019ce3f4;
    }
    if (lVar5 == 0) goto LAB_71019ce3f4;
LAB_71019ce3c8:
    lVar5 = lVar5 + (ulong)uVar2 * 0x10;
    if ((*(int *)(lVar5 + 4) != *param_1) ||
       (puVar4 = *(undefined8 **)(lVar5 + 8), puVar4 == (undefined8 *)0x0)) goto LAB_71019ce3f4;
  }
  iVar1 = *(int *)((long)puVar4 + 0xac);
  if ((iVar1 == 0) || (plVar3 = (long *)((long)iVar1 + (long)puVar4 + 0xac), plVar3 == (long *)0x0))
  {
    plVar3 = FUN_7100bafffc();
  }
  lVar5 = plVar3[7];
  uVar2 = param_2[1];
  if ((int)uVar2 < 0) {
LAB_71019ce468:
    puVar4 = FUN_7100baff84();
  }
  else {
    lVar6 = *(long *)(DAT_71040e7d48 + 2);
    if (*DAT_71040e7d48 <= uVar2) {
      uVar2 = 0;
      if (lVar6 != 0) goto LAB_71019ce434;
      goto LAB_71019ce468;
    }
    if (lVar6 == 0) goto LAB_71019ce468;
LAB_71019ce434:
    lVar6 = lVar6 + (ulong)uVar2 * 0x10;
    if ((*(int *)(lVar6 + 4) != *param_2) ||
       (puVar4 = *(undefined8 **)(lVar6 + 8), puVar4 == (undefined8 *)0x0)) goto LAB_71019ce468;
  }
  if (*(int *)((long)puVar4 + 0xac) == 0) {
    return 0;
  }
  if ((long)*(int *)((long)puVar4 + 0xac) == -0xac - (long)puVar4) {
    return 0;
  }
  uVar2 = param_2[1];
  if (-1 < (int)uVar2) {
    if (*DAT_71040e7d48 <= uVar2) {
      uVar2 = 0;
    }
    if (((*(long *)(DAT_71040e7d48 + 2) != 0) &&
        (lVar6 = *(long *)(DAT_71040e7d48 + 2) + (ulong)uVar2 * 0x10,
        *(int *)(lVar6 + 4) == *param_2)) &&
       (puVar4 = *(undefined8 **)(lVar6 + 8), puVar4 != (undefined8 *)0x0)) goto LAB_71019ce4e0;
  }
  puVar4 = FUN_7100baff84();
LAB_71019ce4e0:
  iVar1 = *(int *)((long)puVar4 + 0xac);
  if ((iVar1 == 0) || (plVar3 = (long *)((long)iVar1 + (long)puVar4 + 0xac), plVar3 == (long *)0x0))
  {
    plVar3 = FUN_7100bafffc();
  }
  local_18 = (int)plVar3[7];
  iStack_14 = (int)lVar5;
  uVar2 = FUN_71019ce520(&iStack_14,&local_18);
  return uVar2;
}



uint FUN_71019ce520(int *param_1,int *param_2)

{
  long lVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  long lVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  ushort uVar10;
  int iVar11;
  uint uVar12;
  long lVar13;
  int *piVar14;
  
  iVar6 = *param_1;
  iVar7 = *param_2;
  iVar8 = *DAT_7103a59b68;
  iVar2 = iVar6;
  if (iVar7 <= iVar6) {
    iVar2 = iVar7;
  }
  iVar3 = iVar6;
  if (iVar6 <= iVar7) {
    iVar3 = iVar7;
  }
  if ((iVar2 != iVar8) && (iVar3 != iVar8 && iVar2 < iVar3)) {
    iVar11 = iVar2 + 2 + (iVar2 + 2) * iVar2;
    if (iVar11 < 0) {
      iVar11 = iVar11 + 1;
    }
    uVar12 = (iVar3 + iVar2 * 0x46) - (iVar11 >> 1);
    if (uVar12 < 0x96f) {
      piVar14 = (int *)(*DAT_7103a5d850 + 0x40 + (ulong)uVar12 * 0x378);
      iVar11 = *piVar14;
      if (((iVar11 != iVar8) &&
          (iVar9 = piVar14[1], (iVar11 < iVar9 && iVar9 != iVar8) && iVar6 != iVar7)) &&
         (iVar11 == iVar2 && iVar9 == iVar3)) {
        lVar13 = *DAT_7103a5d850 + 0x40 + (ulong)uVar12 * 0x378;
        lVar1 = lVar13 + 0x18;
        lVar13 = lVar13 + 0x1c8;
        lVar5 = lVar1;
        if (iVar7 <= iVar6) {
          lVar5 = lVar13;
        }
        uVar10 = *(ushort *)(lVar5 + 4);
        if (iVar6 <= iVar7) {
          lVar1 = lVar13;
        }
        uVar12 = 2;
        if ((uVar10 & 2 & *(ushort *)(lVar1 + 4)) != 0) {
          uVar12 = 4;
        }
        uVar4 = 3;
        if ((uVar10 & 2) != 0) {
          uVar4 = uVar12;
        }
        return uVar4 & (int)((uint)(uVar10 | *(ushort *)(lVar1 + 4)) << 0x1e) >> 0x1f;
      }
    }
  }
  return 0;
}



void FUN_71019ce620(long *param_1,uint param_2,int param_3,ulong param_4,undefined8 param_5,
                   undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  undefined4 uVar1;
  undefined8 *puVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  long *plVar6;
  uint *puVar7;
  char *pcVar8;
  uint uVar9;
  int *piVar10;
  long lVar11;
  char *local_a8;
  byte *local_a0;
  int local_98;
  byte local_94 [63];
  undefined1 local_55;
  char *local_38;
  
  if (param_2 != 0) {
    local_a0 = (byte *)0x710313b65a;
    plVar6 = (long *)FUN_710293d5f0(*DAT_7103a5c248,&local_a0);
    puVar2 = DAT_7103a71180;
    if (plVar6 != (long *)0x0) {
      puVar7 = (uint *)*DAT_7103a71180;
      if ((puVar7 == (uint *)0x0) || ((char)puVar7[0x10] == '\0')) {
        iVar5 = FUN_71024fcfa0();
        iVar3 = FUN_71024fd1e0();
        uVar4 = (iVar5 - iVar3) + iVar3 * 8;
        pcVar8 = "";
        if (uVar4 < 0x5b) {
          uVar9 = (uint)(char)(&DAT_71032c57c7)[uVar4];
          if ((char)(&DAT_71032c57c7)[uVar4] < '\0') {
            if (iVar5 - 1U < 6) {
              iVar3 = *(int *)(&DAT_71032b46c0 + (long)(int)(iVar5 - 1U) * 4);
            }
            else {
              iVar3 = 0;
            }
            if ((uint)(iVar3 + iVar5) < 0x5b) {
              pcVar8 = &DAT_71032c57c7 + (uint)(iVar3 + iVar5);
            }
            uVar9 = (int)*pcVar8 & ((int)*pcVar8 >> 0x1f ^ 0xffffffffU);
            goto LAB_71019ce71c;
          }
        }
        else {
          uVar9 = 0;
        }
        uVar9 = uVar9 & 0xff;
      }
      else {
        uVar9 = *puVar7;
      }
LAB_71019ce71c:
      if ((param_2 == 3) && ((uVar9 & 0xfffffffe) == 6)) {
        local_38 = s_BeOneSideLoved_710398ba4d;
        local_a8 = "_00";
        if (param_3 != 1) {
          local_a8 = "";
        }
      }
      else if (((param_4 & 1) == 0) || ((param_2 != 2 && (param_2 != 4)))) {
        if (param_2 < 5) {
          local_38 = *(char **)(&DAT_710398ba70 + (ulong)param_2 * 8);
          local_a8 = "";
        }
        else {
          local_38 = "";
          local_a8 = "";
        }
      }
      else {
        puVar7 = (uint *)*puVar2;
        if ((puVar7 == (uint *)0x0) || ((char)puVar7[0x10] == '\0')) {
          iVar5 = FUN_71024fcfa0();
          iVar3 = FUN_71024fd1e0();
          uVar4 = (iVar5 - iVar3) + iVar3 * 8;
          pcVar8 = "";
          if (uVar4 < 0x5b) {
            uVar9 = (uint)(char)(&DAT_71032c57c7)[uVar4];
            if ((char)(&DAT_71032c57c7)[uVar4] < '\0') {
              if (iVar5 - 1U < 6) {
                iVar3 = *(int *)(&DAT_71032b46c0 + (long)(int)(iVar5 - 1U) * 4);
              }
              else {
                iVar3 = 0;
              }
              if ((uint)(iVar3 + iVar5) < 0x5b) {
                pcVar8 = &DAT_71032c57c7 + (uint)(iVar3 + iVar5);
              }
              uVar9 = (int)*pcVar8 & ((int)*pcVar8 >> 0x1f ^ 0xffffffffU);
              goto LAB_71019ce848;
            }
          }
          else {
            uVar9 = 0;
          }
          uVar9 = uVar9 & 0xff;
        }
        else {
          uVar9 = *puVar7;
        }
LAB_71019ce848:
        local_38 = *(char **)(&DAT_710398ba70 + (ulong)param_2 * 8);
        local_a8 = "_RelationGraphMulti";
        if (uVar9 != 0xb) {
          local_a8 = "";
        }
      }
      local_a0 = local_94;
      local_98 = 0x40;
      local_55 = 0;
      local_94[0] = 0;
      FUN_7100e3c8a0((long *)&local_a0,0x71030ce987,(long *)&local_38,(long *)&local_a8,param_5,
                     param_6,param_7,param_8);
      local_a0[(long)local_98 + -1] = 0;
      uVar4 = FUN_7102557b90(*plVar6,local_a0);
      if (-1 < (int)uVar4) {
        if (uVar4 < *(uint *)(plVar6 + 1)) {
          iVar5 = FUN_7102557ca0(*plVar6,uVar4);
          iVar5 = iVar5 >> 1;
          if (*(uint *)(plVar6 + 1) <= uVar4) goto LAB_71019ce954;
LAB_71019ce918:
          iVar3 = *(int *)(*plVar6 + 0x24);
          if ((iVar3 == -1) ||
             (piVar10 = *(int **)(*(long *)(*plVar6 + 0x18) + (long)iVar3 * 0x18),
             *piVar10 <= (int)uVar4)) goto LAB_71019ce954;
          lVar11 = (long)piVar10 + (ulong)(uint)piVar10[uVar4 + 1];
        }
        else {
          iVar5 = 0;
          if (uVar4 < *(uint *)(plVar6 + 1)) goto LAB_71019ce918;
LAB_71019ce954:
          lVar11 = 0;
        }
        *(int *)(param_1 + 1) = iVar5;
        uVar1 = *(undefined4 *)((long)plVar6 + 0xc);
        *param_1 = lVar11;
        lVar11 = CONCAT44(uVar1,uVar4);
        goto LAB_71019ce96c;
      }
    }
  }
  lVar11 = -1;
  *param_1 = 0;
  *(undefined4 *)(param_1 + 1) = 0;
LAB_71019ce96c:
  param_1[2] = lVar11;
  return;
}



void FUN_71019ce990(long *param_1,int *param_2,int *param_3,undefined8 param_4,undefined8 param_5,
                   undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined8 param_9)

{
  uint uVar1;
  int iVar2;
  undefined8 *puVar3;
  undefined8 *puVar4;
  long *plVar5;
  long lVar6;
  long lVar7;
  int local_28;
  int iStack_24;
  
  puVar4 = DAT_7103a59c40;
  uVar1 = param_2[1];
  if ((int)uVar1 < 0) {
LAB_71019cea04:
    puVar3 = FUN_7100baff84();
  }
  else {
    lVar6 = *(long *)((uint *)*DAT_7103a59c40 + 2);
    if (*(uint *)*DAT_7103a59c40 <= uVar1) {
      uVar1 = 0;
      if (lVar6 != 0) goto LAB_71019ce9d8;
      goto LAB_71019cea04;
    }
    if (lVar6 == 0) goto LAB_71019cea04;
LAB_71019ce9d8:
    lVar6 = lVar6 + (ulong)uVar1 * 0x10;
    if ((*(int *)(lVar6 + 4) != *param_2) ||
       (puVar3 = *(undefined8 **)(lVar6 + 8), puVar3 == (undefined8 *)0x0)) goto LAB_71019cea04;
  }
  if ((*(int *)((long)puVar3 + 0xac) == 0) ||
     ((long)*(int *)((long)puVar3 + 0xac) == -0xac - (long)puVar3)) goto LAB_71019ceac8;
  uVar1 = param_3[1];
  if ((int)uVar1 < 0) {
LAB_71019cea6c:
    puVar3 = FUN_7100baff84();
  }
  else {
    lVar6 = *(long *)((uint *)*puVar4 + 2);
    if (*(uint *)*puVar4 <= uVar1) {
      uVar1 = 0;
      if (lVar6 != 0) goto LAB_71019cea40;
      goto LAB_71019cea6c;
    }
    if (lVar6 == 0) goto LAB_71019cea6c;
LAB_71019cea40:
    lVar6 = lVar6 + (ulong)uVar1 * 0x10;
    if ((*(int *)(lVar6 + 4) != *param_3) ||
       (puVar3 = *(undefined8 **)(lVar6 + 8), puVar3 == (undefined8 *)0x0)) goto LAB_71019cea6c;
  }
  if ((*(int *)((long)puVar3 + 0xac) == 0) ||
     ((long)*(int *)((long)puVar3 + 0xac) == -0xac - (long)puVar3)) {
LAB_71019ceac8:
    *param_1 = 0;
    *(undefined4 *)(param_1 + 1) = 0;
    param_1[2] = -1;
    return;
  }
  uVar1 = param_2[1];
  if ((int)uVar1 < 0) {
LAB_71019ceaf4:
    puVar3 = FUN_7100baff84();
  }
  else {
    lVar6 = *(long *)((uint *)*puVar4 + 2);
    if (*(uint *)*puVar4 <= uVar1) {
      uVar1 = 0;
      if (lVar6 != 0) goto LAB_71019ceaa4;
      goto LAB_71019ceaf4;
    }
    if (lVar6 == 0) goto LAB_71019ceaf4;
LAB_71019ceaa4:
    lVar6 = lVar6 + (ulong)uVar1 * 0x10;
    if ((*(int *)(lVar6 + 4) != *param_2) ||
       (puVar3 = *(undefined8 **)(lVar6 + 8), puVar3 == (undefined8 *)0x0)) goto LAB_71019ceaf4;
  }
  iVar2 = *(int *)((long)puVar3 + 0xac);
  if ((iVar2 == 0) || (plVar5 = (long *)((long)iVar2 + (long)puVar3 + 0xac), plVar5 == (long *)0x0))
  {
    plVar5 = FUN_7100bafffc();
  }
  lVar6 = plVar5[7];
  uVar1 = param_3[1];
  if (-1 < (int)uVar1) {
    lVar7 = *(long *)((uint *)*puVar4 + 2);
    if (*(uint *)*puVar4 <= uVar1) {
      uVar1 = 0;
    }
    if (((lVar7 != 0) && (lVar7 = lVar7 + (ulong)uVar1 * 0x10, *(int *)(lVar7 + 4) == *param_3)) &&
       (puVar4 = *(undefined8 **)(lVar7 + 8), puVar4 != (undefined8 *)0x0)) goto LAB_71019ceb64;
  }
  puVar4 = FUN_7100baff84();
LAB_71019ceb64:
  iVar2 = *(int *)((long)puVar4 + 0xac);
  if ((iVar2 == 0) || (plVar5 = (long *)((long)iVar2 + (long)puVar4 + 0xac), plVar5 == (long *)0x0))
  {
    plVar5 = FUN_7100bafffc();
  }
  local_28 = (int)plVar5[7];
  iStack_24 = (int)lVar6;
  uVar1 = FUN_71019ce520(&iStack_24,&local_28);
  FUN_7101da0280(param_2);
  iVar2 = FUN_7101da0280(param_3);
  FUN_71019ce620(param_1,uVar1,iVar2,0,param_6,param_7,param_8,param_9);
  return;
}



bool FUN_71019cebd0(int *param_1,int *param_2)

{
  uint uVar1;
  int iVar2;
  bool bVar3;
  long lVar4;
  undefined8 *puVar5;
  uint *puVar6;
  uint local_14;
  
  uVar1 = param_2[1];
  if (-1 < (int)uVar1) {
    lVar4 = *(long *)((uint *)*DAT_7103a59c40 + 2);
    if (lVar4 != 0) {
      if (*(uint *)*DAT_7103a59c40 <= uVar1) {
        uVar1 = 0;
      }
      if (*(int *)(lVar4 + (ulong)uVar1 * 0x10 + 4) == *param_2) {
        puVar5 = *(undefined8 **)(lVar4 + (ulong)uVar1 * 0x10 + 8);
        if (puVar5 == (undefined8 *)0x0) {
          puVar5 = FUN_7100baff84();
        }
        iVar2 = *(int *)((long)puVar5 + 0xac);
        lVar4 = (long)iVar2 + (long)puVar5 + 0xac;
        if (iVar2 != 0 && lVar4 != 0) {
          puVar6 = (uint *)(lVar4 + 0x38);
          goto LAB_71019cec40;
        }
      }
    }
  }
  puVar6 = &DAT_71040104d0;
LAB_71019cec40:
  local_14 = *puVar6;
  uVar1 = param_1[1];
  if (-1 < (int)uVar1) {
    lVar4 = *(long *)((uint *)*DAT_7103a59c40 + 2);
    if (lVar4 != 0) {
      if (*(uint *)*DAT_7103a59c40 <= uVar1) {
        uVar1 = 0;
      }
      if (*(int *)(lVar4 + (ulong)uVar1 * 0x10 + 4) == *param_1) {
        puVar5 = *(undefined8 **)(lVar4 + (ulong)uVar1 * 0x10 + 8);
        if (puVar5 == (undefined8 *)0x0) {
          puVar5 = FUN_7100baff84();
        }
        iVar2 = *(int *)(puVar5 + 0xf);
        lVar4 = (long)iVar2 + (long)(puVar5 + 0xf);
        if (iVar2 != 0 && lVar4 != 0) {
          bVar3 = FUN_7100e38cfc(lVar4,&local_14);
          return bVar3;
        }
      }
    }
  }
  return false;
}



bool FUN_71019cecf0(int *param_1,int *param_2)

{
  int iVar1;
  bool bVar2;
  uint uVar3;
  undefined8 *puVar4;
  undefined8 *puVar5;
  long lVar6;
  uint *puVar7;
  uint local_24;
  
  uVar3 = FUN_71019c9020(param_1,param_2);
  puVar5 = DAT_7103a59c40;
  if ((uVar3 != 0xffffffff) && ((1 << (ulong)(uVar3 & 0x1f) & 0xa8U) != 0)) {
    return true;
  }
  uVar3 = param_2[1];
  if (-1 < (int)uVar3) {
    lVar6 = *(long *)((uint *)*DAT_7103a59c40 + 2);
    if (lVar6 != 0) {
      if (*(uint *)*DAT_7103a59c40 <= uVar3) {
        uVar3 = 0;
      }
      if (*(int *)(lVar6 + (ulong)uVar3 * 0x10 + 4) == *param_2) {
        puVar4 = *(undefined8 **)(lVar6 + (ulong)uVar3 * 0x10 + 8);
        if (puVar4 == (undefined8 *)0x0) {
          puVar4 = FUN_7100baff84();
        }
        iVar1 = *(int *)((long)puVar4 + 0xac);
        lVar6 = (long)iVar1 + (long)puVar4 + 0xac;
        if (iVar1 != 0 && lVar6 != 0) {
          puVar7 = (uint *)(lVar6 + 0x38);
          goto LAB_71019ced90;
        }
      }
    }
  }
  puVar7 = &DAT_71040104d0;
LAB_71019ced90:
  local_24 = *puVar7;
  uVar3 = param_1[1];
  if (-1 < (int)uVar3) {
    lVar6 = *(long *)((uint *)*puVar5 + 2);
    if (lVar6 != 0) {
      if (*(uint *)*puVar5 <= uVar3) {
        uVar3 = 0;
      }
      if (*(int *)(lVar6 + (ulong)uVar3 * 0x10 + 4) == *param_1) {
        puVar5 = *(undefined8 **)(lVar6 + (ulong)uVar3 * 0x10 + 8);
        if (puVar5 == (undefined8 *)0x0) {
          puVar5 = FUN_7100baff84();
        }
        iVar1 = *(int *)(puVar5 + 0xf);
        lVar6 = (long)iVar1 + (long)(puVar5 + 0xf);
        if (iVar1 != 0 && lVar6 != 0) {
          bVar2 = FUN_7100e38cfc(lVar6,&local_24);
          return bVar2;
        }
      }
    }
  }
  return false;
}



ushort FUN_71019cee30(int *param_1,int *param_2)

{
  int iVar1;
  ushort uVar2;
  uint uVar3;
  long lVar4;
  undefined8 *puVar5;
  uint *puVar6;
  uint local_18 [2];
  
  uVar3 = param_2[1];
  if ((int)uVar3 < 0) {
LAB_71019cee98:
    puVar6 = &DAT_71040104d0;
  }
  else {
    lVar4 = *(long *)((uint *)*DAT_7103a59c40 + 2);
    if (lVar4 == 0) goto LAB_71019cee98;
    if (*(uint *)*DAT_7103a59c40 <= uVar3) {
      uVar3 = 0;
    }
    if (*(int *)(lVar4 + (ulong)uVar3 * 0x10 + 4) != *param_2) goto LAB_71019cee98;
    puVar5 = *(undefined8 **)(lVar4 + (ulong)uVar3 * 0x10 + 8);
    if (puVar5 == (undefined8 *)0x0) {
      puVar5 = FUN_7100baff84();
    }
    iVar1 = *(int *)((long)puVar5 + 0xac);
    lVar4 = (long)iVar1 + (long)puVar5 + 0xac;
    if (iVar1 == 0 || lVar4 == 0) goto LAB_71019cee98;
    puVar6 = (uint *)(lVar4 + 0x38);
  }
  local_18[0] = *puVar6;
  uVar3 = param_1[1];
  if (-1 < (int)uVar3) {
    lVar4 = *(long *)((uint *)*DAT_7103a59c40 + 2);
    if (*(uint *)*DAT_7103a59c40 <= uVar3) {
      uVar3 = 0;
    }
    if (((lVar4 != 0) && (lVar4 = lVar4 + (ulong)uVar3 * 0x10, *(int *)(lVar4 + 4) == *param_1)) &&
       (puVar5 = *(undefined8 **)(lVar4 + 8), puVar5 != (undefined8 *)0x0)) goto LAB_71019cef04;
  }
  puVar5 = FUN_7100baff84();
LAB_71019cef04:
  iVar1 = *(int *)(puVar5 + 0xf);
  uVar2 = 0;
  if ((iVar1 != 0) && (lVar4 = (long)iVar1 + (long)(puVar5 + 0xf), lVar4 != 0)) {
    local_18[1] = 1;
    uVar2 = FUN_7100e38b38(lVar4,local_18,local_18 + 1);
  }
  return uVar2 & 1;
}



void FUN_71019cef60(uint *param_1,int *param_2)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  undefined8 *puVar6;
  long lVar7;
  uint uVar8;
  int iVar9;
  long lVar10;
  uint local_34;
  
  uVar2 = param_2[1];
  uVar8 = DAT_71040104d0;
  if ((-1 < (int)uVar2) && (lVar10 = *(long *)(DAT_71040e7d48 + 2), lVar10 != 0)) {
    if (*DAT_71040e7d48 <= uVar2) {
      uVar2 = 0;
    }
    if (*(int *)(lVar10 + (ulong)uVar2 * 0x10 + 4) == *param_2) {
      puVar6 = *(undefined8 **)(lVar10 + (ulong)uVar2 * 0x10 + 8);
      if (puVar6 == (undefined8 *)0x0) {
        puVar6 = FUN_7100baff84();
      }
      iVar5 = *(int *)(puVar6 + 0xf);
      lVar10 = (long)iVar5 + (long)(puVar6 + 0xf);
      uVar8 = DAT_71040104d0;
      if (iVar5 != 0 && lVar10 != 0) {
        uVar8 = *(uint *)(lVar10 + 0x28);
        local_34 = uVar8;
        lVar7 = FUN_7100bd09b0(*DAT_7103a59ec8);
        uVar2 = *(uint *)(lVar7 + 0x2c);
        if (uVar2 != 0) {
          uVar3 = 0;
          if (uVar2 != 0) {
            uVar3 = 0xac499210 / uVar2;
          }
          uVar3 = 0xac499210 - uVar3 * uVar2;
          uVar4 = uVar3;
          do {
            iVar5 = *(int *)(*(long *)(lVar7 + 0x20) +
                            (-(ulong)(uVar4 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar4 << 4));
            if (iVar5 == -0x53b66df0) {
              lVar7 = *(long *)(*(long *)(lVar7 + 0x20) + (long)(int)uVar4 * 0x10 + 8);
              iVar5 = FUN_7100e36ce4(lVar10,&local_34);
              if (lVar7 == 0) {
                iVar9 = 0;
              }
              else {
                iVar9 = *(int *)(lVar7 + 8);
              }
              goto LAB_71019cf08c;
            }
            if (iVar5 == 0) break;
            uVar1 = 0;
            if ((int)(uVar4 + 1) < (int)uVar2) {
              uVar1 = uVar4 + 1;
            }
            uVar4 = uVar1;
          } while (uVar1 != uVar3);
        }
        iVar5 = FUN_7100e36ce4(lVar10,&local_34);
        iVar9 = 0;
LAB_71019cf08c:
        if (iVar5 <= iVar9) {
          uVar8 = *DAT_7103a59b68;
        }
      }
    }
  }
  *param_1 = uVar8;
  return;
}



undefined8 FUN_71019cf0c0(int *param_1,int *param_2)

{
  int iVar1;
  uint uVar2;
  undefined8 *puVar3;
  long *plVar4;
  uint *puVar5;
  uint uVar6;
  long lVar7;
  
  uVar2 = FUN_71019c9020(param_1,param_2);
  if ((uVar2 != 0xffffffff) && ((1 << (ulong)(uVar2 & 0x1f) & 0x50U) != 0)) {
    return 1;
  }
  uVar2 = param_1[1];
  if ((int)uVar2 < 0) {
LAB_71019cf14c:
    puVar3 = FUN_7100baff84();
  }
  else {
    lVar7 = *(long *)(DAT_71040e7d48 + 2);
    if (*DAT_71040e7d48 <= uVar2) {
      uVar2 = 0;
      if (lVar7 != 0) goto LAB_71019cf120;
      goto LAB_71019cf14c;
    }
    if (lVar7 == 0) goto LAB_71019cf14c;
LAB_71019cf120:
    lVar7 = lVar7 + (ulong)uVar2 * 0x10;
    if ((*(int *)(lVar7 + 4) != *param_1) ||
       (puVar3 = *(undefined8 **)(lVar7 + 8), puVar3 == (undefined8 *)0x0)) goto LAB_71019cf14c;
  }
  iVar1 = *(int *)(puVar3 + 0xf);
  if ((iVar1 == 0) || (plVar4 = (long *)((long)iVar1 + (long)(puVar3 + 0xf)), plVar4 == (long *)0x0)
     ) {
    plVar4 = FUN_7100bcff3c();
  }
  uVar2 = *(uint *)(plVar4 + 5);
  if (0x45 < uVar2) {
    return 0;
  }
  uVar6 = param_2[1];
  if ((-1 < (int)uVar6) && (lVar7 = *(long *)(DAT_71040e7d48 + 2), lVar7 != 0)) {
    if (*DAT_71040e7d48 <= uVar6) {
      uVar6 = 0;
    }
    if (*(int *)(lVar7 + (ulong)uVar6 * 0x10 + 4) == *param_2) {
      puVar3 = *(undefined8 **)(lVar7 + (ulong)uVar6 * 0x10 + 8);
      if (puVar3 == (undefined8 *)0x0) {
        puVar3 = FUN_7100baff84();
      }
      iVar1 = *(int *)((long)puVar3 + 0xac);
      puVar5 = DAT_7103a59b68;
      if ((iVar1 != 0) && (lVar7 = (long)iVar1 + (long)puVar3 + 0xac, lVar7 != 0)) {
        puVar5 = (uint *)(lVar7 + 0x38);
      }
      goto LAB_71019cf1e0;
    }
  }
  puVar5 = &DAT_71040104d0;
LAB_71019cf1e0:
  if (uVar2 != *puVar5) {
    return 0;
  }
  return 1;
}



int FUN_71019cf220(int *param_1)

{
  uint uVar1;
  int *piVar2;
  int *piVar3;
  long *plVar4;
  undefined8 *puVar5;
  int iVar6;
  undefined8 *puVar7;
  long *plVar8;
  uint uVar9;
  long lVar10;
  long lVar11;
  long lVar12;
  uint *puVar13;
  int iVar14;
  uint local_54;
  
  puVar5 = DAT_7103a59c40;
  uVar9 = param_1[1];
  if (-1 < (int)uVar9) {
    lVar12 = *(long *)((uint *)*DAT_7103a59c40 + 2);
    if (*(uint *)*DAT_7103a59c40 <= uVar9) {
      uVar9 = 0;
    }
    if (((lVar12 != 0) && (lVar12 = lVar12 + (ulong)uVar9 * 0x10, *(int *)(lVar12 + 4) == *param_1))
       && (puVar7 = *(undefined8 **)(lVar12 + 8), puVar7 != (undefined8 *)0x0)) goto LAB_71019cf298;
  }
  puVar7 = FUN_7100baff84();
LAB_71019cf298:
  plVar4 = DAT_7103a59c30;
  piVar3 = DAT_7103a59b30;
  lVar10 = (long)*(int *)(puVar7 + 0xf);
  iVar14 = 0;
  lVar12 = lVar10 + (long)(puVar7 + 0xf);
  if (lVar12 == 0 || lVar10 == 0) {
    lVar12 = 5;
    do {
      local_54 = (int)lVar12 - 5;
      lVar10 = *(long *)(*(long *)(*plVar4 + 0x19a8d8) + lVar12 * 8);
      piVar2 = piVar3;
      if (lVar10 != 0) {
        piVar2 = (int *)(lVar10 + 0x400);
      }
      uVar9 = piVar2[1];
      if (-1 < (int)uVar9) {
        puVar13 = (uint *)*puVar5;
        lVar10 = *(long *)(puVar13 + 2);
        if (lVar10 != 0) {
          uVar1 = uVar9;
          if (*puVar13 <= uVar9) {
            uVar1 = 0;
          }
          if ((*(int *)(lVar10 + (ulong)uVar1 * 0x10 + 4) == *piVar2) &&
             (uVar9 != param_1[1] || *piVar2 != *param_1)) {
            plVar8 = FUN_7100bcff3c();
            iVar6 = FUN_7100e369bc((long)plVar8,&local_54);
            if (iVar6 == 2) {
              iVar14 = iVar14 + 1;
            }
          }
        }
      }
      lVar12 = lVar12 + 1;
    } while (lVar12 != 0x4b);
  }
  else {
    lVar10 = 5;
    do {
      local_54 = (int)lVar10 - 5;
      lVar11 = *(long *)(*(long *)(*plVar4 + 0x19a8d8) + lVar10 * 8);
      piVar2 = piVar3;
      if (lVar11 != 0) {
        piVar2 = (int *)(lVar11 + 0x400);
      }
      uVar9 = piVar2[1];
      if (-1 < (int)uVar9) {
        puVar13 = (uint *)*puVar5;
        lVar11 = *(long *)(puVar13 + 2);
        if (lVar11 != 0) {
          uVar1 = uVar9;
          if (*puVar13 <= uVar9) {
            uVar1 = 0;
          }
          if (((*(int *)(lVar11 + (ulong)uVar1 * 0x10 + 4) == *piVar2) &&
              (uVar9 != param_1[1] || *piVar2 != *param_1)) &&
             (iVar6 = FUN_7100e369bc(lVar12,&local_54), iVar6 == 2)) {
            iVar14 = iVar14 + 1;
          }
        }
      }
      lVar10 = lVar10 + 1;
    } while (lVar10 != 0x4b);
  }
  return iVar14;
}



int FUN_71019cf420(int *param_1)

{
  uint uVar1;
  int *piVar2;
  int *piVar3;
  long *plVar4;
  undefined8 *puVar5;
  uint uVar6;
  undefined8 *puVar7;
  long *plVar8;
  long lVar9;
  long lVar10;
  long lVar11;
  uint *puVar12;
  int iVar13;
  uint local_64;
  
  puVar5 = DAT_7103a59c40;
  uVar6 = param_1[1];
  if (-1 < (int)uVar6) {
    lVar11 = *(long *)((uint *)*DAT_7103a59c40 + 2);
    if (*(uint *)*DAT_7103a59c40 <= uVar6) {
      uVar6 = 0;
    }
    if (((lVar11 != 0) && (lVar11 = lVar11 + (ulong)uVar6 * 0x10, *(int *)(lVar11 + 4) == *param_1))
       && (puVar7 = *(undefined8 **)(lVar11 + 8), puVar7 != (undefined8 *)0x0)) goto LAB_71019cf49c;
  }
  puVar7 = FUN_7100baff84();
LAB_71019cf49c:
  plVar4 = DAT_7103a59c30;
  piVar3 = DAT_7103a59b30;
  lVar9 = (long)*(int *)(puVar7 + 0xf);
  iVar13 = 0;
  lVar11 = lVar9 + (long)(puVar7 + 0xf);
  if (lVar11 == 0 || lVar9 == 0) {
    lVar11 = 5;
    do {
      local_64 = (int)lVar11 - 5;
      lVar9 = *(long *)(*(long *)(*plVar4 + 0x19a8d8) + lVar11 * 8);
      piVar2 = piVar3;
      if (lVar9 != 0) {
        piVar2 = (int *)(lVar9 + 0x400);
      }
      uVar6 = piVar2[1];
      if (-1 < (int)uVar6) {
        puVar12 = (uint *)*puVar5;
        lVar9 = *(long *)(puVar12 + 2);
        if (lVar9 != 0) {
          uVar1 = uVar6;
          if (*puVar12 <= uVar6) {
            uVar1 = 0;
          }
          if ((*(int *)(lVar9 + (ulong)uVar1 * 0x10 + 4) == *piVar2) &&
             (uVar6 != param_1[1] || *piVar2 != *param_1)) {
            plVar8 = FUN_7100bcff3c();
            uVar6 = FUN_7100e369bc((long)plVar8,&local_64);
            if ((1 << (ulong)(uVar6 & 0x1f) & 0x54U) != 0 && uVar6 != 0xffffffff) {
              iVar13 = iVar13 + 1;
            }
          }
        }
      }
      lVar11 = lVar11 + 1;
    } while (lVar11 != 0x4b);
  }
  else {
    lVar9 = 5;
    do {
      local_64 = (int)lVar9 - 5;
      lVar10 = *(long *)(*(long *)(*plVar4 + 0x19a8d8) + lVar9 * 8);
      piVar2 = piVar3;
      if (lVar10 != 0) {
        piVar2 = (int *)(lVar10 + 0x400);
      }
      uVar6 = piVar2[1];
      if (-1 < (int)uVar6) {
        puVar12 = (uint *)*puVar5;
        lVar10 = *(long *)(puVar12 + 2);
        if (lVar10 != 0) {
          uVar1 = uVar6;
          if (*puVar12 <= uVar6) {
            uVar1 = 0;
          }
          if (((*(int *)(lVar10 + (ulong)uVar1 * 0x10 + 4) == *piVar2) &&
              (uVar6 != param_1[1] || *piVar2 != *param_1)) &&
             (uVar6 = FUN_7100e369bc(lVar11,&local_64),
             (1 << (ulong)(uVar6 & 0x1f) & 0x54U) != 0 && uVar6 != 0xffffffff)) {
            iVar13 = iVar13 + 1;
          }
        }
      }
      lVar9 = lVar9 + 1;
    } while (lVar9 != 0x4b);
  }
  return iVar13;
}



long FUN_71019cf650(int *param_1,int *param_2)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint *puVar4;
  uint uVar5;
  int iVar6;
  uint uVar7;
  uint uVar8;
  undefined8 *puVar9;
  long lVar10;
  long lVar11;
  uint uVar12;
  uint *puVar13;
  
  uVar5 = param_1[1];
  if ((int)uVar5 < 0) {
    return 0;
  }
  lVar11 = *(long *)(DAT_71040e7d48 + 2);
  if (lVar11 == 0) {
    return 0;
  }
  uVar2 = uVar5;
  if (*DAT_71040e7d48 <= uVar5) {
    uVar2 = 0;
  }
  iVar6 = *(int *)(lVar11 + (ulong)uVar2 * 0x10 + 4);
  if (iVar6 != *param_1) {
    return 0;
  }
  uVar12 = param_2[1];
  if ((int)uVar12 < 0) {
    return 0;
  }
  if (*DAT_71040e7d48 <= uVar12) {
    uVar12 = 0;
  }
  if (*(int *)(lVar11 + (ulong)uVar12 * 0x10 + 4) != *param_2) {
    return 0;
  }
  uVar12 = param_2[1];
  if (iVar6 == *param_2 && uVar5 == uVar12) {
    return 0;
  }
  puVar9 = *(undefined8 **)(lVar11 + (ulong)uVar2 * 0x10 + 8);
  if (puVar9 == (undefined8 *)0x0) {
    puVar9 = FUN_7100baff84();
    uVar12 = param_2[1];
  }
  lVar10 = (long)*(int *)((long)puVar9 + 0xac);
  lVar11 = lVar10 + (long)puVar9 + 0xac;
  puVar13 = &DAT_71040104d0;
  if (lVar11 != 0 && lVar10 != 0) {
    puVar13 = (uint *)(lVar11 + 0x38);
  }
  uVar5 = *puVar13;
  if ((int)uVar12 < 0) {
    puVar13 = &DAT_71040104d0;
  }
  else {
    lVar11 = *(long *)(DAT_71040e7d48 + 2);
    if (lVar11 != 0) {
      if (*DAT_71040e7d48 <= uVar12) {
        uVar12 = 0;
      }
      if (*(int *)(lVar11 + (ulong)uVar12 * 0x10 + 4) == *param_2) {
        puVar9 = *(undefined8 **)(lVar11 + (ulong)uVar12 * 0x10 + 8);
        if (puVar9 == (undefined8 *)0x0) {
          puVar9 = FUN_7100baff84();
        }
        iVar6 = *(int *)((long)puVar9 + 0xac);
        lVar11 = (long)iVar6 + (long)puVar9 + 0xac;
        puVar4 = &DAT_71040104d0;
        if (lVar11 != 0) {
          puVar4 = (uint *)(lVar11 + 0x38);
        }
        puVar13 = &DAT_71040104d0;
        if (iVar6 != 0) {
          puVar13 = puVar4;
        }
        goto LAB_71019cf774;
      }
    }
    puVar13 = &DAT_71040104d0;
  }
LAB_71019cf774:
  if (0x45 < uVar5) {
    return 0;
  }
  uVar2 = *puVar13;
  if (uVar2 < 0x46) {
    uVar12 = uVar5;
    if ((int)uVar2 <= (int)uVar5) {
      uVar12 = uVar2;
    }
    uVar3 = uVar5;
    if ((int)uVar5 <= (int)uVar2) {
      uVar3 = uVar2;
    }
    if (((uVar12 != DAT_71040104d0) && (uVar12 < uVar3 && uVar3 != DAT_71040104d0)) &&
       (uVar1 = (uVar12 * 0x46 - (uVar12 + 2 + (uVar12 + 2) * uVar12 >> 1)) + uVar3, uVar1 < 0x96f))
    {
      lVar11 = *DAT_7103a5d850 + 0x40;
      puVar13 = (uint *)(lVar11 + (ulong)uVar1 * 0x378);
      uVar7 = *puVar13;
      if ((uVar7 != DAT_71040104d0) &&
         (uVar8 = puVar13[1], (int)uVar7 < (int)uVar8 && uVar8 != DAT_71040104d0)) {
        if ((uVar5 == uVar2) || (uVar7 != uVar12 || uVar8 != uVar3)) {
          lVar11 = 0;
        }
        else if (uVar5 < uVar2) {
          lVar11 = lVar11 + (ulong)uVar1 * 0x378 + 0x18;
        }
        else {
          lVar11 = lVar11 + (ulong)uVar1 * 0x378 + 0x1c8;
        }
        return lVar11 + 0x198;
      }
    }
    return 0;
  }
  return 0;
}



// WARNING: Type propagation algorithm not settling

undefined8 FUN_71019cf8b0(int *param_1,uint *param_2)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  bool bVar4;
  uint uVar5;
  int iVar6;
  uint uVar7;
  undefined8 *puVar8;
  int *piVar9;
  long lVar10;
  long *plVar11;
  int iVar12;
  long lVar13;
  uint *puVar14;
  uint local_48;
  uint local_44;
  
  uVar7 = param_1[1];
  if ((int)uVar7 < 0) {
    return 0;
  }
  lVar13 = *(long *)(DAT_71040e7d48 + 2);
  if (lVar13 == 0) {
    return 0;
  }
  if (*DAT_71040e7d48 <= uVar7) {
    uVar7 = 0;
  }
  if (*(int *)(lVar13 + (ulong)uVar7 * 0x10 + 4) != *param_1) {
    return 0;
  }
  uVar7 = param_2[1];
  if ((int)uVar7 < 0) {
    return 0;
  }
  if (*DAT_71040e7d48 <= uVar7) {
    uVar7 = 0;
  }
  if (*(uint *)(lVar13 + (ulong)uVar7 * 0x10 + 4) != *param_2) {
    return 0;
  }
  uVar5 = FUN_71019c9020(param_1,(int *)param_2);
  uVar7 = param_2[1];
  if (((int)uVar7 < 0) || (lVar13 = *(long *)(DAT_71040e7d48 + 2), lVar13 == 0)) {
LAB_71019cf9a4:
    puVar14 = &DAT_71040104d0;
  }
  else {
    if (*DAT_71040e7d48 <= uVar7) {
      uVar7 = 0;
    }
    if (*(uint *)(lVar13 + (ulong)uVar7 * 0x10 + 4) != *param_2) goto LAB_71019cf9a4;
    puVar8 = *(undefined8 **)(lVar13 + (ulong)uVar7 * 0x10 + 8);
    if (puVar8 == (undefined8 *)0x0) {
      puVar8 = FUN_7100baff84();
    }
    iVar6 = *(int *)((long)puVar8 + 0xac);
    puVar14 = DAT_7103a59b68;
    if ((iVar6 != 0) && (lVar13 = (long)iVar6 + (long)puVar8 + 0xac, lVar13 != 0)) {
      puVar14 = (uint *)(lVar13 + 0x38);
    }
  }
  local_48 = *puVar14;
  uVar7 = param_1[1];
  if ((int)uVar7 < 0) {
LAB_71019cfa10:
    puVar8 = FUN_7100baff84();
  }
  else {
    lVar13 = *(long *)(DAT_71040e7d48 + 2);
    if (*DAT_71040e7d48 <= uVar7) {
      uVar7 = 0;
      if (lVar13 != 0) goto LAB_71019cf9d4;
      goto LAB_71019cfa10;
    }
    if (lVar13 == 0) goto LAB_71019cfa10;
LAB_71019cf9d4:
    lVar13 = lVar13 + (ulong)uVar7 * 0x10;
    if ((*(int *)(lVar13 + 4) != *param_1) ||
       (puVar8 = *(undefined8 **)(lVar13 + 8), puVar8 == (undefined8 *)0x0)) goto LAB_71019cfa10;
  }
  iVar6 = *(int *)(puVar8 + 0xf);
  if ((iVar6 == 0) ||
     (plVar11 = (long *)((long)iVar6 + (long)(puVar8 + 0xf)), plVar11 == (long *)0x0)) {
    plVar11 = FUN_7100bcff3c();
  }
  iVar6 = FUN_7100e36ce4((long)plVar11,&local_48);
  bVar4 = FUN_7100eec5a0(param_1,(int *)param_2);
  if (bVar4) {
    return 0;
  }
  if (0xe < uVar5) {
    return 0;
  }
  if ((1 << (ulong)(uVar5 & 0x1f) & 0x7f54U) == 0) {
    return 0;
  }
  uVar7 = 0x545415f9;
  if (((*DAT_7103a5d850 != 0) && ((*(byte *)(*DAT_7103a5d850 + 0x4172a0) & 1) == 0)) &&
     (DAT_71040e86a0 != 0)) {
    lVar13 = 0;
    if (*DAT_7103a5a7e8 != 0) {
      lVar13 = *(long *)(*DAT_7103a5a7e8 + 0xf0);
    }
    if (0x1517f < lVar13 - *(long *)(*(long *)(DAT_71040e86a0 + 0x80) + 0x243558)) {
      uVar7 = 0x735d869e;
    }
  }
  lVar13 = FUN_7100bd09b0(DAT_710407a3f8);
  uVar5 = *(uint *)(lVar13 + 0x2c);
  iVar12 = 0;
  if (uVar5 == 0) {
LAB_71019cfb4c:
    if (iVar6 < iVar12) {
      return 0;
    }
  }
  else {
    uVar2 = 0;
    if (uVar5 != 0) {
      uVar2 = uVar7 / uVar5;
    }
    uVar2 = uVar7 - uVar2 * uVar5;
    uVar3 = uVar2;
    do {
      uVar1 = *(uint *)(*(long *)(lVar13 + 0x20) +
                       (-(ulong)(uVar3 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar3 << 4));
      if (uVar1 == uVar7) {
        lVar13 = *(long *)(*(long *)(lVar13 + 0x20) + (long)(int)uVar3 * 0x10 + 8);
        iVar12 = 0;
        if (lVar13 != 0) {
          iVar12 = *(int *)(lVar13 + 8);
        }
        goto LAB_71019cfb4c;
      }
      if (uVar1 == 0) break;
      uVar1 = 0;
      if ((int)(uVar3 + 1) < (int)uVar5) {
        uVar1 = uVar3 + 1;
      }
      uVar3 = uVar1;
    } while (uVar1 != uVar2);
    if (iVar6 < 0) {
      return 0;
    }
  }
  uVar7 = param_2[1];
  if (((int)uVar7 < 0) || (lVar13 = *(long *)(DAT_71040e7d48 + 2), lVar13 == 0)) {
LAB_71019cfbb4:
    puVar14 = &DAT_71040104d0;
  }
  else {
    if (*DAT_71040e7d48 <= uVar7) {
      uVar7 = 0;
    }
    if (*(uint *)(lVar13 + (ulong)uVar7 * 0x10 + 4) != *param_2) goto LAB_71019cfbb4;
    puVar8 = *(undefined8 **)(lVar13 + (ulong)uVar7 * 0x10 + 8);
    if (puVar8 == (undefined8 *)0x0) {
      puVar8 = FUN_7100baff84();
    }
    iVar6 = *(int *)((long)puVar8 + 0xac);
    lVar13 = (long)iVar6 + (long)puVar8 + 0xac;
    if (iVar6 == 0 || lVar13 == 0) goto LAB_71019cfbb4;
    puVar14 = (uint *)(lVar13 + 0x38);
  }
  local_48 = *puVar14;
  uVar7 = param_1[1];
  if ((-1 < (int)uVar7) && (lVar13 = *(long *)(DAT_71040e7d48 + 2), lVar13 != 0)) {
    if (*DAT_71040e7d48 <= uVar7) {
      uVar7 = 0;
    }
    if (*(int *)(lVar13 + (ulong)uVar7 * 0x10 + 4) == *param_1) {
      puVar8 = *(undefined8 **)(lVar13 + (ulong)uVar7 * 0x10 + 8);
      if (puVar8 == (undefined8 *)0x0) {
        puVar8 = FUN_7100baff84();
      }
      iVar6 = *(int *)(puVar8 + 0xf);
      lVar13 = (long)iVar6 + (long)(puVar8 + 0xf);
      if ((iVar6 != 0 && lVar13 != 0) && (bVar4 = FUN_7100e38cfc(lVar13,&local_48), bVar4)) {
        return 0;
      }
    }
  }
  uVar7 = param_2[1];
  if ((int)uVar7 < 0) {
LAB_71019cfca4:
    puVar8 = FUN_7100baff84();
    piVar9 = (int *)(puVar8 + 0x10);
    iVar6 = *piVar9;
  }
  else {
    lVar13 = *(long *)(DAT_71040e7d48 + 2);
    if (*DAT_71040e7d48 <= uVar7) {
      uVar7 = 0;
      if (lVar13 != 0) goto LAB_71019cfc48;
      goto LAB_71019cfca4;
    }
    if (lVar13 == 0) goto LAB_71019cfca4;
LAB_71019cfc48:
    lVar13 = lVar13 + (ulong)uVar7 * 0x10;
    if ((*(uint *)(lVar13 + 4) != *param_2) || (lVar13 = *(long *)(lVar13 + 8), lVar13 == 0))
    goto LAB_71019cfca4;
    piVar9 = (int *)(lVar13 + 0x80);
    iVar6 = *piVar9;
  }
  if ((iVar6 != 0) && (lVar13 = (long)iVar6 + (long)piVar9, lVar13 != 0)) {
    uVar7 = *(uint *)(lVar13 + 0x38);
    if ((uVar7 == 0xb6eede09) || (uVar7 == 0)) {
      FUN_7100df0120(DAT_710407a3f8);
    }
    else {
      lVar10 = FUN_7100df0120(DAT_710407a3f8);
      uVar5 = *(uint *)(lVar10 + 0x2c);
      if (uVar5 != 0) {
        uVar2 = 0;
        if (uVar5 != 0) {
          uVar2 = uVar7 / uVar5;
        }
        uVar2 = uVar7 - uVar2 * uVar5;
        uVar3 = uVar2;
        do {
          uVar1 = *(uint *)(*(long *)(lVar10 + 0x20) +
                           (-(ulong)(uVar3 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar3 << 4));
          if (uVar1 == uVar7) {
            lVar10 = *(long *)(*(long *)(lVar10 + 0x20) + (long)(int)uVar3 * 0x10 + 8);
            if ((lVar10 != 0) &&
               (uVar7 = FUN_7100bb2120(*(byte **)(lVar10 + 0x28),0), uVar7 == 0xf54cf52e)) {
              iVar6 = *(int *)(lVar13 + 0x3c);
              uVar7 = param_2[1];
              if (((int)uVar7 < 0) || (lVar13 = *(long *)(DAT_71040e7d48 + 2), lVar13 == 0)) {
LAB_71019cfdf4:
                piVar9 = &DAT_71040104d0;
              }
              else {
                if (*DAT_71040e7d48 <= uVar7) {
                  uVar7 = 0;
                }
                if (*(uint *)(lVar13 + (ulong)uVar7 * 0x10 + 4) != *param_2) goto LAB_71019cfdf4;
                puVar8 = *(undefined8 **)(lVar13 + (ulong)uVar7 * 0x10 + 8);
                if (puVar8 == (undefined8 *)0x0) {
                  puVar8 = FUN_7100baff84();
                }
                iVar12 = *(int *)((long)puVar8 + 0xac);
                lVar13 = (long)iVar12 + (long)puVar8 + 0xac;
                if (iVar12 == 0 || lVar13 == 0) goto LAB_71019cfdf4;
                piVar9 = (int *)(lVar13 + 0x38);
              }
              if (iVar6 == *piVar9) {
                return 0;
              }
            }
            break;
          }
          if (uVar1 == 0) break;
          uVar1 = 0;
          if ((int)(uVar3 + 1) < (int)uVar5) {
            uVar1 = uVar3 + 1;
          }
          uVar3 = uVar1;
        } while (uVar1 != uVar2);
      }
    }
  }
  uVar7 = param_1[1];
  if ((int)uVar7 < 0) {
LAB_71019cfe1c:
    puVar8 = FUN_7100baff84();
  }
  else {
    lVar13 = *(long *)(DAT_71040e7d48 + 2);
    if (*DAT_71040e7d48 <= uVar7) {
      uVar7 = 0;
      if (lVar13 != 0) goto LAB_71019cfcf8;
      goto LAB_71019cfe1c;
    }
    if (lVar13 == 0) goto LAB_71019cfe1c;
LAB_71019cfcf8:
    lVar13 = lVar13 + (ulong)uVar7 * 0x10;
    if ((*(int *)(lVar13 + 4) != *param_1) ||
       (puVar8 = *(undefined8 **)(lVar13 + 8), puVar8 == (undefined8 *)0x0)) goto LAB_71019cfe1c;
  }
  iVar6 = *(int *)(puVar8 + 0xf);
  if ((iVar6 == 0) ||
     (plVar11 = (long *)((long)iVar6 + (long)(puVar8 + 0xf)), plVar11 == (long *)0x0)) {
    plVar11 = FUN_7100bcff3c();
  }
  if (0x45 < *(uint *)(plVar11 + 5)) {
    return 1;
  }
  lVar13 = *(long *)(*(long *)(*DAT_7103a59c30 + 0x19a8d8) + (ulong)*(uint *)(plVar11 + 5) * 8 +
                    0x28);
  puVar14 = DAT_7103a59b30;
  if (lVar13 != 0) {
    puVar14 = (uint *)(lVar13 + 0x400);
  }
  local_48 = *puVar14;
  local_44 = puVar14[1];
  if (local_44 == param_2[1] && local_48 == *param_2) {
    return 1;
  }
  bVar4 = FUN_7100eec5a0(param_1,(int *)&local_48);
  if (bVar4) {
    return 1;
  }
  if (((int)local_44 < 0) || (lVar13 = *(long *)(DAT_71040e7d48 + 2), lVar13 == 0)) {
    uVar7 = param_2[1];
  }
  else {
    uVar7 = local_44;
    if (*DAT_71040e7d48 <= local_44) {
      uVar7 = 0;
    }
    if (*(uint *)(lVar13 + (ulong)uVar7 * 0x10 + 4) == local_48) {
      puVar8 = *(undefined8 **)(lVar13 + (ulong)uVar7 * 0x10 + 8);
      if (puVar8 == (undefined8 *)0x0) {
        puVar8 = FUN_7100baff84();
      }
      iVar6 = *(int *)((long)puVar8 + 0xac);
      if ((iVar6 != 0) && (lVar13 = (long)iVar6 + (long)puVar8 + 0xac, lVar13 != 0)) {
        lVar13 = (**(code **)(*(long *)(lVar13 + 0x4a0) + 0x20))(lVar13 + 0x4a0);
        iVar6 = *(int *)(lVar13 + 0x98);
        uVar7 = param_2[1];
        goto joined_r0x0071019cff18;
      }
    }
    uVar7 = param_2[1];
  }
  iVar6 = -1;
joined_r0x0071019cff18:
  if ((-1 < (int)uVar7) && (lVar13 = *(long *)(DAT_71040e7d48 + 2), lVar13 != 0)) {
    if (*DAT_71040e7d48 <= uVar7) {
      uVar7 = 0;
    }
    if (*(uint *)(lVar13 + (ulong)uVar7 * 0x10 + 4) == *param_2) {
      puVar8 = *(undefined8 **)(lVar13 + (ulong)uVar7 * 0x10 + 8);
      if (puVar8 == (undefined8 *)0x0) {
        puVar8 = FUN_7100baff84();
      }
      iVar12 = *(int *)((long)puVar8 + 0xac);
      if ((iVar12 != 0) && (lVar13 = (long)iVar12 + (long)puVar8 + 0xac, lVar13 != 0)) {
        lVar13 = (**(code **)(*(long *)(lVar13 + 0x4a0) + 0x20))(lVar13 + 0x4a0);
        if (iVar6 == *(int *)(lVar13 + 0x98)) {
          return 0;
        }
        return 1;
      }
    }
  }
  if (iVar6 == -1) {
    return 0;
  }
  return 1;
}



void FUN_71019d06c0(undefined4 *param_1)

{
  undefined4 uVar1;
  ulong uVar2;
  long lVar3;
  
  if (((DAT_7104054400 == 0) || ((*(byte *)(DAT_7104054400 + 0x4172a0) >> 1 & 1) != 0)) ||
     (DAT_71040e86a0 == 0)) {
    *param_1 = 4;
    return;
  }
  lVar3 = 0;
  if (*DAT_7103a5a7e8 != 0) {
    lVar3 = *(long *)(*DAT_7103a5a7e8 + 0xf0);
  }
  uVar2 = lVar3 - *(long *)(*(long *)(DAT_71040e86a0 + 0x80) + 0x243558);
  if ((long)uVar2 < 0x15180) {
    *param_1 = 0;
    return;
  }
  uVar2 = uVar2 >> 7;
  if (uVar2 < 0x7e9) {
    *param_1 = 1;
    return;
  }
  uVar1 = 2;
  if (0xd2e < uVar2) {
    uVar1 = 3;
  }
  *param_1 = uVar1;
  return;
}



void FUN_71019d0768(long *param_1,long *param_2,long *param_3,uint *param_4,undefined8 param_5,
                   undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  char *pcVar1;
  ulong uVar2;
  uint *puVar3;
  char local_60 [32];
  int local_24;
  
  puVar3 = param_4;
  uVar2 = FUN_71024fd620(param_1,local_60,&local_24);
  if ((uVar2 & 1) != 0) {
    puVar3 = (uint *)0xffffffff;
    pcVar1 = (undefined1 *)0x0;
    if (local_60[0] != '\0' && local_24 != 0) {
      pcVar1 = local_60;
    }
    FUN_71024fdf50((long)pcVar1,(long *)param_1[1],*param_2,0xffffffff,param_5,param_6,param_7,
                   param_8);
  }
  uVar2 = FUN_71024fd620(param_1,local_60,&local_24);
  if ((uVar2 & 1) != 0) {
    puVar3 = (uint *)0xffffffff;
    pcVar1 = (undefined1 *)0x0;
    if (local_60[0] != '\0' && local_24 != 0) {
      pcVar1 = local_60;
    }
    FUN_71024fdf50((long)pcVar1,(long *)param_1[1],*param_3,0xffffffff,param_5,param_6,param_7,
                   param_8);
  }
  uVar2 = FUN_71024fd620(param_1,local_60,&local_24);
  if ((uVar2 & 1) != 0) {
    pcVar1 = (char *)0x0;
    if (local_60[0] != '\0' && local_24 != 0) {
      pcVar1 = local_60;
    }
    FUN_71019d0860(param_4,pcVar1,(long *)param_1[1],puVar3,param_5,param_6,param_7,param_8);
  }
  return;
}



void FUN_71019d0860(uint *param_1,char *param_2,long *param_3,undefined8 param_4,undefined8 param_5,
                   undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  uint uVar1;
  long lVar2;
  uint uVar3;
  undefined **ppuVar4;
  undefined **ppuVar5;
  char *pcVar6;
  undefined **ppuVar7;
  long lVar8;
  ulong uVar9;
  ulong uVar10;
  char *pcVar11;
  undefined *local_50;
  int local_48;
  undefined local_44 [8];
  undefined1 auStack_3c [23];
  undefined1 local_25;
  
  ppuVar4 = &local_50;
  ppuVar7 = &local_50;
  ppuVar5 = &local_50;
  if (param_2 == (char *)0x0) {
    (**(code **)(*param_3 + 0x10))(param_3,&DAT_71030f9bfa,1);
    uVar3 = *param_1;
    if ((int)uVar3 < 0) {
      ppuVar4 = (undefined **)((ulong)&local_50 | 1);
      local_50 = (undefined *)CONCAT71(local_50._1_7_,0x2d);
      uVar3 = -uVar3;
    }
    if (((9 < (long)(auStack_3c + -(long)ppuVar4)) ||
        (uVar1 = (uint)((0x20 - (int)LZCOUNT(uVar3 | 1)) * 0x4d1) >> 0xc,
        (long)(ulong)((uVar1 - (uVar3 < *(uint *)(&DAT_71032ac43c + (ulong)uVar1 * 4))) + 1) <=
        (long)(auStack_3c + -(long)ppuVar4))) &&
       (pcVar6 = FUN_7100f613e0((char *)ppuVar4,uVar3), pcVar6 != (char *)0x0)) {
      (**(code **)(*param_3 + 0x10))(param_3,&local_50,(int)pcVar6 - (int)&local_50);
    }
    (**(code **)(*param_3 + 0x10))(param_3,&DAT_71031313e0,2);
    lVar8 = *param_3;
    ppuVar7 = (undefined **)&DAT_71030cb711;
    uVar3 = 2;
    goto LAB_71019d0a08;
  }
  if (*param_2 == '\0') {
LAB_71019d09a4:
    pcVar6 = "";
  }
  else {
    lVar8 = 0;
    do {
      pcVar6 = DAT_7103a59fe0;
      if (lVar8 == 0x400000) goto LAB_71019d09ac;
      if (param_2[lVar8 + 1] == '\0') {
        lVar8 = lVar8 + 1;
        break;
      }
      lVar2 = lVar8 + 2;
      lVar8 = lVar8 + 2;
    } while (param_2[lVar2] != '\0');
    uVar3 = (int)lVar8 - 1;
    uVar9 = (ulong)uVar3;
    if (0x400000 < uVar3) goto LAB_71019d09a4;
    uVar10 = uVar9;
    pcVar11 = param_2;
    if (uVar3 == 0) {
      uVar9 = 0;
    }
    else {
      do {
        if (*pcVar11 == '\0') goto LAB_71019d09ac;
        uVar10 = uVar10 - 1;
        pcVar11 = pcVar11 + 1;
      } while (uVar10 != 0);
    }
    pcVar6 = param_2 + uVar9;
  }
LAB_71019d09ac:
  if ((*pcVar6 == 'x') || (*pcVar6 == 'd')) {
    local_50 = local_44;
    local_25 = 0;
    local_44[0] = 0;
    local_48 = 0x20;
    uVar3 = FUN_7100bc08f0((long *)&local_50,param_2,(ulong)*param_1,param_4,param_5,param_6,param_7
                           ,param_8);
    local_50[(long)local_48 + -1] = 0;
    lVar8 = *param_3;
    ppuVar7 = (undefined **)local_50;
  }
  else {
    uVar3 = *param_1;
    if ((int)uVar3 < 0) {
      ppuVar5 = (undefined **)((ulong)&local_50 | 1);
      local_50 = (undefined *)CONCAT71(local_50._1_7_,0x2d);
      uVar3 = -uVar3;
    }
    if (((long)(auStack_3c + -(long)ppuVar5) < 10) &&
       (uVar1 = (uint)((0x20 - (int)LZCOUNT(uVar3 | 1)) * 0x4d1) >> 0xc,
       (long)(auStack_3c + -(long)ppuVar5) <
       (long)(ulong)((uVar1 - (uVar3 < *(uint *)(&DAT_71032ac43c + (ulong)uVar1 * 4))) + 1))) {
      return;
    }
    pcVar6 = FUN_7100f613e0((char *)ppuVar5,uVar3);
    if (pcVar6 == (char *)0x0) {
      return;
    }
    uVar3 = (int)pcVar6 - (int)&local_50;
    lVar8 = *param_3;
  }
LAB_71019d0a08:
  (**(code **)(lVar8 + 0x10))(param_3,ppuVar7,uVar3);
  return;
}



int FUN_71019d0ae0(uint *param_1,int *param_2,int *param_3)

{
  int iVar1;
  int iVar2;
  ulong uVar3;
  undefined8 *puVar4;
  undefined8 *puVar5;
  long *plVar6;
  uint uVar7;
  long lVar8;
  uint local_40;
  uint local_3c;
  uint local_38;
  uint local_34;
  
  local_34 = *param_1;
  uVar3 = FUN_71019e45c0(param_2,(int *)&local_34);
  if ((uVar3 & 1) != 0) {
    return -1;
  }
  local_38 = *param_1;
  uVar3 = FUN_71019e45c0(param_3,(int *)&local_38);
  puVar5 = DAT_7103a59c40;
  if ((uVar3 & 1) != 0) {
    return 1;
  }
  local_3c = *param_1;
  uVar7 = param_2[1];
  if ((int)uVar7 < 0) {
LAB_71019d0b9c:
    puVar4 = FUN_7100baff84();
  }
  else {
    lVar8 = *(long *)((uint *)*DAT_7103a59c40 + 2);
    if (*(uint *)*DAT_7103a59c40 <= uVar7) {
      uVar7 = 0;
      if (lVar8 != 0) goto LAB_71019d0b70;
      goto LAB_71019d0b9c;
    }
    if (lVar8 == 0) goto LAB_71019d0b9c;
LAB_71019d0b70:
    lVar8 = lVar8 + (ulong)uVar7 * 0x10;
    if ((*(int *)(lVar8 + 4) != *param_2) ||
       (puVar4 = *(undefined8 **)(lVar8 + 8), puVar4 == (undefined8 *)0x0)) goto LAB_71019d0b9c;
  }
  iVar1 = *(int *)(puVar4 + 0xf);
  if ((iVar1 == 0) || (plVar6 = (long *)((long)iVar1 + (long)(puVar4 + 0xf)), plVar6 == (long *)0x0)
     ) {
    plVar6 = FUN_7100bcff3c();
  }
  iVar1 = FUN_7100e36ce4((long)plVar6,&local_3c);
  local_40 = *param_1;
  uVar7 = param_3[1];
  if (-1 < (int)uVar7) {
    lVar8 = *(long *)((uint *)*puVar5 + 2);
    if (*(uint *)*puVar5 <= uVar7) {
      uVar7 = 0;
    }
    if (((lVar8 != 0) && (lVar8 = lVar8 + (ulong)uVar7 * 0x10, *(int *)(lVar8 + 4) == *param_3)) &&
       (puVar5 = *(undefined8 **)(lVar8 + 8), puVar5 != (undefined8 *)0x0)) goto LAB_71019d0c1c;
  }
  puVar5 = FUN_7100baff84();
LAB_71019d0c1c:
  iVar2 = *(int *)(puVar5 + 0xf);
  if ((iVar2 == 0) || (plVar6 = (long *)((long)iVar2 + (long)(puVar5 + 0xf)), plVar6 == (long *)0x0)
     ) {
    plVar6 = FUN_7100bcff3c();
  }
  iVar2 = FUN_7100e36ce4((long)plVar6,&local_40);
  return iVar2 - iVar1;
}



void FUN_71019d0c60(long *param_1,long *param_2,long *param_3,undefined8 param_4,undefined8 param_5,
                   undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  long lVar1;
  ulong uVar2;
  long *plVar3;
  long lVar4;
  long lVar5;
  char *pcVar6;
  int local_54;
  char local_50 [32];
  
  uVar2 = FUN_71024fd620(param_1,local_50,&local_54);
  if ((uVar2 & 1) != 0) {
    pcVar6 = (char *)0x0;
    if (local_50[0] != '\0' && local_54 != 0) {
      pcVar6 = local_50;
    }
    FUN_71024fdf50((long)pcVar6,(long *)param_1[1],*param_2,0xffffffff,param_5,param_6,param_7,
                   param_8);
  }
  uVar2 = FUN_71024fd620(param_1,local_50,&local_54);
  if ((uVar2 & 1) != 0) {
    plVar3 = (long *)param_1[1];
    *(undefined1 *)((long)(int)param_3[1] + *param_3 + -1) = 0;
    lVar4 = *param_3;
    *(undefined1 *)((int)param_3[1] + lVar4 + -1) = 0;
    pcVar6 = (char *)*param_3;
    if ((pcVar6 == (char *)0x0) || (*pcVar6 == '\0')) {
LAB_71019d0d28:
      lVar5 = 0;
    }
    else {
      lVar5 = 0;
      do {
        if (lVar5 == 0x400000) goto LAB_71019d0d28;
        if (pcVar6[lVar5 + 1] == '\0') {
          lVar5 = lVar5 + 1;
          break;
        }
        lVar1 = lVar5 + 2;
        lVar5 = lVar5 + 2;
      } while (pcVar6[lVar1] != '\0');
    }
    (**(code **)(*plVar3 + 0x10))(plVar3,lVar4,lVar5);
  }
  return;
}



undefined8 * FUN_71019d0fc0(long param_1,long *param_2)

{
  undefined8 *puVar1;
  long lVar2;
  long *plVar3;
  undefined8 *puVar4;
  long *plVar5;
  long lVar6;
  long *local_40;
  undefined8 uStack_38;
  
  plVar5 = DAT_7103a65db8;
  lVar6 = *DAT_7103a65db8;
  if (lVar6 == 0) {
    puVar4 = (undefined8 *)FUN_71005fbcb0(8,0x18);
  }
  else {
    plVar3 = param_2;
    if (param_2 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      plVar3 = (long *)(lVar6 + 8);
      if (lVar2 != 0) {
        plVar3 = (long *)(lVar2 + 0x88);
      }
      plVar3 = (long *)*plVar3;
      if (plVar3 == (long *)0x0) {
        puVar4 = (undefined8 *)0x0;
        goto LAB_71019d1048;
      }
    }
    puVar4 = (undefined8 *)(**(code **)(*plVar3 + 0x30))(plVar3,0x18,8);
  }
LAB_71019d1048:
  *(undefined4 *)(puVar4 + 1) = 0;
  puVar4[2] = 0;
  *puVar4 = &DAT_7103a296b0;
  uStack_38 = *(undefined8 *)(param_1 + 8);
  lVar6 = *plVar5;
  local_40 = param_2;
  if (lVar6 == 0) {
    plVar5 = (long *)FUN_71005fbcb0(8,0x88);
  }
  else {
    if (param_2 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar1 = (undefined8 *)(lVar6 + 8);
      if (lVar2 != 0) {
        puVar1 = (undefined8 *)(lVar2 + 0x88);
      }
      param_2 = (long *)*puVar1;
    }
    plVar5 = (long *)(**(code **)(*param_2 + 0x30))(param_2,0x88,8);
  }
  lVar6 = DAT_7103a72cd8;
  plVar5[2] = 0;
  plVar5[3] = 0;
  plVar5[4] = 0;
  plVar5[5] = 0;
  plVar5[0x10] = 0;
  plVar5[6] = 0;
  plVar5[7] = 0;
  plVar5[8] = 0;
  plVar5[9] = 0;
  plVar5[10] = 0;
  plVar5[0xb] = 0;
  *plVar5 = lVar6 + 0x10;
  plVar5[1] = 0;
  plVar5[0xc] = 0;
  plVar5[0xd] = 0;
  plVar5[0xe] = 0;
  plVar5[0xf] = 0;
  puVar4[2] = plVar5;
  FUN_71029a5d90((long)plVar5,(long *)&local_40);
  *(uint *)(puVar4 + 1) = *(uint *)(puVar4 + 1) | 1;
  return puVar4;
}



void FUN_71019d1130(uint *param_1)

{
  undefined4 *puVar1;
  long *plVar2;
  uint uVar3;
  int iVar4;
  long lVar5;
  long lVar6;
  undefined4 *puVar7;
  long lVar8;
  
  uVar3 = *param_1;
  lVar6 = *(long *)(DAT_71040e86a0 + 0x88);
  thunk_EXT_FUN_02e95df0(lVar6 + 0x11a428);
  if ((DAT_71040e86a0 != 0) && (*(int *)(DAT_71040e86a0 + 0x944) == 1)) {
    iVar4 = *(int *)(DAT_71040e86a0 + 0x948);
    if (*(int *)(lVar6 + 0x11a400) != iVar4) {
      lVar8 = 0x65;
      puVar7 = (undefined4 *)(lVar6 + 0x10a09c);
      lVar5 = lVar6 + 0xf9810;
      do {
        FUN_7100bb7ab0((long)(puVar7 + -0xa5),lVar5);
        lVar8 = lVar8 + -1;
        puVar7[-2] = *(undefined4 *)(lVar5 + 0x28c);
        puVar7[-1] = *(undefined4 *)(lVar5 + 0x290);
        puVar1 = (undefined4 *)(lVar5 + 0x294);
        lVar5 = lVar5 + 0x298;
        *puVar7 = *puVar1;
        puVar7 = puVar7 + 0xa6;
      } while (lVar8 != 0);
      *(int *)(lVar6 + 0x11a400) = iVar4;
    }
  }
  thunk_EXT_FUN_02e95df0(lVar6 + 0x11a428);
  plVar2 = (long *)(lVar6 + 0xf9810) + (ulong)uVar3 * 0x53;
  if (100 < uVar3) {
    plVar2 = (long *)(lVar6 + 0xf9810);
  }
                    // WARNING: Could not recover jumptable at 0x0071019d1224. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*plVar2 + 0x10))();
  return;
}



long * FUN_71019d1340(long *param_1,undefined4 param_2)

{
  undefined8 *puVar1;
  long lVar2;
  long *plVar3;
  long *plVar4;
  long lVar5;
  
  lVar5 = *DAT_7103a65db8;
  if (lVar5 == 0) {
    plVar3 = (long *)FUN_71005fbcb0(8,0x120);
  }
  else {
    plVar3 = param_1;
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar1 = (undefined8 *)(lVar5 + 8);
      if (lVar2 != 0) {
        puVar1 = (undefined8 *)(lVar2 + 0x88);
      }
      plVar3 = (long *)*puVar1;
      if (plVar3 == (long *)0x0) {
        plVar3 = (long *)0x0;
        goto LAB_71019d13c4;
      }
    }
    plVar3 = (long *)(**(code **)(*plVar3 + 0x30))(plVar3,0x120,8);
  }
LAB_71019d13c4:
  *(undefined2 *)(plVar3 + 1) = 0;
  lVar5 = DAT_7103a65b60;
  *(undefined8 *)((long)plVar3 + 0xc) = 0xffffffffffffffff;
  *(undefined1 *)((long)plVar3 + 10) = 0;
  plVar3[0xe] = 0;
  plVar3[0xd] = (long)(plVar3 + 0xe);
  *(undefined2 *)((long)plVar3 + 0x14) = 0;
  plVar3[0xc] = (long)(plVar3 + 0xd);
  *plVar3 = lVar5 + 0x10;
  plVar3[0xb] = (long)(plVar3 + 0xc);
  plVar3[3] = -0xc0800000;
  plVar3[10] = (long)(plVar3 + 0xb);
  *(undefined4 *)(plVar3 + 4) = 0xffffffff;
  plVar4 = plVar3 + 9;
  *plVar4 = (long)(plVar3 + 10);
  plVar3[5] = 0;
  plVar3[6] = 0;
  plVar3[7] = (long)plVar4;
  plVar3[8] = (long)plVar4;
  if (plVar3 + 0xf != (long *)0x0) {
    plVar3[6] = (long)(plVar3 + 0xf);
    *(undefined4 *)((long)plVar3 + 0x2c) = 6;
  }
  *(undefined4 *)(plVar3 + 0x15) = 0;
  plVar3[0x16] = 0;
  plVar3[0x17] = 0;
  *(undefined1 *)(plVar3 + 0x1a) = 1;
  *(undefined4 *)((long)plVar3 + 0xd4) = 0;
  *(undefined1 *)(plVar3 + 0x1b) = 0;
  *(undefined4 *)(plVar3 + 0x1e) = param_2;
  plVar3[0x18] = 0;
  plVar3[0x19] = 0;
  plVar3[0x1c] = 0;
  plVar3[0x1d] = 0;
  lVar5 = DAT_7103a65c00 + 0x10;
  *(undefined4 *)(plVar3 + 0x23) = 0xffffffff;
  *plVar3 = lVar5;
  plVar3[0x1f] = 0;
  plVar3[0x20] = 0;
  plVar3[0x21] = 0;
  plVar3[0x22] = 0;
  FUN_71019745e0(plVar3,param_1);
  return plVar3;
}



long * FUN_71019d14b0(long *param_1)

{
  undefined8 *puVar1;
  long lVar2;
  long *plVar3;
  long *plVar4;
  undefined2 *puVar5;
  long lVar6;
  
  lVar6 = *DAT_7103a65db8;
  if (lVar6 == 0) {
    plVar3 = (long *)FUN_71005fbcb0(8,0xe218);
  }
  else {
    plVar3 = param_1;
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar1 = (undefined8 *)(lVar6 + 8);
      if (lVar2 != 0) {
        puVar1 = (undefined8 *)(lVar2 + 0x88);
      }
      plVar3 = (long *)*puVar1;
      if (plVar3 == (long *)0x0) {
        plVar3 = (long *)0x0;
        goto LAB_71019d1530;
      }
    }
    plVar3 = (long *)(**(code **)(*plVar3 + 0x30))(plVar3,0xe218,8);
  }
LAB_71019d1530:
  thunk_EXT_FUN_02e95df0(plVar3 + 1,0,0xe210);
  plVar3[0xd] = (long)(plVar3 + 0xe);
  plVar3[0xc] = (long)(plVar3 + 0xd);
  plVar3[3] = -0xc0800000;
  plVar3[0xb] = (long)(plVar3 + 0xc);
  lVar6 = DAT_7103a65b60;
  *(undefined8 *)((long)plVar3 + 0xc) = 0xffffffffffffffff;
  plVar3[5] = 0;
  plVar3[6] = 0;
  *plVar3 = lVar6 + 0x10;
  *(undefined4 *)(plVar3 + 4) = 0xffffffff;
  plVar3[10] = (long)(plVar3 + 0xb);
  plVar4 = plVar3 + 9;
  *plVar4 = (long)(plVar3 + 10);
  plVar3[7] = (long)plVar4;
  plVar3[8] = (long)plVar4;
  if (plVar3 + 0xf != (long *)0x0) {
    plVar3[6] = (long)(plVar3 + 0xf);
    *(undefined4 *)((long)plVar3 + 0x2c) = 6;
  }
  *(undefined4 *)(plVar3 + 0x15) = 0;
  *(undefined1 *)(plVar3 + 0x1a) = 1;
  lVar6 = 300;
  plVar3[0x16] = 0;
  plVar3[0x17] = 0;
  *(undefined4 *)((long)plVar3 + 0xd4) = 0;
  *(undefined1 *)(plVar3 + 0x1b) = 0;
  plVar3[0x18] = 0;
  plVar3[0x19] = 0;
  plVar3[0x1c] = 0;
  plVar3[0x1d] = 0;
  lVar2 = 0;
  do {
    lVar6 = lVar6 + -1;
    puVar5 = (undefined2 *)((long)plVar3 + lVar2 + 0xfc);
    *puVar5 = 0;
    *(undefined2 **)((long)plVar3 + lVar2 + 0xf0) = puVar5;
    *(undefined4 *)((long)plVar3 + lVar2 + 0xf8) = 0x20;
    puVar5 = (undefined2 *)((long)plVar3 + lVar2 + 0x14c);
    *puVar5 = 0;
    *(undefined2 *)((long)plVar3 + lVar2 + 0x13a) = 0;
    *(undefined2 **)((long)plVar3 + lVar2 + 0x140) = puVar5;
    *(undefined4 *)((long)plVar3 + lVar2 + 0x148) = 0x20;
    *(undefined2 *)((long)plVar3 + lVar2 + 0x18a) = 0;
    lVar2 = lVar2 + 0xa0;
  } while (lVar6 != 0);
  plVar3[0x1790] = 0;
  plVar3[0x1791] = 0;
  *(undefined4 *)((long)plVar3 + 0xbc8c) = 300;
  plVar4 = plVar3 + 0x179a;
  plVar3[0x178e] = 0;
  plVar3[0x178f] = 0;
  plVar3[0x178f] = (long)(plVar3 + 0x1792);
  for (lVar6 = 0x12a; plVar4[-8] = (long)(plVar4 + -4), lVar6 != 0; lVar6 = lVar6 + -2) {
    plVar4[-4] = (long)plVar4;
    plVar4 = plVar4 + 8;
  }
  plVar3[0x1c3e] = 0;
  plVar3[0x1790] = (long)(plVar3 + 0x1792);
  *plVar3 = (long)&DAT_710398bf98;
  plVar3[0x1c42] = -1;
  FUN_710196d370(plVar3,param_1);
  return plVar3;
}



long * FUN_71019d16b0(long *param_1)

{
  undefined8 *puVar1;
  long lVar2;
  long *plVar3;
  long *plVar4;
  undefined2 *puVar5;
  long lVar6;
  
  lVar6 = *DAT_7103a65db8;
  if (lVar6 == 0) {
    plVar3 = (long *)FUN_71005fbcb0(8,0x280f8);
  }
  else {
    plVar3 = param_1;
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar1 = (undefined8 *)(lVar6 + 8);
      if (lVar2 != 0) {
        puVar1 = (undefined8 *)(lVar2 + 0x88);
      }
      plVar3 = (long *)*puVar1;
    }
    plVar3 = (long *)(**(code **)(*plVar3 + 0x30))(plVar3,0x280f8,8);
  }
  *(undefined2 *)(plVar3 + 1) = 0;
  lVar6 = DAT_7103a65b60;
  *(undefined8 *)((long)plVar3 + 0xc) = 0xffffffffffffffff;
  plVar3[0xe] = 0;
  plVar3[0xd] = (long)(plVar3 + 0xe);
  *(undefined1 *)((long)plVar3 + 10) = 0;
  plVar3[0xc] = (long)(plVar3 + 0xd);
  *plVar3 = lVar6 + 0x10;
  plVar3[0xb] = (long)(plVar3 + 0xc);
  plVar3[3] = -0xc0800000;
  plVar3[10] = (long)(plVar3 + 0xb);
  *(undefined2 *)((long)plVar3 + 0x14) = 0;
  plVar4 = plVar3 + 9;
  *plVar4 = (long)(plVar3 + 10);
  *(undefined4 *)(plVar3 + 4) = 0xffffffff;
  plVar3[5] = 0;
  plVar3[6] = 0;
  plVar3[7] = (long)plVar4;
  plVar3[8] = (long)plVar4;
  if (plVar3 + 0xf != (long *)0x0) {
    plVar3[6] = (long)(plVar3 + 0xf);
    *(undefined4 *)((long)plVar3 + 0x2c) = 6;
  }
  *(undefined4 *)(plVar3 + 0x15) = 0;
  *(undefined1 *)(plVar3 + 0x1a) = 1;
  *plVar3 = (long)&DAT_710398c238;
  plVar3[0x16] = 0;
  plVar3[0x17] = 0;
  *(undefined4 *)((long)plVar3 + 0xd4) = 0;
  *(undefined1 *)(plVar3 + 0x1b) = 0;
  plVar3[0x18] = 0;
  plVar3[0x19] = 0;
  plVar3[0x1c] = 0;
  plVar3[0x1d] = 0;
  lVar6 = 0;
  do {
    lVar2 = lVar6 + 0xa0;
    puVar5 = (undefined2 *)((long)plVar3 + lVar6 + 0xfc);
    *puVar5 = 0;
    *(undefined2 **)((long)plVar3 + lVar6 + 0xf0) = puVar5;
    *(undefined4 *)((long)plVar3 + lVar6 + 0xf8) = 0x20;
    puVar5 = (undefined2 *)((long)plVar3 + lVar6 + 0x14c);
    *puVar5 = 0;
    *(undefined2 *)((long)plVar3 + lVar6 + 0x13a) = 0;
    *(undefined2 **)((long)plVar3 + lVar6 + 0x140) = puVar5;
    *(undefined4 *)((long)plVar3 + lVar6 + 0x148) = 0x20;
    *(undefined2 *)((long)plVar3 + lVar6 + 0x18a) = 0;
    lVar6 = lVar2;
  } while (lVar2 != 0x28000);
  *(undefined4 *)(plVar3 + 0x501e) = 0xffffffff;
  FUN_710196d370(plVar3,param_1);
  return plVar3;
}



long * FUN_71019d1850(long *param_1,undefined4 param_2,int param_3)

{
  undefined8 *puVar1;
  long lVar2;
  long *plVar3;
  long *plVar4;
  long lVar5;
  
  if (param_3 == 0) {
    lVar5 = *DAT_7103a65db8;
    if (lVar5 == 0) {
      plVar3 = (long *)FUN_71005fbcb0(8,0x12150);
    }
    else {
      plVar3 = param_1;
      if (param_1 == (long *)0x0) {
        lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
        puVar1 = (undefined8 *)(lVar5 + 8);
        if (lVar2 != 0) {
          puVar1 = (undefined8 *)(lVar2 + 0x88);
        }
        plVar3 = (long *)*puVar1;
      }
      plVar3 = (long *)(**(code **)(*plVar3 + 0x30))(plVar3,0x12150,8);
    }
    lVar5 = DAT_7103a65b60;
    *(undefined8 *)((long)plVar3 + 0xc) = 0xffffffffffffffff;
    plVar3[0xe] = 0;
    plVar3[0xd] = (long)(plVar3 + 0xe);
    *(undefined2 *)(plVar3 + 1) = 0;
    plVar3[0xc] = (long)(plVar3 + 0xd);
    *plVar3 = lVar5 + 0x10;
    plVar3[3] = -0xc0800000;
    *(undefined4 *)(plVar3 + 4) = 0xffffffff;
    plVar3[0xb] = (long)(plVar3 + 0xc);
    *(undefined1 *)((long)plVar3 + 10) = 0;
    plVar3[10] = (long)(plVar3 + 0xb);
    *(undefined2 *)((long)plVar3 + 0x14) = 0;
    plVar4 = plVar3 + 9;
    *plVar4 = (long)(plVar3 + 10);
    plVar3[5] = 0;
    plVar3[6] = 0;
    plVar3[7] = (long)plVar4;
    plVar3[8] = (long)plVar4;
    if (plVar3 + 0xf != (long *)0x0) {
      plVar3[6] = (long)(plVar3 + 0xf);
      *(undefined4 *)((long)plVar3 + 0x2c) = 6;
    }
    *(undefined4 *)(plVar3 + 0x15) = 0;
    plVar3[0x16] = 0;
    plVar3[0x17] = 0;
    lVar5 = 0x17e;
    *(undefined1 *)(plVar3 + 0x1a) = 1;
    *(undefined4 *)((long)plVar3 + 0xd4) = 0;
    *(undefined1 *)(plVar3 + 0x1b) = 0;
    *(undefined4 *)(plVar3 + 0x1e) = param_2;
    *(undefined4 *)(plVar3 + 0x21) = 0;
    *(undefined1 *)((long)plVar3 + 0x10c) = 0;
    *(undefined4 *)(plVar3 + 0x22) = 0;
    plVar3[0x23] = 0;
    *(undefined4 *)(plVar3 + 0x24) = 0;
    *(undefined1 *)((long)plVar3 + 0x124) = 0;
    plVar3[0x18] = 0;
    plVar3[0x19] = 0;
    plVar3[0x1c] = 0;
    plVar3[0x1d] = 0;
    plVar3[0x1f] = DAT_7103a65e88 + 0x10;
    plVar3[0x20] = 0;
    plVar3[0x27] = 0;
    plVar3[0x28] = 0;
    *(undefined4 *)((long)plVar3 + 0x144) = 0x180;
    plVar3[0x25] = 0;
    plVar3[0x26] = (long)(plVar3 + 0x29);
    plVar3[0x29] = (long)(plVar3 + 0x41);
    plVar4 = plVar3 + 0x41;
    do {
      lVar5 = lVar5 + -2;
      *plVar4 = (long)(plVar4 + 0x18);
      plVar4[0x18] = (long)(plVar4 + 0x30);
      plVar4 = plVar4 + 0x30;
    } while (lVar5 != 0);
    plVar3[0x27] = (long)(plVar3 + 0x29);
    *plVar3 = (long)&DAT_710398baa8;
    plVar3[0x2411] = 0;
    *(undefined1 *)(plVar3 + 0x2429) = 1;
  }
  else {
    lVar5 = *DAT_7103a65db8;
    if (lVar5 == 0) {
      plVar3 = (long *)FUN_71005fbcb0(8,0x12150);
    }
    else {
      plVar3 = param_1;
      if (param_1 == (long *)0x0) {
        lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
        puVar1 = (undefined8 *)(lVar5 + 8);
        if (lVar2 != 0) {
          puVar1 = (undefined8 *)(lVar2 + 0x88);
        }
        plVar3 = (long *)*puVar1;
      }
      plVar3 = (long *)(**(code **)(*plVar3 + 0x30))(plVar3,0x12150,8);
    }
    lVar5 = DAT_7103a65b60;
    *(undefined8 *)((long)plVar3 + 0xc) = 0xffffffffffffffff;
    plVar3[0xe] = 0;
    plVar3[0xd] = (long)(plVar3 + 0xe);
    *(undefined2 *)(plVar3 + 1) = 0;
    plVar3[0xc] = (long)(plVar3 + 0xd);
    *plVar3 = lVar5 + 0x10;
    plVar3[3] = -0xc0800000;
    *(undefined4 *)(plVar3 + 4) = 0xffffffff;
    plVar3[0xb] = (long)(plVar3 + 0xc);
    *(undefined1 *)((long)plVar3 + 10) = 0;
    plVar3[10] = (long)(plVar3 + 0xb);
    *(undefined2 *)((long)plVar3 + 0x14) = 0;
    plVar4 = plVar3 + 9;
    *plVar4 = (long)(plVar3 + 10);
    plVar3[5] = 0;
    plVar3[6] = 0;
    plVar3[7] = (long)plVar4;
    plVar3[8] = (long)plVar4;
    if (plVar3 + 0xf != (long *)0x0) {
      plVar3[6] = (long)(plVar3 + 0xf);
      *(undefined4 *)((long)plVar3 + 0x2c) = 6;
    }
    *(undefined4 *)(plVar3 + 0x15) = 0;
    *(undefined1 *)(plVar3 + 0x1a) = 1;
    lVar5 = 0x17e;
    plVar3[0x16] = 0;
    plVar3[0x17] = 0;
    *(undefined4 *)((long)plVar3 + 0xd4) = 0;
    *(undefined1 *)(plVar3 + 0x1b) = 0;
    *(undefined4 *)(plVar3 + 0x1e) = 2;
    *(undefined4 *)(plVar3 + 0x21) = 0;
    *(undefined1 *)((long)plVar3 + 0x10c) = 0;
    *(undefined4 *)(plVar3 + 0x22) = 0;
    plVar3[0x23] = 0;
    *(undefined4 *)(plVar3 + 0x24) = 0;
    *(undefined1 *)((long)plVar3 + 0x124) = 0;
    plVar3[0x18] = 0;
    plVar3[0x19] = 0;
    plVar3[0x1c] = 0;
    plVar3[0x1d] = 0;
    plVar3[0x1f] = DAT_7103a65e88 + 0x10;
    plVar3[0x20] = 0;
    plVar3[0x27] = 0;
    plVar3[0x28] = 0;
    *(undefined4 *)((long)plVar3 + 0x144) = 0x180;
    plVar3[0x25] = 0;
    plVar3[0x26] = (long)(plVar3 + 0x29);
    plVar3[0x29] = (long)(plVar3 + 0x41);
    plVar4 = plVar3 + 0x41;
    do {
      lVar5 = lVar5 + -2;
      *plVar4 = (long)(plVar4 + 0x18);
      plVar4[0x18] = (long)(plVar4 + 0x30);
      plVar4 = plVar4 + 0x30;
    } while (lVar5 != 0);
    plVar3[0x27] = (long)(plVar3 + 0x29);
    plVar3[0x2411] = 0;
    *(undefined1 *)(plVar3 + 0x2429) = 1;
    *plVar3 = (long)&DAT_710398bd20;
    *(int *)((long)plVar3 + 0x1214c) = param_3;
  }
  FUN_710196d370(plVar3,param_1);
  return plVar3;
}



long * FUN_71019d2550(long *param_1)

{
  undefined8 *puVar1;
  long lVar2;
  long *plVar3;
  long *plVar4;
  undefined2 *puVar5;
  long lVar6;
  
  lVar6 = *DAT_7103a65db8;
  if (lVar6 == 0) {
    plVar3 = (long *)FUN_71005fbcb0(8,0xbc70);
  }
  else {
    plVar3 = param_1;
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar1 = (undefined8 *)(lVar6 + 8);
      if (lVar2 != 0) {
        puVar1 = (undefined8 *)(lVar2 + 0x88);
      }
      plVar3 = (long *)*puVar1;
      if (plVar3 == (long *)0x0) {
        plVar3 = (long *)0x0;
        goto LAB_71019d25cc;
      }
    }
    plVar3 = (long *)(**(code **)(*plVar3 + 0x30))(plVar3,0xbc70,8);
  }
LAB_71019d25cc:
  thunk_EXT_FUN_02e95df0(plVar3 + 1,0,0xbc68);
  plVar3[0xd] = (long)(plVar3 + 0xe);
  plVar3[0xc] = (long)(plVar3 + 0xd);
  *(undefined8 *)((long)plVar3 + 0xc) = 0xffffffffffffffff;
  plVar3[0xb] = (long)(plVar3 + 0xc);
  plVar3[3] = -0xc0800000;
  plVar3[5] = 0;
  plVar3[6] = 0;
  *plVar3 = (long)&DAT_7103987b08;
  *(undefined4 *)(plVar3 + 4) = 0xffffffff;
  plVar3[10] = (long)(plVar3 + 0xb);
  plVar4 = plVar3 + 9;
  *plVar4 = (long)(plVar3 + 10);
  plVar3[7] = (long)plVar4;
  plVar3[8] = (long)plVar4;
  if (plVar3 + 0xf != (long *)0x0) {
    plVar3[6] = (long)(plVar3 + 0xf);
    *(undefined4 *)((long)plVar3 + 0x2c) = 6;
  }
  *(undefined4 *)(plVar3 + 0x15) = 0;
  *(undefined1 *)(plVar3 + 0x1a) = 1;
  lVar6 = 300;
  plVar3[0x16] = 0;
  plVar3[0x17] = 0;
  *(undefined4 *)((long)plVar3 + 0xd4) = 0;
  *(undefined1 *)(plVar3 + 0x1b) = 0;
  plVar3[0x18] = 0;
  plVar3[0x19] = 0;
  plVar3[0x1c] = 0;
  plVar3[0x1d] = 0;
  lVar2 = 0;
  do {
    lVar6 = lVar6 + -1;
    puVar5 = (undefined2 *)((long)plVar3 + lVar2 + 0xfc);
    *puVar5 = 0;
    *(undefined2 **)((long)plVar3 + lVar2 + 0xf0) = puVar5;
    *(undefined4 *)((long)plVar3 + lVar2 + 0xf8) = 0x20;
    puVar5 = (undefined2 *)((long)plVar3 + lVar2 + 0x14c);
    *puVar5 = 0;
    *(undefined2 *)((long)plVar3 + lVar2 + 0x13a) = 0;
    *(undefined2 **)((long)plVar3 + lVar2 + 0x140) = puVar5;
    *(undefined4 *)((long)plVar3 + lVar2 + 0x148) = 0x20;
    *(undefined2 *)((long)plVar3 + lVar2 + 0x18a) = 0;
    lVar2 = lVar2 + 0xa0;
  } while (lVar6 != 0);
  *plVar3 = (long)&DAT_710398cea8;
  FUN_710196d370(plVar3,param_1);
  return plVar3;
}



long * FUN_71019d26f0(long *param_1)

{
  undefined8 *puVar1;
  long lVar2;
  long *plVar3;
  long *plVar4;
  undefined2 *puVar5;
  long lVar6;
  
  lVar6 = *DAT_7103a65db8;
  if (lVar6 == 0) {
    plVar3 = (long *)FUN_71005fbcb0(8,0xbc70);
  }
  else {
    plVar3 = param_1;
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar1 = (undefined8 *)(lVar6 + 8);
      if (lVar2 != 0) {
        puVar1 = (undefined8 *)(lVar2 + 0x88);
      }
      plVar3 = (long *)*puVar1;
      if (plVar3 == (long *)0x0) {
        plVar3 = (long *)0x0;
        goto LAB_71019d276c;
      }
    }
    plVar3 = (long *)(**(code **)(*plVar3 + 0x30))(plVar3,0xbc70,8);
  }
LAB_71019d276c:
  thunk_EXT_FUN_02e95df0(plVar3 + 1,0,0xbc68);
  plVar3[0xd] = (long)(plVar3 + 0xe);
  plVar3[0xc] = (long)(plVar3 + 0xd);
  *(undefined8 *)((long)plVar3 + 0xc) = 0xffffffffffffffff;
  plVar3[0xb] = (long)(plVar3 + 0xc);
  plVar3[3] = -0xc0800000;
  plVar3[5] = 0;
  plVar3[6] = 0;
  *plVar3 = (long)&DAT_7103987b08;
  *(undefined4 *)(plVar3 + 4) = 0xffffffff;
  plVar3[10] = (long)(plVar3 + 0xb);
  plVar4 = plVar3 + 9;
  *plVar4 = (long)(plVar3 + 10);
  plVar3[7] = (long)plVar4;
  plVar3[8] = (long)plVar4;
  if (plVar3 + 0xf != (long *)0x0) {
    plVar3[6] = (long)(plVar3 + 0xf);
    *(undefined4 *)((long)plVar3 + 0x2c) = 6;
  }
  *(undefined4 *)(plVar3 + 0x15) = 0;
  *(undefined1 *)(plVar3 + 0x1a) = 1;
  lVar6 = 300;
  plVar3[0x16] = 0;
  plVar3[0x17] = 0;
  *(undefined4 *)((long)plVar3 + 0xd4) = 0;
  *(undefined1 *)(plVar3 + 0x1b) = 0;
  plVar3[0x18] = 0;
  plVar3[0x19] = 0;
  plVar3[0x1c] = 0;
  plVar3[0x1d] = 0;
  lVar2 = 0;
  do {
    lVar6 = lVar6 + -1;
    puVar5 = (undefined2 *)((long)plVar3 + lVar2 + 0xfc);
    *puVar5 = 0;
    *(undefined2 **)((long)plVar3 + lVar2 + 0xf0) = puVar5;
    *(undefined4 *)((long)plVar3 + lVar2 + 0xf8) = 0x20;
    puVar5 = (undefined2 *)((long)plVar3 + lVar2 + 0x14c);
    *puVar5 = 0;
    *(undefined2 *)((long)plVar3 + lVar2 + 0x13a) = 0;
    *(undefined2 **)((long)plVar3 + lVar2 + 0x140) = puVar5;
    *(undefined4 *)((long)plVar3 + lVar2 + 0x148) = 0x20;
    *(undefined2 *)((long)plVar3 + lVar2 + 0x18a) = 0;
    lVar2 = lVar2 + 0xa0;
  } while (lVar6 != 0);
  *plVar3 = (long)&DAT_710398d130;
  FUN_710196d370(plVar3,param_1);
  return plVar3;
}



long * FUN_71019d2df0(long *param_1)

{
  undefined8 *puVar1;
  long lVar2;
  long *plVar3;
  long lVar4;
  
  lVar4 = *DAT_7103a65db8;
  if (lVar4 == 0) {
    plVar3 = (long *)FUN_71005fbcb0(8,0x140f8);
  }
  else {
    plVar3 = param_1;
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar1 = (undefined8 *)(lVar4 + 8);
      if (lVar2 != 0) {
        puVar1 = (undefined8 *)(lVar2 + 0x88);
      }
      plVar3 = (long *)*puVar1;
      if (plVar3 == (long *)0x0) {
        plVar3 = (long *)0x0;
        goto LAB_71019d2e78;
      }
    }
    plVar3 = (long *)(**(code **)(*plVar3 + 0x30))(plVar3,0x140f8,8);
  }
LAB_71019d2e78:
  FUN_71019d68a0(plVar3,0xffffffff);
  *plVar3 = DAT_7103a65cc0 + 0x10;
  FUN_710196d370(plVar3,param_1);
  *(undefined4 *)(plVar3 + 0x15) = 0xffffffff;
  *(undefined4 *)((long)plVar3 + 0xc) = 4;
  *(undefined1 *)(plVar3 + 1) = 1;
  *(undefined1 *)((long)plVar3 + 10) = 1;
  return plVar3;
}



long * FUN_71019d2ee0(long *param_1)

{
  undefined8 *puVar1;
  long lVar2;
  long *plVar3;
  long *plVar4;
  undefined2 *puVar5;
  long lVar6;
  
  lVar6 = *DAT_7103a65db8;
  if (lVar6 == 0) {
    plVar3 = (long *)FUN_71005fbcb0(8,0xbc70);
  }
  else {
    plVar3 = param_1;
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar1 = (undefined8 *)(lVar6 + 8);
      if (lVar2 != 0) {
        puVar1 = (undefined8 *)(lVar2 + 0x88);
      }
      plVar3 = (long *)*puVar1;
      if (plVar3 == (long *)0x0) {
        plVar3 = (long *)0x0;
        goto LAB_71019d2f5c;
      }
    }
    plVar3 = (long *)(**(code **)(*plVar3 + 0x30))(plVar3,0xbc70,8);
  }
LAB_71019d2f5c:
  thunk_EXT_FUN_02e95df0(plVar3 + 1,0,0xbc68);
  plVar3[0xd] = (long)(plVar3 + 0xe);
  plVar3[0xc] = (long)(plVar3 + 0xd);
  *(undefined8 *)((long)plVar3 + 0xc) = 0xffffffffffffffff;
  plVar3[0xb] = (long)(plVar3 + 0xc);
  plVar3[3] = -0xc0800000;
  plVar3[5] = 0;
  plVar3[6] = 0;
  *plVar3 = (long)&DAT_7103987b08;
  *(undefined4 *)(plVar3 + 4) = 0xffffffff;
  plVar3[10] = (long)(plVar3 + 0xb);
  plVar4 = plVar3 + 9;
  *plVar4 = (long)(plVar3 + 10);
  plVar3[7] = (long)plVar4;
  plVar3[8] = (long)plVar4;
  if (plVar3 + 0xf != (long *)0x0) {
    plVar3[6] = (long)(plVar3 + 0xf);
    *(undefined4 *)((long)plVar3 + 0x2c) = 6;
  }
  *(undefined4 *)(plVar3 + 0x15) = 0;
  *(undefined1 *)(plVar3 + 0x1a) = 1;
  lVar6 = 300;
  plVar3[0x16] = 0;
  plVar3[0x17] = 0;
  *(undefined4 *)((long)plVar3 + 0xd4) = 0;
  *(undefined1 *)(plVar3 + 0x1b) = 0;
  plVar3[0x18] = 0;
  plVar3[0x19] = 0;
  plVar3[0x1c] = 0;
  plVar3[0x1d] = 0;
  lVar2 = 0;
  do {
    lVar6 = lVar6 + -1;
    puVar5 = (undefined2 *)((long)plVar3 + lVar2 + 0xfc);
    *puVar5 = 0;
    *(undefined2 **)((long)plVar3 + lVar2 + 0xf0) = puVar5;
    *(undefined4 *)((long)plVar3 + lVar2 + 0xf8) = 0x20;
    puVar5 = (undefined2 *)((long)plVar3 + lVar2 + 0x14c);
    *puVar5 = 0;
    *(undefined2 *)((long)plVar3 + lVar2 + 0x13a) = 0;
    *(undefined2 **)((long)plVar3 + lVar2 + 0x140) = puVar5;
    *(undefined4 *)((long)plVar3 + lVar2 + 0x148) = 0x20;
    *(undefined2 *)((long)plVar3 + lVar2 + 0x18a) = 0;
    lVar2 = lVar2 + 0xa0;
  } while (lVar6 != 0);
  *plVar3 = (long)&DAT_710398d3b8;
  FUN_710196d370(plVar3,param_1);
  return plVar3;
}



long * FUN_71019d3080(long *param_1)

{
  undefined8 *puVar1;
  long lVar2;
  long *plVar3;
  long *plVar4;
  undefined2 *puVar5;
  long lVar6;
  
  lVar6 = *DAT_7103a65db8;
  if (lVar6 == 0) {
    plVar3 = (long *)FUN_71005fbcb0(8,0xbc70);
  }
  else {
    plVar3 = param_1;
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar1 = (undefined8 *)(lVar6 + 8);
      if (lVar2 != 0) {
        puVar1 = (undefined8 *)(lVar2 + 0x88);
      }
      plVar3 = (long *)*puVar1;
      if (plVar3 == (long *)0x0) {
        plVar3 = (long *)0x0;
        goto LAB_71019d30fc;
      }
    }
    plVar3 = (long *)(**(code **)(*plVar3 + 0x30))(plVar3,0xbc70,8);
  }
LAB_71019d30fc:
  thunk_EXT_FUN_02e95df0(plVar3 + 1,0,0xbc68);
  plVar3[0xd] = (long)(plVar3 + 0xe);
  plVar3[0xc] = (long)(plVar3 + 0xd);
  *(undefined8 *)((long)plVar3 + 0xc) = 0xffffffffffffffff;
  plVar3[0xb] = (long)(plVar3 + 0xc);
  plVar3[3] = -0xc0800000;
  plVar3[5] = 0;
  plVar3[6] = 0;
  *plVar3 = (long)&DAT_7103987b08;
  *(undefined4 *)(plVar3 + 4) = 0xffffffff;
  plVar3[10] = (long)(plVar3 + 0xb);
  plVar4 = plVar3 + 9;
  *plVar4 = (long)(plVar3 + 10);
  plVar3[7] = (long)plVar4;
  plVar3[8] = (long)plVar4;
  if (plVar3 + 0xf != (long *)0x0) {
    plVar3[6] = (long)(plVar3 + 0xf);
    *(undefined4 *)((long)plVar3 + 0x2c) = 6;
  }
  *(undefined4 *)(plVar3 + 0x15) = 0;
  *(undefined1 *)(plVar3 + 0x1a) = 1;
  lVar6 = 300;
  plVar3[0x16] = 0;
  plVar3[0x17] = 0;
  *(undefined4 *)((long)plVar3 + 0xd4) = 0;
  *(undefined1 *)(plVar3 + 0x1b) = 0;
  plVar3[0x18] = 0;
  plVar3[0x19] = 0;
  plVar3[0x1c] = 0;
  plVar3[0x1d] = 0;
  lVar2 = 0;
  do {
    lVar6 = lVar6 + -1;
    puVar5 = (undefined2 *)((long)plVar3 + lVar2 + 0xfc);
    *puVar5 = 0;
    *(undefined2 **)((long)plVar3 + lVar2 + 0xf0) = puVar5;
    *(undefined4 *)((long)plVar3 + lVar2 + 0xf8) = 0x20;
    puVar5 = (undefined2 *)((long)plVar3 + lVar2 + 0x14c);
    *puVar5 = 0;
    *(undefined2 *)((long)plVar3 + lVar2 + 0x13a) = 0;
    *(undefined2 **)((long)plVar3 + lVar2 + 0x140) = puVar5;
    *(undefined4 *)((long)plVar3 + lVar2 + 0x148) = 0x20;
    *(undefined2 *)((long)plVar3 + lVar2 + 0x18a) = 0;
    lVar2 = lVar2 + 0xa0;
  } while (lVar6 != 0);
  *plVar3 = (long)&DAT_710398d640;
  FUN_710196d370(plVar3,param_1);
  return plVar3;
}



long * FUN_71019d3220(long *param_1)

{
  undefined8 *puVar1;
  long lVar2;
  long *plVar3;
  long *plVar4;
  long *plVar5;
  long *plVar6;
  long lVar7;
  
  plVar5 = DAT_7103a65db8;
  lVar7 = *DAT_7103a65db8;
  if (lVar7 == 0) {
    plVar3 = (long *)FUN_71005fbcb0(8,0x108);
  }
  else {
    plVar3 = param_1;
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar1 = (undefined8 *)(lVar7 + 8);
      if (lVar2 != 0) {
        puVar1 = (undefined8 *)(lVar2 + 0x88);
      }
      plVar3 = (long *)*puVar1;
      if (plVar3 == (long *)0x0) {
        plVar3 = (long *)0x0;
        goto LAB_71019d32a4;
      }
    }
    plVar3 = (long *)(**(code **)(*plVar3 + 0x30))(plVar3,0x108,8);
  }
LAB_71019d32a4:
  FUN_710196e5ac(plVar3,10,param_1);
  *plVar3 = (long)&DAT_710398d8c8;
  FUN_710196d370(plVar3,param_1);
  lVar7 = *plVar5;
  *(undefined4 *)(plVar3 + 2) = 3;
  if (lVar7 == 0) {
    plVar4 = (long *)FUN_71005fbcb0(8,0x110);
  }
  else {
    plVar4 = param_1;
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar1 = (undefined8 *)(lVar7 + 8);
      if (lVar2 != 0) {
        puVar1 = (undefined8 *)(lVar2 + 0x88);
      }
      plVar4 = (long *)*puVar1;
      if (plVar4 == (long *)0x0) {
        plVar4 = (long *)0x0;
        goto LAB_71019d3338;
      }
    }
    plVar4 = (long *)(**(code **)(*plVar4 + 0x30))(plVar4,0x110,8);
  }
LAB_71019d3338:
  *(undefined2 *)(plVar4 + 1) = 0;
  lVar7 = DAT_7103a65b60;
  *(undefined8 *)((long)plVar4 + 0xc) = 0xffffffffffffffff;
  *(undefined1 *)((long)plVar4 + 10) = 0;
  plVar4[0xe] = 0;
  plVar4[0xd] = (long)(plVar4 + 0xe);
  *(undefined2 *)((long)plVar4 + 0x14) = 0;
  *plVar4 = lVar7 + 0x10;
  plVar4[0xc] = (long)(plVar4 + 0xd);
  plVar4[3] = -0xc0800000;
  plVar4[0xb] = (long)(plVar4 + 0xc);
  plVar4[10] = (long)(plVar4 + 0xb);
  *(undefined4 *)(plVar4 + 4) = 0xffffffff;
  plVar6 = plVar4 + 9;
  *plVar6 = (long)(plVar4 + 10);
  plVar4[5] = 0;
  plVar4[6] = 0;
  plVar4[7] = (long)plVar6;
  plVar4[8] = (long)plVar6;
  if (plVar4 + 0xf != (long *)0x0) {
    plVar4[6] = (long)(plVar4 + 0xf);
    *(undefined4 *)((long)plVar4 + 0x2c) = 6;
  }
  *(undefined4 *)(plVar4 + 0x15) = 0;
  plVar4[0x16] = 0;
  plVar4[0x17] = 0;
  *(undefined1 *)(plVar4 + 0x1a) = 1;
  *(undefined4 *)((long)plVar4 + 0xd4) = 0;
  *(undefined1 *)(plVar4 + 0x1b) = 0;
  plVar4[0x1f] = 0;
  *(undefined4 *)(plVar4 + 0x20) = 0;
  plVar4[0x21] = 0;
  plVar4[0x18] = 0;
  plVar4[0x19] = 0;
  plVar4[0x1c] = 0;
  plVar4[0x1d] = 0;
  lVar7 = DAT_7103a65cb8 + 0x10;
  *(undefined4 *)(plVar4 + 0x1e) = 0;
  *plVar4 = lVar7;
  FUN_71019786e0(plVar4,param_1);
  *(undefined4 *)(plVar4 + 0x15) = 0xffffffff;
  *(undefined1 *)((long)plVar4 + 0x15) = 1;
  *(undefined4 *)((long)plVar4 + 0xc) = 5;
  *(undefined1 *)(plVar4 + 1) = 1;
  *(undefined1 *)((long)plVar4 + 10) = 1;
  if ((int)plVar3[0x1e] < *(int *)((long)plVar3 + 0xf4)) {
    *(long **)(plVar3[0x1f] + (long)(int)plVar3[0x1e] * 8) = plVar4;
    *(int *)(plVar3 + 0x1e) = (int)plVar3[0x1e] + 1;
  }
  lVar7 = *plVar5;
  if (lVar7 == 0) {
    plVar4 = (long *)FUN_71005fbcb0(8,0x360);
  }
  else {
    plVar4 = param_1;
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar1 = (undefined8 *)(lVar7 + 8);
      if (lVar2 != 0) {
        puVar1 = (undefined8 *)(lVar2 + 0x88);
      }
      plVar4 = (long *)*puVar1;
      if (plVar4 == (long *)0x0) {
        plVar4 = (long *)0x0;
        goto LAB_71019d34a8;
      }
    }
    plVar4 = (long *)(**(code **)(*plVar4 + 0x30))(plVar4,0x360,8);
  }
LAB_71019d34a8:
  FUN_71019dc408(plVar4,2);
  (**(code **)(*plVar4 + 0x20))(plVar4,param_1);
  *(undefined4 *)(plVar4 + 0x15) = 0xffffffff;
  *(undefined4 *)((long)plVar4 + 0xc) = 4;
  *(undefined1 *)((long)plVar4 + 0x15) = 1;
  *(undefined1 *)(plVar4 + 1) = 1;
  *(undefined1 *)((long)plVar4 + 10) = 1;
  if ((int)plVar3[0x1e] < *(int *)((long)plVar3 + 0xf4)) {
    *(long **)(plVar3[0x1f] + (long)(int)plVar3[0x1e] * 8) = plVar4;
    *(int *)(plVar3 + 0x1e) = (int)plVar3[0x1e] + 1;
  }
  lVar7 = *plVar5;
  if (lVar7 == 0) {
    plVar4 = (long *)FUN_71005fbcb0(8,0x360);
  }
  else {
    plVar4 = param_1;
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar1 = (undefined8 *)(lVar7 + 8);
      if (lVar2 != 0) {
        puVar1 = (undefined8 *)(lVar2 + 0x88);
      }
      plVar4 = (long *)*puVar1;
      if (plVar4 == (long *)0x0) {
        plVar4 = (long *)0x0;
        goto LAB_71019d356c;
      }
    }
    plVar4 = (long *)(**(code **)(*plVar4 + 0x30))(plVar4,0x360,8);
  }
LAB_71019d356c:
  FUN_71019dc408(plVar4,1);
  (**(code **)(*plVar4 + 0x20))(plVar4,param_1);
  *(undefined4 *)(plVar4 + 0x15) = 0xffffffff;
  *(undefined1 *)((long)plVar4 + 0x15) = 1;
  *(undefined4 *)((long)plVar4 + 0xc) = 2;
  *(undefined1 *)(plVar4 + 1) = 1;
  *(undefined1 *)((long)plVar4 + 10) = 1;
  if ((int)plVar3[0x1e] < *(int *)((long)plVar3 + 0xf4)) {
    *(long **)(plVar3[0x1f] + (long)(int)plVar3[0x1e] * 8) = plVar4;
    *(int *)(plVar3 + 0x1e) = (int)plVar3[0x1e] + 1;
  }
  lVar7 = *plVar5;
  if (lVar7 == 0) {
    plVar4 = (long *)FUN_71005fbcb0(8,0x360);
  }
  else {
    plVar4 = param_1;
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar1 = (undefined8 *)(lVar7 + 8);
      if (lVar2 != 0) {
        puVar1 = (undefined8 *)(lVar2 + 0x88);
      }
      plVar4 = (long *)*puVar1;
      if (plVar4 == (long *)0x0) {
        plVar4 = (long *)0x0;
        goto LAB_71019d3630;
      }
    }
    plVar4 = (long *)(**(code **)(*plVar4 + 0x30))(plVar4,0x360,8);
  }
LAB_71019d3630:
  FUN_71019dc408(plVar4,3);
  (**(code **)(*plVar4 + 0x20))(plVar4,param_1);
  *(undefined4 *)(plVar4 + 0x15) = 0xffffffff;
  *(undefined4 *)((long)plVar4 + 0xc) = 2;
  *(undefined1 *)((long)plVar4 + 0x15) = 1;
  *(undefined1 *)(plVar4 + 1) = 1;
  *(undefined1 *)((long)plVar4 + 10) = 1;
  if ((int)plVar3[0x1e] < *(int *)((long)plVar3 + 0xf4)) {
    *(long **)(plVar3[0x1f] + (long)(int)plVar3[0x1e] * 8) = plVar4;
    *(int *)(plVar3 + 0x1e) = (int)plVar3[0x1e] + 1;
  }
  lVar7 = *plVar5;
  if (lVar7 == 0) {
    plVar4 = (long *)FUN_71005fbcb0(8,0x360);
  }
  else {
    plVar4 = param_1;
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar1 = (undefined8 *)(lVar7 + 8);
      if (lVar2 != 0) {
        puVar1 = (undefined8 *)(lVar2 + 0x88);
      }
      plVar4 = (long *)*puVar1;
      if (plVar4 == (long *)0x0) {
        plVar4 = (long *)0x0;
        goto LAB_71019d36f4;
      }
    }
    plVar4 = (long *)(**(code **)(*plVar4 + 0x30))(plVar4,0x360,8);
  }
LAB_71019d36f4:
  FUN_71019dc408(plVar4,7);
  (**(code **)(*plVar4 + 0x20))(plVar4,param_1);
  *(undefined4 *)(plVar4 + 0x15) = 0xffffffff;
  *(undefined4 *)((long)plVar4 + 0xc) = 2;
  *(undefined1 *)((long)plVar4 + 0x15) = 1;
  *(undefined1 *)(plVar4 + 1) = 1;
  *(undefined1 *)((long)plVar4 + 10) = 1;
  if ((int)plVar3[0x1e] < *(int *)((long)plVar3 + 0xf4)) {
    *(long **)(plVar3[0x1f] + (long)(int)plVar3[0x1e] * 8) = plVar4;
    *(int *)(plVar3 + 0x1e) = (int)plVar3[0x1e] + 1;
  }
  lVar7 = *plVar5;
  if (lVar7 == 0) {
    plVar4 = (long *)FUN_71005fbcb0(8,0x360);
  }
  else {
    plVar4 = param_1;
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar1 = (undefined8 *)(lVar7 + 8);
      if (lVar2 != 0) {
        puVar1 = (undefined8 *)(lVar2 + 0x88);
      }
      plVar4 = (long *)*puVar1;
      if (plVar4 == (long *)0x0) {
        plVar4 = (long *)0x0;
        goto LAB_71019d37b8;
      }
    }
    plVar4 = (long *)(**(code **)(*plVar4 + 0x30))(plVar4,0x360,8);
  }
LAB_71019d37b8:
  FUN_71019dc408(plVar4,6);
  (**(code **)(*plVar4 + 0x20))(plVar4,param_1);
  *(undefined4 *)(plVar4 + 0x15) = 0xffffffff;
  *(undefined4 *)((long)plVar4 + 0xc) = 2;
  *(undefined1 *)((long)plVar4 + 0x15) = 1;
  *(undefined1 *)(plVar4 + 1) = 1;
  *(undefined1 *)((long)plVar4 + 10) = 1;
  if ((int)plVar3[0x1e] < *(int *)((long)plVar3 + 0xf4)) {
    *(long **)(plVar3[0x1f] + (long)(int)plVar3[0x1e] * 8) = plVar4;
    *(int *)(plVar3 + 0x1e) = (int)plVar3[0x1e] + 1;
  }
  lVar7 = *plVar5;
  if (lVar7 == 0) {
    plVar4 = (long *)FUN_71005fbcb0(8,0x360);
  }
  else {
    plVar4 = param_1;
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar1 = (undefined8 *)(lVar7 + 8);
      if (lVar2 != 0) {
        puVar1 = (undefined8 *)(lVar2 + 0x88);
      }
      plVar4 = (long *)*puVar1;
      if (plVar4 == (long *)0x0) {
        plVar4 = (long *)0x0;
        goto LAB_71019d387c;
      }
    }
    plVar4 = (long *)(**(code **)(*plVar4 + 0x30))(plVar4,0x360,8);
  }
LAB_71019d387c:
  FUN_71019dc408(plVar4,4);
  (**(code **)(*plVar4 + 0x20))(plVar4,param_1);
  *(undefined4 *)(plVar4 + 0x15) = 0xffffffff;
  *(undefined4 *)((long)plVar4 + 0xc) = 1;
  *(undefined1 *)((long)plVar4 + 0x15) = 1;
  *(undefined1 *)(plVar4 + 1) = 1;
  *(undefined1 *)((long)plVar4 + 10) = 1;
  if ((int)plVar3[0x1e] < *(int *)((long)plVar3 + 0xf4)) {
    *(long **)(plVar3[0x1f] + (long)(int)plVar3[0x1e] * 8) = plVar4;
    *(int *)(plVar3 + 0x1e) = (int)plVar3[0x1e] + 1;
  }
  lVar7 = *plVar5;
  if (lVar7 == 0) {
    plVar4 = (long *)FUN_71005fbcb0(8,0x360);
  }
  else {
    plVar4 = param_1;
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar1 = (undefined8 *)(lVar7 + 8);
      if (lVar2 != 0) {
        puVar1 = (undefined8 *)(lVar2 + 0x88);
      }
      plVar4 = (long *)*puVar1;
      if (plVar4 == (long *)0x0) {
        plVar4 = (long *)0x0;
        goto LAB_71019d393c;
      }
    }
    plVar4 = (long *)(**(code **)(*plVar4 + 0x30))(plVar4,0x360,8);
  }
LAB_71019d393c:
  FUN_71019dc408(plVar4,5);
  (**(code **)(*plVar4 + 0x20))(plVar4,param_1);
  *(undefined4 *)(plVar4 + 0x15) = 0xffffffff;
  *(undefined4 *)((long)plVar4 + 0xc) = 1;
  *(undefined1 *)((long)plVar4 + 0x15) = 1;
  *(undefined1 *)(plVar4 + 1) = 1;
  *(undefined1 *)((long)plVar4 + 10) = 1;
  if ((int)plVar3[0x1e] < *(int *)((long)plVar3 + 0xf4)) {
    *(long **)(plVar3[0x1f] + (long)(int)plVar3[0x1e] * 8) = plVar4;
    *(int *)(plVar3 + 0x1e) = (int)plVar3[0x1e] + 1;
  }
  lVar7 = *plVar5;
  if (lVar7 == 0) {
    plVar5 = (long *)FUN_71005fbcb0(8,0x360);
  }
  else {
    plVar5 = param_1;
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar1 = (undefined8 *)(lVar7 + 8);
      if (lVar2 != 0) {
        puVar1 = (undefined8 *)(lVar2 + 0x88);
      }
      plVar5 = (long *)*puVar1;
      if (plVar5 == (long *)0x0) {
        plVar5 = (long *)0x0;
        goto LAB_71019d39fc;
      }
    }
    plVar5 = (long *)(**(code **)(*plVar5 + 0x30))(plVar5,0x360,8);
  }
LAB_71019d39fc:
  FUN_71019dc408(plVar5,0);
  (**(code **)(*plVar5 + 0x20))(plVar5,param_1);
  *(undefined4 *)(plVar5 + 0x15) = 0xffffffff;
  *(undefined4 *)((long)plVar5 + 0xc) = 1;
  *(undefined1 *)((long)plVar5 + 0x15) = 1;
  *(undefined1 *)(plVar5 + 1) = 1;
  *(undefined1 *)((long)plVar5 + 10) = 1;
  if ((int)plVar3[0x1e] < *(int *)((long)plVar3 + 0xf4)) {
    *(long **)(plVar3[0x1f] + (long)(int)plVar3[0x1e] * 8) = plVar5;
    *(int *)(plVar3 + 0x1e) = (int)plVar3[0x1e] + 1;
  }
  return plVar3;
}



long * FUN_71019d3ac0(long *param_1)

{
  undefined8 *puVar1;
  long lVar2;
  long *plVar3;
  long *plVar4;
  long lVar5;
  
  lVar5 = *DAT_7103a65db8;
  if (lVar5 == 0) {
    plVar3 = (long *)FUN_71005fbcb0(8,0x110);
  }
  else {
    plVar3 = param_1;
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar1 = (undefined8 *)(lVar5 + 8);
      if (lVar2 != 0) {
        puVar1 = (undefined8 *)(lVar2 + 0x88);
      }
      plVar3 = (long *)*puVar1;
    }
    plVar3 = (long *)(**(code **)(*plVar3 + 0x30))(plVar3,0x110,8);
  }
  plVar3[0xe] = 0;
  plVar3[0xd] = (long)(plVar3 + 0xe);
  *(undefined8 *)((long)plVar3 + 0xc) = 0xffffffffffffffff;
  *(undefined2 *)(plVar3 + 1) = 0;
  *(undefined1 *)((long)plVar3 + 10) = 0;
  *(undefined2 *)((long)plVar3 + 0x14) = 0;
  *plVar3 = (long)&DAT_7103987b08;
  plVar3[5] = 0;
  plVar3[6] = 0;
  plVar3[0xc] = (long)(plVar3 + 0xd);
  plVar3[3] = -0xc0800000;
  plVar3[0xb] = (long)(plVar3 + 0xc);
  *(undefined4 *)(plVar3 + 4) = 0xffffffff;
  plVar3[10] = (long)(plVar3 + 0xb);
  plVar4 = plVar3 + 9;
  *plVar4 = (long)(plVar3 + 10);
  plVar3[7] = (long)plVar4;
  plVar3[8] = (long)plVar4;
  if (plVar3 + 0xf != (long *)0x0) {
    plVar3[6] = (long)(plVar3 + 0xf);
    *(undefined4 *)((long)plVar3 + 0x2c) = 6;
  }
  *(undefined4 *)(plVar3 + 0x15) = 0;
  plVar3[0x16] = 0;
  plVar3[0x17] = 0;
  *(undefined1 *)(plVar3 + 0x1a) = 1;
  *(undefined4 *)((long)plVar3 + 0xd4) = 0;
  *(undefined1 *)(plVar3 + 0x1b) = 0;
  plVar3[0x1f] = 0;
  *(undefined4 *)(plVar3 + 0x20) = 0;
  plVar3[0x21] = 0;
  plVar3[0x18] = 0;
  plVar3[0x19] = 0;
  plVar3[0x1c] = 0;
  plVar3[0x1d] = 0;
  lVar5 = DAT_7103a65cb8 + 0x10;
  *(undefined4 *)(plVar3 + 0x1e) = 0;
  *plVar3 = lVar5;
  FUN_71019786e0(plVar3,param_1);
  *(undefined1 *)(plVar3 + 1) = 1;
  *(undefined2 *)((long)plVar3 + 0x14) = 0x101;
  *(undefined1 *)((long)plVar3 + 10) = 1;
  return plVar3;
}



long * FUN_71019d3c30(long *param_1)

{
  undefined8 *puVar1;
  long lVar2;
  long *plVar3;
  long *plVar4;
  undefined2 *puVar5;
  long lVar6;
  
  lVar6 = *DAT_7103a65db8;
  if (lVar6 == 0) {
    plVar3 = (long *)FUN_71005fbcb0(8,0xe210);
  }
  else {
    plVar3 = param_1;
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar1 = (undefined8 *)(lVar6 + 8);
      if (lVar2 != 0) {
        puVar1 = (undefined8 *)(lVar2 + 0x88);
      }
      plVar3 = (long *)*puVar1;
      if (plVar3 == (long *)0x0) {
        plVar3 = (long *)0x0;
        goto LAB_71019d3cb0;
      }
    }
    plVar3 = (long *)(**(code **)(*plVar3 + 0x30))(plVar3,0xe210,8);
  }
LAB_71019d3cb0:
  thunk_EXT_FUN_02e95df0(plVar3 + 1,0,0xe208);
  plVar3[0xd] = (long)(plVar3 + 0xe);
  plVar3[0xc] = (long)(plVar3 + 0xd);
  *(undefined8 *)((long)plVar3 + 0xc) = 0xffffffffffffffff;
  plVar3[0xb] = (long)(plVar3 + 0xc);
  plVar3[3] = -0xc0800000;
  plVar3[5] = 0;
  plVar3[6] = 0;
  *plVar3 = (long)&DAT_7103987b08;
  *(undefined4 *)(plVar3 + 4) = 0xffffffff;
  plVar3[10] = (long)(plVar3 + 0xb);
  plVar4 = plVar3 + 9;
  *plVar4 = (long)(plVar3 + 10);
  plVar3[7] = (long)plVar4;
  plVar3[8] = (long)plVar4;
  if (plVar3 + 0xf != (long *)0x0) {
    plVar3[6] = (long)(plVar3 + 0xf);
    *(undefined4 *)((long)plVar3 + 0x2c) = 6;
  }
  *(undefined4 *)(plVar3 + 0x15) = 0;
  *(undefined1 *)(plVar3 + 0x1a) = 1;
  lVar6 = 300;
  plVar3[0x16] = 0;
  plVar3[0x17] = 0;
  *(undefined4 *)((long)plVar3 + 0xd4) = 0;
  *(undefined1 *)(plVar3 + 0x1b) = 0;
  plVar3[0x18] = 0;
  plVar3[0x19] = 0;
  plVar3[0x1c] = 0;
  plVar3[0x1d] = 0;
  lVar2 = 0;
  do {
    lVar6 = lVar6 + -1;
    puVar5 = (undefined2 *)((long)plVar3 + lVar2 + 0xfc);
    *puVar5 = 0;
    *(undefined2 **)((long)plVar3 + lVar2 + 0xf0) = puVar5;
    *(undefined4 *)((long)plVar3 + lVar2 + 0xf8) = 0x20;
    puVar5 = (undefined2 *)((long)plVar3 + lVar2 + 0x14c);
    *puVar5 = 0;
    *(undefined2 *)((long)plVar3 + lVar2 + 0x13a) = 0;
    *(undefined2 **)((long)plVar3 + lVar2 + 0x140) = puVar5;
    *(undefined4 *)((long)plVar3 + lVar2 + 0x148) = 0x20;
    *(undefined2 *)((long)plVar3 + lVar2 + 0x18a) = 0;
    lVar2 = lVar2 + 0xa0;
  } while (lVar6 != 0);
  plVar3[0x1790] = 0;
  plVar3[0x1791] = 0;
  *(undefined4 *)((long)plVar3 + 0xbc8c) = 300;
  plVar4 = plVar3 + 0x179a;
  plVar3[0x178e] = 0;
  plVar3[0x178f] = 0;
  plVar3[0x178f] = (long)(plVar3 + 0x1792);
  for (lVar6 = 0x12a; plVar4[-8] = (long)(plVar4 + -4), lVar6 != 0; lVar6 = lVar6 + -2) {
    plVar4[-4] = (long)plVar4;
    plVar4 = plVar4 + 8;
  }
  plVar3[0x1790] = (long)(plVar3 + 0x1792);
  plVar3[0x1c3e] = 0;
  *plVar3 = (long)&DAT_710398db60;
  FUN_710196d370(plVar3,param_1);
  return plVar3;
}



long * FUN_71019d3fe0(long *param_1,undefined4 param_2)

{
  undefined8 *puVar1;
  long lVar2;
  long *plVar3;
  long *plVar4;
  long lVar5;
  
  lVar5 = *DAT_7103a65db8;
  if (lVar5 == 0) {
    plVar3 = (long *)FUN_71005fbcb0(8,0x12148);
  }
  else {
    plVar3 = param_1;
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar1 = (undefined8 *)(lVar5 + 8);
      if (lVar2 != 0) {
        puVar1 = (undefined8 *)(lVar2 + 0x88);
      }
      plVar3 = (long *)*puVar1;
    }
    plVar3 = (long *)(**(code **)(*plVar3 + 0x30))(plVar3,0x12148,8);
  }
  plVar3[0xe] = 0;
  plVar3[0xd] = (long)(plVar3 + 0xe);
  *(undefined8 *)((long)plVar3 + 0xc) = 0xffffffffffffffff;
  *(undefined2 *)(plVar3 + 1) = 0;
  *(undefined1 *)((long)plVar3 + 10) = 0;
  *(undefined2 *)((long)plVar3 + 0x14) = 0;
  *plVar3 = (long)&DAT_7103987b08;
  plVar3[5] = 0;
  plVar3[6] = 0;
  plVar3[0xc] = (long)(plVar3 + 0xd);
  plVar3[3] = -0xc0800000;
  plVar3[0xb] = (long)(plVar3 + 0xc);
  *(undefined4 *)(plVar3 + 4) = 0xffffffff;
  plVar3[10] = (long)(plVar3 + 0xb);
  plVar4 = plVar3 + 9;
  *plVar4 = (long)(plVar3 + 10);
  plVar3[7] = (long)plVar4;
  plVar3[8] = (long)plVar4;
  if (plVar3 + 0xf != (long *)0x0) {
    plVar3[6] = (long)(plVar3 + 0xf);
    *(undefined4 *)((long)plVar3 + 0x2c) = 6;
  }
  *(undefined4 *)(plVar3 + 0x15) = 0;
  plVar3[0x16] = 0;
  plVar3[0x17] = 0;
  lVar5 = 0x17e;
  *(undefined1 *)(plVar3 + 0x1a) = 1;
  *(undefined4 *)((long)plVar3 + 0xd4) = 0;
  *(undefined1 *)(plVar3 + 0x1b) = 0;
  *(undefined4 *)(plVar3 + 0x1e) = param_2;
  *(undefined4 *)(plVar3 + 0x21) = 0;
  *(undefined1 *)((long)plVar3 + 0x10c) = 0;
  *(undefined4 *)(plVar3 + 0x22) = 0;
  plVar3[0x23] = 0;
  *(undefined4 *)(plVar3 + 0x24) = 0;
  *(undefined1 *)((long)plVar3 + 0x124) = 0;
  plVar3[0x18] = 0;
  plVar3[0x19] = 0;
  plVar3[0x1c] = 0;
  plVar3[0x1d] = 0;
  plVar3[0x1f] = DAT_7103a65e88 + 0x10;
  plVar3[0x20] = 0;
  plVar3[0x27] = 0;
  plVar3[0x28] = 0;
  *(undefined4 *)((long)plVar3 + 0x144) = 0x180;
  plVar3[0x25] = 0;
  plVar3[0x26] = (long)(plVar3 + 0x29);
  plVar3[0x29] = (long)(plVar3 + 0x41);
  plVar4 = plVar3 + 0x41;
  do {
    lVar5 = lVar5 + -2;
    *plVar4 = (long)(plVar4 + 0x18);
    plVar4[0x18] = (long)(plVar4 + 0x30);
    plVar4 = plVar4 + 0x30;
  } while (lVar5 != 0);
  plVar3[0x27] = (long)(plVar3 + 0x29);
  *plVar3 = (long)&DAT_710398e058;
  plVar3[0x2411] = 0;
  FUN_710196d370(plVar3,param_1);
  return plVar3;
}



long * FUN_71019d41c0(long *param_1)

{
  undefined8 *puVar1;
  long lVar2;
  long *plVar3;
  long *plVar4;
  undefined2 *puVar5;
  long lVar6;
  
  lVar6 = *DAT_7103a65db8;
  if (lVar6 == 0) {
    plVar3 = (long *)FUN_71005fbcb0(8,0xbc70);
  }
  else {
    plVar3 = param_1;
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar1 = (undefined8 *)(lVar6 + 8);
      if (lVar2 != 0) {
        puVar1 = (undefined8 *)(lVar2 + 0x88);
      }
      plVar3 = (long *)*puVar1;
      if (plVar3 == (long *)0x0) {
        plVar3 = (long *)0x0;
        goto LAB_71019d423c;
      }
    }
    plVar3 = (long *)(**(code **)(*plVar3 + 0x30))(plVar3,0xbc70,8);
  }
LAB_71019d423c:
  thunk_EXT_FUN_02e95df0(plVar3 + 1,0,0xbc68);
  plVar3[0xd] = (long)(plVar3 + 0xe);
  plVar3[0xc] = (long)(plVar3 + 0xd);
  *(undefined8 *)((long)plVar3 + 0xc) = 0xffffffffffffffff;
  plVar3[0xb] = (long)(plVar3 + 0xc);
  plVar3[3] = -0xc0800000;
  plVar3[5] = 0;
  plVar3[6] = 0;
  *plVar3 = (long)&DAT_7103987b08;
  *(undefined4 *)(plVar3 + 4) = 0xffffffff;
  plVar3[10] = (long)(plVar3 + 0xb);
  plVar4 = plVar3 + 9;
  *plVar4 = (long)(plVar3 + 10);
  plVar3[7] = (long)plVar4;
  plVar3[8] = (long)plVar4;
  if (plVar3 + 0xf != (long *)0x0) {
    plVar3[6] = (long)(plVar3 + 0xf);
    *(undefined4 *)((long)plVar3 + 0x2c) = 6;
  }
  *(undefined4 *)(plVar3 + 0x15) = 0;
  *(undefined1 *)(plVar3 + 0x1a) = 1;
  lVar6 = 300;
  plVar3[0x16] = 0;
  plVar3[0x17] = 0;
  *(undefined4 *)((long)plVar3 + 0xd4) = 0;
  *(undefined1 *)(plVar3 + 0x1b) = 0;
  plVar3[0x18] = 0;
  plVar3[0x19] = 0;
  plVar3[0x1c] = 0;
  plVar3[0x1d] = 0;
  lVar2 = 0;
  do {
    lVar6 = lVar6 + -1;
    puVar5 = (undefined2 *)((long)plVar3 + lVar2 + 0xfc);
    *puVar5 = 0;
    *(undefined2 **)((long)plVar3 + lVar2 + 0xf0) = puVar5;
    *(undefined4 *)((long)plVar3 + lVar2 + 0xf8) = 0x20;
    puVar5 = (undefined2 *)((long)plVar3 + lVar2 + 0x14c);
    *puVar5 = 0;
    *(undefined2 *)((long)plVar3 + lVar2 + 0x13a) = 0;
    *(undefined2 **)((long)plVar3 + lVar2 + 0x140) = puVar5;
    *(undefined4 *)((long)plVar3 + lVar2 + 0x148) = 0x20;
    *(undefined2 *)((long)plVar3 + lVar2 + 0x18a) = 0;
    lVar2 = lVar2 + 0xa0;
  } while (lVar6 != 0);
  *plVar3 = (long)&DAT_710398e548;
  FUN_710196d370(plVar3,param_1);
  return plVar3;
}



long * FUN_71019d49a0(long *param_1)

{
  undefined8 *puVar1;
  long lVar2;
  long *plVar3;
  long *plVar4;
  long lVar5;
  
  lVar5 = *DAT_7103a65db8;
  if (lVar5 == 0) {
    plVar3 = (long *)FUN_71005fbcb0(8,0x110);
  }
  else {
    plVar3 = param_1;
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar1 = (undefined8 *)(lVar5 + 8);
      if (lVar2 != 0) {
        puVar1 = (undefined8 *)(lVar2 + 0x88);
      }
      plVar3 = (long *)*puVar1;
    }
    plVar3 = (long *)(**(code **)(*plVar3 + 0x30))(plVar3,0x110,8);
  }
  plVar3[0xe] = 0;
  plVar3[0xd] = (long)(plVar3 + 0xe);
  *(undefined8 *)((long)plVar3 + 0xc) = 0xffffffffffffffff;
  *(undefined2 *)(plVar3 + 1) = 0;
  *(undefined1 *)((long)plVar3 + 10) = 0;
  *(undefined2 *)((long)plVar3 + 0x14) = 0;
  *plVar3 = (long)&DAT_7103987b08;
  plVar3[5] = 0;
  plVar3[6] = 0;
  plVar3[0xc] = (long)(plVar3 + 0xd);
  plVar3[3] = -0xc0800000;
  plVar3[0xb] = (long)(plVar3 + 0xc);
  *(undefined4 *)(plVar3 + 4) = 0xffffffff;
  plVar3[10] = (long)(plVar3 + 0xb);
  plVar4 = plVar3 + 9;
  *plVar4 = (long)(plVar3 + 10);
  plVar3[7] = (long)plVar4;
  plVar3[8] = (long)plVar4;
  if (plVar3 + 0xf != (long *)0x0) {
    plVar3[6] = (long)(plVar3 + 0xf);
    *(undefined4 *)((long)plVar3 + 0x2c) = 6;
  }
  *(undefined4 *)(plVar3 + 0x15) = 0;
  plVar3[0x16] = 0;
  plVar3[0x17] = 0;
  *(undefined1 *)(plVar3 + 0x1a) = 1;
  *(undefined4 *)((long)plVar3 + 0xd4) = 0;
  *(undefined1 *)(plVar3 + 0x1b) = 0;
  plVar3[0x1f] = 0;
  *(undefined4 *)(plVar3 + 0x20) = 0;
  plVar3[0x21] = 0;
  plVar3[0x18] = 0;
  plVar3[0x19] = 0;
  plVar3[0x1c] = 0;
  plVar3[0x1d] = 0;
  lVar5 = DAT_7103a65bc0 + 0x10;
  *(undefined4 *)(plVar3 + 0x1e) = 0;
  *plVar3 = lVar5;
  FUN_71019786e0(plVar3,param_1);
  *(undefined1 *)(plVar3 + 1) = 1;
  *(undefined2 *)((long)plVar3 + 0x14) = 0x101;
  *(undefined1 *)((long)plVar3 + 10) = 1;
  return plVar3;
}



long * FUN_71019d4b10(long *param_1)

{
  long lVar1;
  long lVar2;
  undefined8 *puVar3;
  long lVar4;
  long *plVar5;
  long lVar6;
  long *plVar7;
  long lVar8;
  
  lVar8 = *DAT_7103a65db8;
  if (lVar8 == 0) {
    plVar5 = (long *)FUN_71005fbcb0(8,0x150f0);
  }
  else {
    plVar5 = param_1;
    if (param_1 == (long *)0x0) {
      lVar4 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar3 = (undefined8 *)(lVar8 + 8);
      if (lVar4 != 0) {
        puVar3 = (undefined8 *)(lVar4 + 0x88);
      }
      plVar5 = (long *)*puVar3;
      if (plVar5 == (long *)0x0) {
        plVar5 = (long *)0x0;
        goto LAB_71019d4b94;
      }
    }
    plVar5 = (long *)(**(code **)(*plVar5 + 0x30))(plVar5,0x150f0,8);
  }
LAB_71019d4b94:
  thunk_EXT_FUN_02e95df0(plVar5 + 1,0,0x150e8);
  plVar5[0xd] = (long)(plVar5 + 0xe);
  plVar5[0xc] = (long)(plVar5 + 0xd);
  *(undefined8 *)((long)plVar5 + 0xc) = 0xffffffffffffffff;
  plVar5[0xb] = (long)(plVar5 + 0xc);
  plVar5[3] = -0xc0800000;
  plVar5[5] = 0;
  plVar5[6] = 0;
  *plVar5 = (long)&DAT_7103987b08;
  *(undefined4 *)(plVar5 + 4) = 0xffffffff;
  plVar5[10] = (long)(plVar5 + 0xb);
  plVar7 = plVar5 + 9;
  *plVar7 = (long)(plVar5 + 10);
  plVar5[7] = (long)plVar7;
  plVar5[8] = (long)plVar7;
  if (plVar5 + 0xf != (long *)0x0) {
    plVar5[6] = (long)(plVar5 + 0xf);
    *(undefined4 *)((long)plVar5 + 0x2c) = 6;
  }
  *(undefined4 *)(plVar5 + 0x15) = 0;
  *(undefined1 *)(plVar5 + 0x1a) = 1;
  plVar5[0x16] = 0;
  plVar5[0x17] = 0;
  *(undefined4 *)((long)plVar5 + 0xd4) = 0;
  *(undefined1 *)(plVar5 + 0x1b) = 0;
  plVar5[0x18] = 0;
  plVar5[0x19] = 0;
  thunk_EXT_FUN_02e95df0(plVar5 + 0x1c,0,0x1010);
  lVar8 = 0x114c;
  lVar4 = 0x10fc;
  lVar6 = 0;
  do {
    *(long *)((long)plVar5 + lVar6 + 0x10f0) = (long)plVar5 + lVar4;
    lVar1 = lVar6 + 0xa0;
    lVar2 = (long)plVar5 + lVar8;
    *(undefined4 *)((long)plVar5 + lVar6 + 0x10f8) = 0x20;
    lVar8 = lVar8 + 0xa0;
    lVar4 = lVar4 + 0xa0;
    *(undefined2 *)((long)plVar5 + lVar6 + 0x113a) = 0;
    *(undefined2 *)((long)plVar5 + lVar6 + 0x10fc) = 0;
    *(long *)((long)plVar5 + lVar6 + 0x1140) = lVar2;
    *(undefined4 *)((long)plVar5 + lVar6 + 0x1148) = 0x20;
    *(undefined2 *)((long)plVar5 + lVar6 + 0x118a) = 0;
    *(undefined2 *)((long)plVar5 + lVar6 + 0x114c) = 0;
    lVar6 = lVar1;
  } while (lVar1 != 0x14000);
  *plVar5 = DAT_7103a65c90 + 0x10;
  FUN_710196d370(plVar5,param_1);
  return plVar5;
}



undefined8 FUN_71019d4e0c(long *param_1,undefined4 param_2)

{
  ulong uVar1;
  undefined8 uVar2;
  
  uVar1 = (**(code **)(*param_1 + 0x260))();
  if ((uVar1 & 1) != 0) {
                    // WARNING: Could not recover jumptable at 0x0071019d4e48. Too many branches
                    // WARNING: Treating indirect jump as call
    uVar2 = (**(code **)(*param_1 + 0x108))(param_1,param_2);
    return uVar2;
  }
  return 0;
}



void FUN_71019d4fd0(long *param_1)

{
  long *plVar1;
  long *plVar2;
  long lVar3;
  long *plVar4;
  long lVar5;
  long *local_18;
  
  *param_1 = DAT_7103a65b40 + 0x10;
  local_18 = param_1 + 0x25;
  if ((long *)param_1[0x25] != (long *)0x0) {
    FUN_7101969eb0((long *)param_1[0x25],&local_18);
  }
  *param_1 = DAT_7103a65b60 + 0x10;
  plVar2 = DAT_7103a65db8;
  if (param_1[0x17] != 0) {
    if (0 < (int)param_1[0x16]) {
      lVar3 = 0;
      plVar1 = (long *)param_1[0x18];
      do {
        plVar4 = *(long **)(param_1[0x17] + lVar3 * 8);
        lVar3 = lVar3 + 1;
        *plVar4 = (long)plVar1;
        param_1[0x18] = (long)plVar4;
        plVar1 = plVar4;
      } while (lVar3 < (int)param_1[0x16]);
    }
    lVar5 = param_1[0x19];
    *(undefined4 *)(param_1 + 0x16) = 0;
    lVar3 = *plVar2;
    if (lVar3 == 0) {
      FUN_71005fbbd0(lVar5);
    }
    else if ((lVar5 != 0) && (plVar1 = FUN_71024ef490(lVar3,lVar5), plVar1 != (long *)0x0)) {
      (**(code **)(*plVar1 + 0x38))(plVar1,lVar5);
    }
    *(undefined4 *)((long)param_1 + 0xcc) = 0;
    *(undefined8 *)((long)param_1 + 0xc4) = 0;
    *(undefined8 *)((long)param_1 + 0xbc) = 0;
    *(undefined8 *)((long)param_1 + 0xb4) = 0;
  }
  if ((char)param_1[0x1b] != '\0') {
    *(undefined1 *)(param_1 + 0x1b) = 0;
  }
  lVar3 = *plVar2;
  if (lVar3 == 0) {
    FUN_71005fbbd0((long)param_1);
  }
  else {
    plVar2 = FUN_71024ef490(lVar3,param_1);
    if (plVar2 != (long *)0x0) {
      (**(code **)(*plVar2 + 0x38))(plVar2,param_1);
    }
  }
  return;
}



bool FUN_71019d50fc(long param_1,uint param_2)

{
  undefined1 auStack_40 [8];
  long local_38;
  undefined1 auStack_30 [8];
  long local_28;
  
  local_38 = 0;
  FUN_7101572590((long)auStack_40,param_2);
  if (((local_38 != 0) && (*(long *)(local_38 + 0x70) != 0)) &&
     (*(int *)(*(long *)(local_38 + 0x70) + 0xc) == *(int *)(param_1 + 0x1214c))) {
    if (*(int *)(param_1 + 0xf0) < 0) {
      return true;
    }
    local_28 = 0;
    FUN_7101572590((long)auStack_30,param_2);
    if (local_28 != 0) {
      return *(int *)(param_1 + 0xf0) == *(int *)(*(long *)(local_28 + 0x20) + 0x14);
    }
  }
  return false;
}



bool FUN_71019d519c(undefined8 param_1,uint param_2)

{
  bool bVar1;
  long lVar2;
  
  lVar2 = FUN_710197c2a0(param_1,param_2);
  bVar1 = false;
  if (lVar2 != 0) {
    bVar1 = *(int *)(lVar2 + 0x18) == 4;
  }
  return bVar1;
}



undefined8 FUN_71019d51c0(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if (((*DAT_7103a65e68 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a65e68), iVar1 != 0))
  {
    *DAT_7103a65e60 = (long)&DAT_710398c220;
    thunk_EXT_FUN_02e95df0(DAT_7103a65e68);
  }
  if (param_2 != DAT_7103a65e60) {
    if (((*DAT_7103a65b50 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a65b50), iVar1 != 0)
       ) {
      *DAT_7103a65b48 = DAT_7103a59af0 + 0x10;
      thunk_EXT_FUN_02e95df0(DAT_7103a65b50);
    }
    if (param_2 != DAT_7103a65b48) {
      param_1 = 0;
    }
  }
  return param_1;
}



undefined8 * FUN_71019d52bc(void)

{
  int iVar1;
  
  if (((*DAT_7103a65e68 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a65e68), iVar1 != 0))
  {
    *DAT_7103a65e60 = &DAT_710398c220;
    thunk_EXT_FUN_02e95df0(DAT_7103a65e68);
  }
  return DAT_7103a65e60;
}



uint FUN_71019d5520(long *param_1)

{
  uint uVar1;
  
  uVar1 = (**(code **)(*param_1 + 0x108))();
  return uVar1 & 1;
}



undefined8 FUN_71019d554c(long param_1,uint param_2)

{
  int *piVar1;
  uint *puVar2;
  uint uVar3;
  int iVar4;
  undefined8 *puVar5;
  ulong uVar6;
  long lVar7;
  uint local_44;
  long local_40;
  long local_38;
  undefined8 uStack_30;
  long local_28;
  
  uVar3 = *(uint *)(param_1 + 0xe214);
  if ((int)uVar3 < 0) {
LAB_71019d55bc:
    piVar1 = (int *)(param_1 + 0x1c);
    uVar3 = *(uint *)(param_1 + 0x20);
  }
  else {
    lVar7 = *(long *)((uint *)*DAT_7103a59c40 + 2);
    if (lVar7 == 0) goto LAB_71019d55bc;
    if (*(uint *)*DAT_7103a59c40 <= uVar3) {
      uVar3 = 0;
    }
    piVar1 = (int *)(param_1 + 0xe210);
    if (*(int *)(lVar7 + (ulong)uVar3 * 0x10 + 4) != *(int *)(param_1 + 0xe210)) {
      piVar1 = (int *)(param_1 + 0x1c);
    }
    uVar3 = piVar1[1];
  }
  if ((int)uVar3 < 0) {
    return 0;
  }
  lVar7 = *(long *)((uint *)*DAT_7103a59c40 + 2);
  if (lVar7 == 0) {
    return 0;
  }
  if (*(uint *)*DAT_7103a59c40 <= uVar3) {
    uVar3 = 0;
  }
  if (*(int *)(lVar7 + (ulong)uVar3 * 0x10 + 4) != *piVar1) {
    return 0;
  }
  puVar5 = *(undefined8 **)(lVar7 + (ulong)uVar3 * 0x10 + 8);
  if (puVar5 == (undefined8 *)0x0) {
    puVar5 = FUN_7100baff84();
  }
  iVar4 = *(int *)((long)puVar5 + 0xac);
  lVar7 = (long)iVar4 + (long)puVar5 + 0xac;
  if (iVar4 == 0 || lVar7 == 0) {
    return 0;
  }
  uVar3 = *(uint *)(lVar7 + 0x1250);
  if (uVar3 != 0xce9a5baa) {
    if (uVar3 == 0) {
      if ((*(int *)(lVar7 + 0x1284) != 0) &&
         (FUN_710150bf70(&uStack_30,(uint *)(lVar7 + 0x1284)), local_28 != 0)) {
        local_40 = DAT_7103a61968 + 0x10;
        local_38 = 0;
        uVar6 = FUN_710150d040((long)&uStack_30,2,(long)&local_40);
        if ((uVar6 & 1) != 0) {
          puVar2 = DAT_7103a5d098;
          if (local_38 != 0) {
            puVar2 = (uint *)(local_38 + 0x50);
          }
          local_44 = *puVar2;
          uVar3 = local_44;
          if (local_44 != 0) goto LAB_71019d569c;
        }
      }
    }
    else {
LAB_71019d569c:
      local_44 = uVar3;
      FUN_71015081f0(&uStack_30,&local_44);
      if (((local_28 != 0) && (*(int *)(local_28 + 0x68) == 1)) &&
         (*(uint *)(lVar7 + 0x1290) < 0x12f && *(uint *)(lVar7 + 0x1290) == param_2)) {
        return 1;
      }
    }
  }
  uVar3 = *(uint *)(lVar7 + 0x1258);
  if (uVar3 == 0) {
    if ((*(int *)(lVar7 + 0x1284) == 0) ||
       (FUN_710150bf70(&uStack_30,(uint *)(lVar7 + 0x1284)), local_28 == 0)) goto LAB_71019d5788;
    local_40 = DAT_7103a61968 + 0x10;
    local_38 = 0;
    uVar6 = FUN_710150d040((long)&uStack_30,3,(long)&local_40);
    if ((uVar6 & 1) == 0) goto LAB_71019d5788;
    puVar2 = DAT_7103a5d098;
    if (local_38 != 0) {
      puVar2 = (uint *)(local_38 + 0x50);
    }
    local_44 = *puVar2;
    uVar3 = local_44;
    if (local_44 == 0) goto LAB_71019d5788;
  }
  else if (uVar3 == 0x4197b1e0) goto LAB_71019d5788;
  local_44 = uVar3;
  FUN_71015081f0(&uStack_30,&local_44);
  if (((local_28 != 0) && (*(int *)(local_28 + 0x68) == 1)) &&
     ((*(uint *)(lVar7 + 0x1294) < 0x12f && (*(uint *)(lVar7 + 0x1294) == param_2)))) {
    return 1;
  }
LAB_71019d5788:
  uVar3 = *(uint *)(lVar7 + 0x1278);
  if (uVar3 == 0) {
    if (*(int *)(lVar7 + 0x1284) == 0) {
      return 0;
    }
    FUN_710150bf70(&uStack_30,(uint *)(lVar7 + 0x1284));
    if (local_28 == 0) {
      return 0;
    }
    local_40 = DAT_7103a61968 + 0x10;
    local_38 = 0;
    uVar6 = FUN_710150d040((long)&uStack_30,7,(long)&local_40);
    if ((uVar6 & 1) == 0) {
      return 0;
    }
    puVar2 = DAT_7103a5d098;
    if (local_38 != 0) {
      puVar2 = (uint *)(local_38 + 0x50);
    }
    local_44 = *puVar2;
    if (*puVar2 == 0) {
      return 0;
    }
  }
  else {
    local_44 = uVar3;
    if (uVar3 == 0x45e11c6) {
      return 0;
    }
  }
  FUN_71015081f0(&uStack_30,&local_44);
  if ((((local_28 != 0) && (*(int *)(local_28 + 0x68) == 1)) && (*(uint *)(lVar7 + 0x1298) < 0x12f))
     && (*(uint *)(lVar7 + 0x1298) == param_2)) {
    return 1;
  }
  return 0;
}



undefined8 * FUN_71019d59f0(void)

{
  int iVar1;
  
  if (((DAT_71040e3e68 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_71040e3e68), iVar1 != 0))
  {
    DAT_71040e3e60 = DAT_7103a65bf0 + 0x10;
    thunk_EXT_FUN_02e95df0(&DAT_71040e3e68);
  }
  return &DAT_71040e3e60;
}



void FUN_71019d5b20(long *param_1)

{
  long *plVar1;
  long *plVar2;
  long lVar3;
  long *plVar4;
  long lVar5;
  
  *param_1 = DAT_7103a65b60 + 0x10;
  plVar2 = DAT_7103a65db8;
  if (param_1[0x17] != 0) {
    if (0 < (int)param_1[0x16]) {
      lVar3 = 0;
      plVar1 = (long *)param_1[0x18];
      do {
        plVar4 = *(long **)(param_1[0x17] + lVar3 * 8);
        lVar3 = lVar3 + 1;
        *plVar4 = (long)plVar1;
        param_1[0x18] = (long)plVar4;
        plVar1 = plVar4;
      } while (lVar3 < (int)param_1[0x16]);
    }
    lVar5 = param_1[0x19];
    *(undefined4 *)(param_1 + 0x16) = 0;
    lVar3 = *plVar2;
    if (lVar3 == 0) {
      FUN_71005fbbd0(lVar5);
    }
    else if ((lVar5 != 0) && (plVar1 = FUN_71024ef490(lVar3,lVar5), plVar1 != (long *)0x0)) {
      (**(code **)(*plVar1 + 0x38))(plVar1,lVar5);
    }
    *(undefined4 *)((long)param_1 + 0xcc) = 0;
    *(undefined8 *)((long)param_1 + 0xc4) = 0;
    *(undefined8 *)((long)param_1 + 0xbc) = 0;
    *(undefined8 *)((long)param_1 + 0xb4) = 0;
  }
  if ((char)param_1[0x1b] != '\0') {
    *(undefined1 *)(param_1 + 0x1b) = 0;
  }
  lVar3 = *plVar2;
  if (lVar3 != 0) {
    plVar2 = FUN_71024ef490(lVar3,param_1);
    if (plVar2 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071019d5c18. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*plVar2 + 0x38))(plVar2,param_1);
      return;
    }
    return;
  }
  FUN_71005fbbd0((long)param_1);
  return;
}



uint FUN_71019d6568(long *param_1)

{
  uint uVar1;
  
  uVar1 = (**(code **)(*param_1 + 0x108))();
  return uVar1 & 1;
}



void FUN_71019d673c(undefined1 param_1 [16],float param_2,undefined8 param_3,long param_4,
                   uint param_5)

{
  byte bVar1;
  int iVar2;
  undefined8 *puVar3;
  long lVar4;
  undefined1 extraout_q0 [16];
  undefined1 auVar5 [16];
  undefined1 extraout_q0_00 [16];
  undefined8 auStack_50 [3];
  long local_38;
  undefined8 local_30;
  char local_24 [4];
  
  local_30 = 0;
  local_38 = DAT_7103a61990 + 0x10;
  puVar3 = *(undefined8 **)(*DAT_7103a59ec8 + 0x30);
  lVar4 = 0;
  if (puVar3 != (undefined8 *)0x0) {
    if ((*DAT_7103a619a8 & 1) == 0) {
      iVar2 = thunk_EXT_FUN_02e95df0(DAT_7103a619a8);
      param_1 = extraout_q0_00;
      if (iVar2 != 0) {
        *DAT_7103a619a0 = DAT_7103a59e80 + 0x10;
        param_1 = thunk_EXT_FUN_02e95df0(DAT_7103a619a8);
      }
    }
    lVar4 = (**(code **)*puVar3)(param_1,puVar3,DAT_7103a619a0);
  }
  if ((-1 < (int)param_5) && ((int)param_5 < *(int *)(lVar4 + 0x18))) {
    local_30 = *(undefined8 *)(*(long *)(lVar4 + 0x20) + (ulong)param_5 * 8);
    (**(code **)(local_38 + 0x48))(auStack_50,&local_38);
    local_24[0] = '\0';
    iVar2 = FUN_710292ebe0(param_4,*(long **)(param_4 + 0x18),(long *)"T_Text_00",auStack_50,0,-1,
                           local_24,0);
    if ((iVar2 != 0) && (local_24[0] != '\0')) {
      bVar1 = *(byte *)(param_4 + 0x90);
      auVar5 = extraout_q0;
      if ((bVar1 & 1) != 0) {
        auVar5 = FUN_7102932010(extraout_q0,param_2,param_4,*(long **)(param_4 + 0x18));
        bVar1 = *(byte *)(param_4 + 0x90);
      }
      if (((bVar1 >> 2 & 1) != 0) && (lVar4 = *(long *)(param_4 + 0x88), lVar4 != 0)) {
        FUN_7102932010(auVar5,param_2,lVar4,*(long **)(lVar4 + 0x18));
      }
    }
  }
  return;
}



// WARNING: Restarted to delay deadcode elimination for space: stack

void FUN_71019d68a0(long *param_1,undefined4 param_2)

{
  short *psVar1;
  ushort *puVar2;
  long lVar3;
  uint uVar4;
  ulong uVar5;
  long *plVar6;
  short *psVar7;
  ushort *puVar8;
  ushort *puVar9;
  long lVar10;
  ushort local_f4;
  undefined1 auStack_f2 [6];
  undefined8 local_ec;
  undefined8 local_e4;
  undefined8 uStack_dc;
  undefined8 local_d4;
  undefined8 uStack_cc;
  undefined8 local_c4;
  undefined6 uStack_bc;
  undefined2 local_b6;
  ushort *local_b0;
  int local_a8;
  ushort local_a4;
  undefined6 uStack_a2;
  undefined8 local_9c;
  undefined8 local_94;
  undefined8 uStack_8c;
  undefined8 local_84;
  undefined8 uStack_7c;
  undefined8 local_74;
  undefined6 uStack_6c;
  undefined2 local_66;
  
  *(undefined2 *)(param_1 + 1) = 0;
  *(undefined8 *)((long)param_1 + 0xc) = 0xffffffffffffffff;
  *(undefined1 *)((long)param_1 + 10) = 0;
  param_1[0xe] = 0;
  param_1[0xd] = (long)(param_1 + 0xe);
  *(undefined2 *)((long)param_1 + 0x14) = 0;
  param_1[5] = 0;
  param_1[6] = 0;
  *param_1 = (long)&DAT_7103987b08;
  param_1[0xc] = (long)(param_1 + 0xd);
  param_1[3] = -0xc0800000;
  param_1[0xb] = (long)(param_1 + 0xc);
  *(undefined4 *)(param_1 + 4) = 0xffffffff;
  param_1[10] = (long)(param_1 + 0xb);
  plVar6 = param_1 + 9;
  *plVar6 = (long)(param_1 + 10);
  param_1[7] = (long)plVar6;
  param_1[8] = (long)plVar6;
  if (param_1 + 0xf != (long *)0x0) {
    param_1[6] = (long)(param_1 + 0xf);
    *(undefined4 *)((long)param_1 + 0x2c) = 6;
  }
  *(undefined4 *)(param_1 + 0x15) = 0;
  param_1[0x16] = 0;
  param_1[0x17] = 0;
  *(undefined1 *)(param_1 + 0x1a) = 1;
  *(undefined4 *)((long)param_1 + 0xd4) = 0;
  *(undefined1 *)(param_1 + 0x1b) = 0;
  param_1[0x18] = 0;
  param_1[0x19] = 0;
  lVar10 = DAT_7103a65b58 + 0x10;
  *(undefined4 *)(param_1 + 0x1e) = param_2;
  *param_1 = lVar10;
  param_1[0x1c] = 0;
  param_1[0x1d] = 0;
  lVar10 = 0;
  do {
    lVar3 = lVar10 + 0xa0;
    *(undefined4 *)((long)param_1 + lVar10 + 0x100) = 0x20;
    *(undefined2 *)((long)param_1 + lVar10 + 0x142) = 0;
    *(long *)((long)param_1 + lVar10 + 0xf8) = (long)param_1 + lVar10 + 0x104;
    *(undefined2 *)((long)param_1 + lVar10 + 0x104) = 0;
    *(long *)((long)param_1 + lVar10 + 0x148) = (long)param_1 + lVar10 + 0x154;
    *(undefined4 *)((long)param_1 + lVar10 + 0x150) = 0x20;
    *(undefined2 *)((long)param_1 + lVar10 + 0x192) = 0;
    *(undefined2 *)((long)param_1 + lVar10 + 0x154) = 0;
    lVar10 = lVar3;
  } while (lVar3 != 0x14000);
  lVar10 = 0;
  local_b6 = 0;
  local_b0 = &local_a4;
  local_f4 = 0;
  local_a8 = 0x20;
  local_66 = 0;
  local_a4 = 0;
  do {
    plVar6 = param_1 + lVar10 * 0x14 + 0x1f;
    puVar9 = (ushort *)*plVar6;
    if (puVar9 != &local_f4) {
      if (&local_f4 == (ushort *)0x0) {
LAB_71019d6ae0:
        uVar5 = 0;
      }
      else {
        uVar5 = (ulong)local_f4;
        if (local_f4 != 0) {
          uVar5 = 0;
          psVar7 = (short *)(auStack_f2 + 4);
          do {
            if (psVar7[-2] == 0) {
              uVar5 = uVar5 + 1;
              break;
            }
            if (psVar7[-1] == 0) {
              uVar5 = uVar5 + 2;
              break;
            }
            if (*psVar7 == 0) {
              uVar5 = uVar5 + 3;
              break;
            }
            if (psVar7[1] == 0) {
              uVar5 = uVar5 + 4;
              break;
            }
            if (uVar5 == 0x3ffffc) goto LAB_71019d6ae0;
            psVar1 = psVar7 + 2;
            uVar5 = uVar5 + 5;
            psVar7 = psVar7 + 5;
          } while (*psVar1 != 0);
        }
      }
      uVar4 = (uint)uVar5;
      if ((int)plVar6[1] <= (int)(uint)uVar5) {
        uVar4 = (int)plVar6[1] - 1;
      }
      uVar5 = -(ulong)(uVar4 >> 0x1f) & 0xfffffffe00000000 | (ulong)uVar4 << 1;
      thunk_EXT_FUN_02e95df0(puVar9,&local_f4,uVar5);
      *(undefined2 *)((long)puVar9 + uVar5) = 0;
    }
    *(undefined8 *)((long)plVar6 + 0x2c) = local_d4;
    *(undefined8 *)((long)plVar6 + 0x34) = uStack_cc;
    *(undefined8 *)((long)plVar6 + 0x3c) = local_c4;
    *(ulong *)((long)plVar6 + 0x44) = CONCAT26(local_b6,uStack_bc);
    *(ulong *)((long)plVar6 + 0xc) = CONCAT62(auStack_f2,local_f4);
    *(undefined8 *)((long)plVar6 + 0x14) = local_ec;
    *(undefined8 *)((long)plVar6 + 0x24) = uStack_dc;
    *(undefined8 *)((long)plVar6 + 0x1c) = local_e4;
    local_b0[(long)local_a8 + -1] = 0;
    puVar9 = (ushort *)param_1[lVar10 * 0x14 + 0x29];
    if (puVar9 != local_b0) {
      if (local_b0 == (ushort *)0x0) {
LAB_71019d6a00:
        uVar5 = 0;
      }
      else {
        uVar5 = (ulong)*local_b0;
        if (*local_b0 != 0) {
          uVar5 = 0;
          puVar8 = local_b0 + 3;
          do {
            if (puVar8[-2] == 0) {
              uVar5 = uVar5 + 1;
              break;
            }
            if (puVar8[-1] == 0) {
              uVar5 = uVar5 + 2;
              break;
            }
            if (*puVar8 == 0) {
              uVar5 = uVar5 + 3;
              break;
            }
            if (puVar8[1] == 0) {
              uVar5 = uVar5 + 4;
              break;
            }
            if (uVar5 == 0x3ffffc) goto LAB_71019d6a00;
            puVar2 = puVar8 + 2;
            uVar5 = uVar5 + 5;
            puVar8 = puVar8 + 5;
          } while (*puVar2 != 0);
        }
      }
      uVar4 = (uint)uVar5;
      if ((int)param_1[lVar10 * 0x14 + 0x2a] <= (int)(uint)uVar5) {
        uVar4 = (int)param_1[lVar10 * 0x14 + 0x2a] - 1;
      }
      uVar5 = -(ulong)(uVar4 >> 0x1f) & 0xfffffffe00000000 | (ulong)uVar4 << 1;
      thunk_EXT_FUN_02e95df0(puVar9,local_b0,uVar5);
      *(undefined2 *)((long)puVar9 + uVar5) = 0;
    }
    lVar3 = lVar10 * 0xa0;
    lVar10 = lVar10 + 1;
    *(undefined8 *)((long)param_1 + lVar3 + 0x174) = local_84;
    *(undefined8 *)((long)param_1 + lVar3 + 0x17c) = uStack_7c;
    *(undefined8 *)((long)param_1 + lVar3 + 0x184) = local_74;
    *(ulong *)((long)param_1 + lVar3 + 0x18c) = CONCAT26(local_66,uStack_6c);
    *(ulong *)((long)param_1 + lVar3 + 0x154) = CONCAT62(uStack_a2,local_a4);
    *(undefined8 *)((long)param_1 + lVar3 + 0x15c) = local_9c;
    *(undefined8 *)((long)param_1 + lVar3 + 0x164) = local_94;
    *(undefined8 *)((long)param_1 + lVar3 + 0x16c) = uStack_8c;
    if (lVar10 == 0x200) {
      return;
    }
  } while( true );
}



int FUN_71019d6d30(void)

{
  int iVar1;
  undefined8 *puVar2;
  long lVar3;
  
  puVar2 = *(undefined8 **)(*DAT_7103a59ec8 + 0x60);
  if ((*DAT_7103a62bd8 & 1) == 0) {
    iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a62bd8);
    if (iVar1 != 0) {
      *DAT_7103a62bd0 = DAT_7103a59e80 + 0x10;
      thunk_EXT_FUN_02e95df0(DAT_7103a62bd8);
    }
  }
  lVar3 = (**(code **)*puVar2)(puVar2,DAT_7103a62bd0);
  return *(int *)(lVar3 + 0x20) + 1;
}



undefined8 FUN_71019d6dd0(long *param_1,undefined4 param_2)

{
  ulong uVar1;
  undefined8 uVar2;
  
  uVar1 = (**(code **)(*param_1 + 0x260))();
  if ((uVar1 & 1) != 0) {
                    // WARNING: Could not recover jumptable at 0x0071019d6e0c. Too many branches
                    // WARNING: Treating indirect jump as call
    uVar2 = (**(code **)(*param_1 + 0x108))(param_1,param_2);
    return uVar2;
  }
  return 0;
}



ulong FUN_71019d6eb0(long *param_1,uint *param_2,uint *param_3)

{
  int iVar1;
  long *plVar2;
  long *plVar3;
  byte *pbVar4;
  long lVar5;
  int iVar6;
  ulong uVar7;
  undefined8 *puVar8;
  long local_70;
  int *local_68;
  long lStack_60;
  int *local_58;
  
  lVar5 = DAT_7103a62d98;
  pbVar4 = DAT_7103a62bd8;
  plVar2 = DAT_7103a59ec8;
  local_70 = DAT_7103a62d98 + 0x10;
  puVar8 = *(undefined8 **)(*DAT_7103a59ec8 + 0x60);
  if (puVar8 == (undefined8 *)0x0) {
    local_68 = (int *)0x0;
  }
  else {
    if (((*DAT_7103a62bd8 & 1) == 0) && (iVar6 = thunk_EXT_FUN_02e95df0(DAT_7103a62bd8), iVar6 != 0)
       ) {
      *DAT_7103a62bd0 = DAT_7103a59e80 + 0x10;
      thunk_EXT_FUN_02e95df0(DAT_7103a62bd8);
    }
    plVar3 = DAT_7103a62bd0;
    (**(code **)*puVar8)(puVar8,DAT_7103a62bd0);
    puVar8 = *(undefined8 **)(*plVar2 + 0x60);
    lStack_60 = lVar5 + 0x10;
    local_68 = (int *)0x0;
    if (puVar8 != (undefined8 *)0x0) {
      if (((*pbVar4 & 1) == 0) && (iVar6 = thunk_EXT_FUN_02e95df0(DAT_7103a62bd8), iVar6 != 0)) {
        *plVar3 = DAT_7103a59e80 + 0x10;
        thunk_EXT_FUN_02e95df0(DAT_7103a62bd8);
      }
      (**(code **)*puVar8)(puVar8,DAT_7103a62bd0);
    }
  }
  local_58 = (int *)0x0;
  FUN_7101554fd0((long)&local_70,*param_2);
  if (local_68 != (int *)0x0) {
    FUN_7101554fd0((long)&lStack_60,*param_3);
    if (local_58 != (int *)0x0) {
      iVar6 = 1;
      if (*local_68 != -0x4928959e) {
        iVar6 = 2;
      }
      iVar1 = 0;
      if (*local_68 != -0x2de49a4a) {
        iVar1 = iVar6;
      }
      if (*local_58 == -0x4928959e) {
        iVar6 = -1;
      }
      else if (*local_58 == -0x2de49a4a) {
        iVar6 = 0;
      }
      else {
        if (iVar1 == 2) goto LAB_71019d6ff4;
        iVar6 = -2;
      }
      return (ulong)(uint)(iVar6 + iVar1);
    }
  }
LAB_71019d6ff4:
  uVar7 = FUN_710196e2c4(param_1,(int *)param_2,(int *)param_3);
  return uVar7;
}



bool FUN_71019d73c0(long param_1,uint param_2)

{
  int iVar1;
  undefined8 *puVar2;
  long *plVar3;
  long local_30;
  uint *local_28;
  
  local_30 = DAT_7103a62d98 + 0x10;
  puVar2 = *(undefined8 **)(*DAT_7103a59ec8 + 0x60);
  if (puVar2 != (undefined8 *)0x0) {
    if ((*DAT_7103a62bd8 & 1) == 0) {
      iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a62bd8);
      if (iVar1 != 0) {
        *DAT_7103a62bd0 = DAT_7103a59e80 + 0x10;
        thunk_EXT_FUN_02e95df0(DAT_7103a62bd8);
      }
    }
    (**(code **)*puVar2)(puVar2,DAT_7103a62bd0);
  }
  local_28 = (uint *)0x0;
  FUN_7101554fd0((long)&local_30,param_2);
  if ((local_28 != (uint *)0x0) &&
     (plVar3 = *(long **)(*(long *)(*DAT_7103a5c098 + 0x80) + 0x26ea8), plVar3 != (long *)0x0)) {
    do {
      if (*(uint *)(plVar3 + 3) <= *local_28) {
        if (*local_28 <= *(uint *)(plVar3 + 3)) {
          plVar3 = plVar3 + 4;
          goto LAB_71019d7488;
        }
        plVar3 = plVar3 + 1;
      }
      plVar3 = (long *)*plVar3;
    } while (plVar3 != (long *)0x0);
  }
  plVar3 = (long *)(param_1 + 0xf0);
LAB_71019d7488:
  return (int)plVar3[3] == 1;
}



undefined4 FUN_71019d7af0(long param_1,uint param_2)

{
  int iVar1;
  undefined8 *puVar2;
  long *plVar3;
  long local_30;
  uint *local_28;
  
  local_30 = DAT_7103a62d98 + 0x10;
  puVar2 = *(undefined8 **)(*DAT_7103a59ec8 + 0x60);
  if (puVar2 != (undefined8 *)0x0) {
    if ((*DAT_7103a62bd8 & 1) == 0) {
      iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a62bd8);
      if (iVar1 != 0) {
        *DAT_7103a62bd0 = DAT_7103a59e80 + 0x10;
        thunk_EXT_FUN_02e95df0(DAT_7103a62bd8);
      }
    }
    (**(code **)*puVar2)(puVar2,DAT_7103a62bd0);
  }
  local_28 = (uint *)0x0;
  FUN_7101554fd0((long)&local_30,param_2);
  if ((local_28 != (uint *)0x0) &&
     (plVar3 = *(long **)(*(long *)(*DAT_7103a5c098 + 0x80) + 0x26ea8), plVar3 != (long *)0x0)) {
    do {
      if (*(uint *)(plVar3 + 3) <= *local_28) {
        if (*local_28 <= *(uint *)(plVar3 + 3)) {
          plVar3 = plVar3 + 4;
          goto LAB_71019d7bb8;
        }
        plVar3 = plVar3 + 1;
      }
      plVar3 = (long *)*plVar3;
    } while (plVar3 != (long *)0x0);
  }
  plVar3 = (long *)(param_1 + 0xf0);
LAB_71019d7bb8:
  return (int)plVar3[2];
}



int FUN_71019d7c30(long *param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  int iVar2;
  ulong uVar3;
  
  uVar3 = (**(code **)(*param_1 + 0x238))();
  if ((uVar3 & 1) == 0) {
    iVar1 = (**(code **)(*param_1 + 0x138))(param_1,param_2);
    if (iVar1 < 1) {
      iVar2 = 0x7fffffff;
    }
    else {
      iVar2 = 0;
      if (iVar1 != 0) {
        iVar2 = param_3 / iVar1;
      }
    }
  }
  else {
    iVar2 = 1;
  }
  return iVar2;
}



int FUN_71019d7c9c(long *param_1,uint param_2)

{
  int iVar1;
  undefined8 *puVar2;
  long local_30 [2];
  
  local_30[0] = DAT_7103a62d98 + 0x10;
  puVar2 = *(undefined8 **)(*DAT_7103a59ec8 + 0x60);
  if (puVar2 != (undefined8 *)0x0) {
    if ((*DAT_7103a62bd8 & 1) == 0) {
      iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a62bd8);
      if (iVar1 != 0) {
        *DAT_7103a62bd0 = DAT_7103a59e80 + 0x10;
        thunk_EXT_FUN_02e95df0(DAT_7103a62bd8);
      }
    }
    (**(code **)*puVar2)(puVar2,DAT_7103a62bd0);
  }
  FUN_7101554fd0((long)local_30,param_2);
  iVar1 = (**(code **)(*param_1 + 0x128))(param_1,param_2,0xffffffff);
  return 99 - iVar1;
}



bool FUN_71019d8bfc(undefined8 param_1,uint param_2)

{
  bool bVar1;
  int iVar2;
  undefined8 *puVar3;
  long local_30;
  long local_28;
  
  local_30 = DAT_7103a62d98 + 0x10;
  puVar3 = *(undefined8 **)(*DAT_7103a59ec8 + 0x60);
  if (puVar3 != (undefined8 *)0x0) {
    if ((*DAT_7103a62bd8 & 1) == 0) {
      iVar2 = thunk_EXT_FUN_02e95df0(DAT_7103a62bd8);
      if (iVar2 != 0) {
        *DAT_7103a62bd0 = DAT_7103a59e80 + 0x10;
        thunk_EXT_FUN_02e95df0(DAT_7103a62bd8);
      }
    }
    (**(code **)*puVar3)(puVar3,DAT_7103a62bd0);
  }
  local_28 = 0;
  FUN_7101554fd0((long)&local_30,param_2);
  if ((local_28 == 0) || (*(char *)(*(long *)(local_28 + 0x78) + 0x20) == '\0')) {
    bVar1 = false;
  }
  else {
    bVar1 = *(char *)(*(long *)(local_28 + 0x78) + 0x21) == '\0';
  }
  return bVar1;
}



void FUN_71019d8cf0(undefined8 *param_1)

{
  long lVar1;
  undefined8 *puVar2;
  
  *(undefined2 *)(param_1 + 1) = 0;
  *(undefined8 *)((long)param_1 + 0xc) = 0xffffffffffffffff;
  *(undefined1 *)((long)param_1 + 10) = 0;
  param_1[0xe] = 0;
  param_1[0xd] = param_1 + 0xe;
  *(undefined2 *)((long)param_1 + 0x14) = 0;
  param_1[5] = 0;
  param_1[6] = 0;
  *param_1 = &DAT_7103987b08;
  param_1[0xc] = param_1 + 0xd;
  param_1[3] = 0xffffffff3f800000;
  param_1[0xb] = param_1 + 0xc;
  *(undefined4 *)(param_1 + 4) = 0xffffffff;
  param_1[10] = param_1 + 0xb;
  puVar2 = param_1 + 9;
  *puVar2 = param_1 + 10;
  param_1[7] = puVar2;
  param_1[8] = puVar2;
  if (param_1 + 0xf != (undefined8 *)0x0) {
    param_1[6] = param_1 + 0xf;
    *(undefined4 *)((long)param_1 + 0x2c) = 6;
  }
  *(undefined4 *)(param_1 + 0x15) = 0;
  *(undefined1 *)(param_1 + 0x1a) = 1;
  param_1[0x16] = 0;
  param_1[0x17] = 0;
  *(undefined4 *)((long)param_1 + 0xd4) = 0;
  *(undefined1 *)(param_1 + 0x1b) = 0;
  *param_1 = &DAT_710398c730;
  *(undefined4 *)(param_1 + 0x20) = 0;
  *(undefined1 *)((long)param_1 + 0x104) = 0;
  param_1[0x21] = 0;
  param_1[0x18] = 0;
  param_1[0x19] = 0;
  param_1[0x1c] = 0;
  param_1[0x1d] = 0;
  lVar1 = DAT_7103a65e90 + 0x10;
  *(undefined1 *)(param_1 + 0x22) = 0;
  param_1[0x1e] = lVar1;
  param_1[0x1f] = 0;
  lVar1 = 0x40;
  do {
    *(undefined4 *)(param_1 + 0x24) = 0x20;
    lVar1 = lVar1 + -1;
    param_1[0x23] = (long)param_1 + 0x124;
    *(undefined2 *)((long)param_1 + 0x162) = 0;
    *(undefined2 *)((long)param_1 + 0x124) = 0;
    param_1[0x2d] = (long)param_1 + 0x174;
    *(undefined4 *)(param_1 + 0x2e) = 0x20;
    *(undefined2 *)((long)param_1 + 0x1b2) = 0;
    *(undefined2 *)((long)param_1 + 0x174) = 0;
    param_1 = param_1 + 0x14;
  } while (lVar1 != 0);
  return;
}



void FUN_71019d8fd0(long *param_1)

{
  long *plVar1;
  long *plVar2;
  long lVar3;
  long *plVar4;
  long lVar5;
  
  *param_1 = DAT_7103a65b60 + 0x10;
  plVar2 = DAT_7103a65db8;
  if (param_1[0x17] != 0) {
    if (0 < (int)param_1[0x16]) {
      lVar3 = 0;
      plVar1 = (long *)param_1[0x18];
      do {
        plVar4 = *(long **)(param_1[0x17] + lVar3 * 8);
        lVar3 = lVar3 + 1;
        *plVar4 = (long)plVar1;
        param_1[0x18] = (long)plVar4;
        plVar1 = plVar4;
      } while (lVar3 < (int)param_1[0x16]);
    }
    lVar5 = param_1[0x19];
    *(undefined4 *)(param_1 + 0x16) = 0;
    lVar3 = *plVar2;
    if (lVar3 == 0) {
      FUN_71005fbbd0(lVar5);
    }
    else if ((lVar5 != 0) && (plVar1 = FUN_71024ef490(lVar3,lVar5), plVar1 != (long *)0x0)) {
      (**(code **)(*plVar1 + 0x38))(plVar1,lVar5);
    }
    *(undefined4 *)((long)param_1 + 0xcc) = 0;
    *(undefined8 *)((long)param_1 + 0xc4) = 0;
    *(undefined8 *)((long)param_1 + 0xbc) = 0;
    *(undefined8 *)((long)param_1 + 0xb4) = 0;
  }
  if ((char)param_1[0x1b] != '\0') {
    *(undefined1 *)(param_1 + 0x1b) = 0;
  }
  lVar3 = *plVar2;
  if (lVar3 != 0) {
    plVar2 = FUN_71024ef490(lVar3,param_1);
    if (plVar2 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071019d90c8. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*plVar2 + 0x38))(plVar2,param_1);
      return;
    }
    return;
  }
  FUN_71005fbbd0((long)param_1);
  return;
}



bool FUN_71019d90f0(undefined8 param_1,uint param_2)

{
  bool bVar1;
  int iVar2;
  undefined8 *puVar3;
  long local_30;
  long local_28;
  
  local_30 = DAT_7103a62d98 + 0x10;
  puVar3 = *(undefined8 **)(*DAT_7103a59ec8 + 0x60);
  if (puVar3 != (undefined8 *)0x0) {
    if ((*DAT_7103a62bd8 & 1) == 0) {
      iVar2 = thunk_EXT_FUN_02e95df0(DAT_7103a62bd8);
      if (iVar2 != 0) {
        *DAT_7103a62bd0 = DAT_7103a59e80 + 0x10;
        thunk_EXT_FUN_02e95df0(DAT_7103a62bd8);
      }
    }
    (**(code **)*puVar3)(puVar3,DAT_7103a62bd0);
  }
  local_28 = 0;
  FUN_7101554fd0((long)&local_30,param_2);
  if ((local_28 == 0) || (*(char *)(*(long *)(local_28 + 0x78) + 0x20) == '\0')) {
    bVar1 = false;
  }
  else {
    bVar1 = *(char *)(*(long *)(local_28 + 0x78) + 0x21) != '\0';
  }
  return bVar1;
}



undefined8 * FUN_71019d92d0(void)

{
  int iVar1;
  
  if (((DAT_71040e3e78 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_71040e3e78), iVar1 != 0))
  {
    DAT_71040e3e70 = &DAT_710398ce90;
    thunk_EXT_FUN_02e95df0(&DAT_71040e3e78);
  }
  return &DAT_71040e3e70;
}



undefined4 FUN_71019d9450(void)

{
  long lVar1;
  
  lVar1 = FUN_7100d53f40(DAT_710407a3f8);
  return *(undefined4 *)(lVar1 + 0x28);
}



undefined4 FUN_71019d956c(undefined8 param_1,uint param_2)

{
  undefined4 *puVar1;
  long lVar2;
  
  lVar2 = FUN_7100d53f40(*DAT_7103a59ec8);
  puVar1 = (undefined4 *)(*(long *)(lVar2 + 0x88) + (ulong)param_2 * 4);
  if (*(int *)(lVar2 + 0x80) <= (int)param_2 || 0x7fffffff < param_2) {
    puVar1 = DAT_7103a5cdf0;
  }
  return *puVar1;
}



bool FUN_71019d95c0(undefined8 param_1,uint param_2)

{
  bool bVar1;
  long lVar2;
  
  lVar2 = FUN_71019d9f00(param_2);
  bVar1 = false;
  if (lVar2 != 0) {
    bVar1 = *(int *)(lVar2 + 0x18) == 1;
  }
  return bVar1;
}



bool FUN_71019d95e8(undefined8 param_1,uint param_2)

{
  bool bVar1;
  long lVar2;
  
  lVar2 = FUN_71019d9f00(param_2);
  bVar1 = false;
  if (lVar2 != 0) {
    bVar1 = *(int *)(lVar2 + 0x18) == 0;
  }
  return bVar1;
}



bool FUN_71019d9610(undefined8 param_1,uint param_2)

{
  bool bVar1;
  long lVar2;
  
  lVar2 = FUN_71019d9f00(param_2);
  bVar1 = false;
  if (lVar2 != 0) {
    bVar1 = *(int *)(lVar2 + 0x18) == 4;
  }
  return bVar1;
}



undefined4 FUN_71019d9638(undefined8 param_1,uint param_2)

{
  undefined4 uVar1;
  long lVar2;
  
  lVar2 = FUN_71019d9f00(param_2);
  uVar1 = 0;
  if (lVar2 != 0) {
    uVar1 = *(undefined4 *)(lVar2 + 0x10);
  }
  return uVar1;
}



void FUN_71019d97c8(undefined8 param_1,uint param_2)

{
  long lVar1;
  
  lVar1 = FUN_71019da010(param_2);
  if ((lVar1 != 0) && (*(int *)(lVar1 + 0x18) == 0)) {
    *(undefined4 *)(lVar1 + 0x18) = 1;
    return;
  }
  return;
}



void FUN_71019d97fc(undefined8 param_1,uint param_2)

{
  long lVar1;
  
  lVar1 = FUN_71019da010(param_2);
  if ((lVar1 != 0) && (*(int *)(lVar1 + 0x18) == 1)) {
    *(undefined4 *)(lVar1 + 0x18) = 3;
  }
  return;
}



long FUN_71019d9f00(uint param_1)

{
  uint *puVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  long lVar7;
  long *plVar8;
  
  plVar8 = DAT_7103a59ec8;
  lVar7 = FUN_7100d53f40(*DAT_7103a59ec8);
  puVar1 = (uint *)(*(long *)(lVar7 + 0x88) + (ulong)param_1 * 4);
  if (*(int *)(lVar7 + 0x80) <= (int)param_1 || 0x7fffffff < param_1) {
    puVar1 = DAT_7103a5cdf0;
  }
  uVar2 = *puVar1;
  lVar7 = FUN_7100d53f40(*plVar8);
  if ((uVar2 != 0) && (uVar3 = *(uint *)(lVar7 + 0x2c), uVar3 != 0)) {
    uVar5 = 0;
    if (uVar3 != 0) {
      uVar5 = uVar2 / uVar3;
    }
    uVar5 = uVar2 - uVar5 * uVar3;
    uVar6 = uVar5;
    do {
      uVar4 = *(uint *)(*(long *)(lVar7 + 0x20) +
                       (-(ulong)(uVar6 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar6 << 4));
      if (uVar4 == uVar2) {
        if (*(long *)(*(long *)(lVar7 + 0x20) + (long)(int)uVar6 * 0x10 + 8) == 0) {
          return 0;
        }
        plVar8 = *(long **)(*(long *)(*DAT_7103a5c098 + 0x80) + 0x226288);
        do {
          if (plVar8 == (long *)0x0) {
            return 0;
          }
          if (*(uint *)(plVar8 + 3) <= uVar2) {
            if (uVar2 <= *(uint *)(plVar8 + 3)) {
              return (long)(plVar8 + 4);
            }
            plVar8 = plVar8 + 1;
          }
          plVar8 = (long *)*plVar8;
        } while( true );
      }
      if (uVar4 == 0) {
        return 0;
      }
      uVar4 = 0;
      if ((int)(uVar6 + 1) < (int)uVar3) {
        uVar4 = uVar6 + 1;
      }
      uVar6 = uVar4;
    } while (uVar4 != uVar5);
  }
  return 0;
}



long FUN_71019da010(uint param_1)

{
  uint *puVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  long lVar8;
  long *plVar9;
  
  plVar9 = DAT_7103a59ec8;
  lVar8 = FUN_7100d53f40(*DAT_7103a59ec8);
  puVar1 = (uint *)(*(long *)(lVar8 + 0x88) + (ulong)param_1 * 4);
  if (*(int *)(lVar8 + 0x80) <= (int)param_1 || 0x7fffffff < param_1) {
    puVar1 = DAT_7103a5cdf0;
  }
  uVar2 = *puVar1;
  lVar8 = FUN_7100d53f40(*plVar9);
  if ((uVar2 != 0) && (uVar3 = *(uint *)(lVar8 + 0x2c), uVar3 != 0)) {
    uVar6 = 0;
    if (uVar3 != 0) {
      uVar6 = uVar2 / uVar3;
    }
    uVar6 = uVar2 - uVar6 * uVar3;
    uVar7 = uVar6;
    do {
      uVar5 = *(uint *)(*(long *)(lVar8 + 0x20) +
                       (-(ulong)(uVar7 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar7 << 4));
      if (uVar5 == uVar2) {
        if (*(long *)(*(long *)(lVar8 + 0x20) + (long)(int)uVar7 * 0x10 + 8) == 0) {
          return 0;
        }
        lVar8 = *(long *)(DAT_71040e86a0 + 0x80);
        thunk_EXT_FUN_02e95df0(lVar8 + 0x22a2f0);
        if ((DAT_71040e86a0 != 0) && (*(int *)(DAT_71040e86a0 + 0x944) == 1)) {
          iVar4 = *(int *)(DAT_71040e86a0 + 0x948);
          if (*(int *)(lVar8 + 0x22a2c8) != iVar4) {
            FUN_7101a8d620((ulong *)(lVar8 + 0x2282a8),(ulong *)(lVar8 + 0x226288));
            *(int *)(lVar8 + 0x22a2c8) = iVar4;
          }
        }
        thunk_EXT_FUN_02e95df0(lVar8 + 0x22a2f0);
        plVar9 = *(long **)(lVar8 + 0x226288);
        do {
          if (plVar9 == (long *)0x0) {
            return 0;
          }
          if (*(uint *)(plVar9 + 3) <= uVar2) {
            if (uVar2 <= *(uint *)(plVar9 + 3)) {
              return (long)(plVar9 + 4);
            }
            plVar9 = plVar9 + 1;
          }
          plVar9 = (long *)*plVar9;
        } while( true );
      }
      if (uVar5 == 0) {
        return 0;
      }
      uVar5 = 0;
      if ((int)(uVar7 + 1) < (int)uVar3) {
        uVar5 = uVar7 + 1;
      }
      uVar7 = uVar5;
    } while (uVar5 != uVar6);
  }
  return 0;
}



int FUN_71019da2a0(long *param_1)

{
  int *piVar1;
  int *piVar2;
  long lVar3;
  int iVar4;
  long lVar5;
  
  lVar3 = (**(code **)(*param_1 + 0x260))();
  iVar4 = 0;
  lVar5 = 100;
  do {
    piVar1 = (int *)(lVar3 + 0x16c);
    piVar2 = (int *)(lVar3 + 0x42c);
    lVar3 = lVar3 + 0x580;
    if (*piVar1 != 0) {
      iVar4 = iVar4 + 1;
    }
    if (*piVar2 != 0) {
      iVar4 = iVar4 + 1;
    }
    lVar5 = lVar5 + -2;
  } while (lVar5 != 0);
  return iVar4;
}



ulong FUN_71019da2f0(long *param_1,int param_2)

{
  long lVar1;
  ulong uVar2;
  int iVar3;
  int *piVar4;
  
  lVar1 = (**(code **)(*param_1 + 0x260))();
  uVar2 = 0;
  iVar3 = 0;
  piVar4 = (int *)(lVar1 + 0x16c);
  do {
    if (*piVar4 != 0) {
      if (iVar3 == param_2) {
        return uVar2 & 0xffffffff;
      }
      iVar3 = iVar3 + 1;
    }
    uVar2 = uVar2 + 1;
    piVar4 = piVar4 + 0xb0;
  } while (uVar2 != 100);
  return 0xffffffff;
}



ulong FUN_71019da588(long *param_1,uint *param_2,uint *param_3)

{
  ulong *puVar1;
  ulong *puVar2;
  uint uVar3;
  long lVar4;
  long lVar5;
  ulong uVar6;
  
  uVar3 = *param_2;
  lVar5 = (**(code **)(*param_1 + 0x260))();
  puVar2 = DAT_7103a5d848;
  lVar4 = DAT_7103a59e10;
  lVar5 = lVar5 + (ulong)uVar3 * 0x2c0 + 0x10;
  if (100 < uVar3) {
    lVar5 = DAT_7103a59e10;
  }
  uVar3 = *param_3;
  puVar1 = DAT_7103a5d848;
  if (*(int *)(lVar5 + 0x15c) != 0) {
    puVar1 = (ulong *)(lVar5 + 0x170);
  }
  uVar6 = *puVar1;
  lVar5 = (**(code **)(*param_1 + 0x260))(param_1);
  lVar5 = lVar5 + (ulong)uVar3 * 0x2c0 + 0x10;
  if (100 < uVar3) {
    lVar5 = lVar4;
  }
  if (*(int *)(lVar5 + 0x15c) != 0) {
    puVar2 = (ulong *)(lVar5 + 0x170);
  }
  if (uVar6 <= *puVar2) {
    if (uVar6 < *puVar2) {
      return 1;
    }
    if ((int)*param_2 <= (int)*param_3) {
      return (ulong)((int)*param_2 < (int)*param_3);
    }
  }
  return 0xffffffff;
}



void FUN_71019da690(long *param_1,uint param_2,undefined8 *param_3)

{
  uint uVar1;
  long lVar2;
  ushort *puVar3;
  ulong uVar4;
  ushort *puVar5;
  
  lVar2 = (**(code **)(*param_1 + 0x260))();
  lVar2 = lVar2 + (ulong)param_2 * 0x2c0 + 0x10;
  if (100 < param_2) {
    lVar2 = DAT_7103a59e10;
  }
  *(undefined2 *)(*(long *)(lVar2 + 0x30) + (long)*(int *)(lVar2 + 0x38) * 2 + -2) = 0;
  puVar5 = (ushort *)*param_3;
  puVar3 = *(ushort **)(lVar2 + 0x30);
  if (puVar5 != puVar3) {
    if (puVar3 == (ushort *)0x0) {
LAB_71019da724:
      uVar4 = 0;
    }
    else {
      uVar4 = (ulong)*puVar3;
      if (*puVar3 != 0) {
        uVar4 = 0;
        do {
          if (uVar4 == 0x400000) goto LAB_71019da724;
          if (puVar3[uVar4 + 1] == 0) {
            uVar4 = uVar4 + 1;
            break;
          }
          lVar2 = uVar4 + 2;
          uVar4 = uVar4 + 2;
        } while (puVar3[lVar2] != 0);
      }
    }
    uVar1 = (uint)uVar4;
    if (*(int *)(param_3 + 1) <= (int)(uint)uVar4) {
      uVar1 = *(int *)(param_3 + 1) - 1;
    }
    uVar4 = -(ulong)(uVar1 >> 0x1f) & 0xfffffffe00000000 | (ulong)uVar1 << 1;
    thunk_EXT_FUN_02e95df0(puVar5,puVar3,uVar4);
    *(undefined2 *)((long)puVar5 + uVar4) = 0;
  }
  return;
}



bool FUN_71019da770(long *param_1)

{
  bool bVar1;
  long lVar2;
  
  lVar2 = (**(code **)(*param_1 + 0x270))();
  bVar1 = false;
  if (lVar2 != 0) {
    bVar1 = *(int *)(lVar2 + 0x18) == 1;
  }
  return bVar1;
}



bool FUN_71019da79c(long *param_1)

{
  bool bVar1;
  long lVar2;
  
  lVar2 = (**(code **)(*param_1 + 0x270))();
  bVar1 = false;
  if (lVar2 != 0) {
    bVar1 = *(int *)(lVar2 + 0x18) == 0;
  }
  return bVar1;
}



bool FUN_71019da7c8(long *param_1)

{
  bool bVar1;
  long lVar2;
  
  lVar2 = (**(code **)(*param_1 + 0x270))();
  bVar1 = false;
  if (lVar2 != 0) {
    bVar1 = *(int *)(lVar2 + 0x18) == 4;
  }
  return bVar1;
}



uint FUN_71019da7f4(long *param_1)

{
  long lVar1;
  uint extraout_w8;
  uint uVar2;
  
  lVar1 = (**(code **)(*param_1 + 0x270))();
  uVar2 = extraout_w8;
  if (lVar1 != 0) {
    uVar2 = (uint)(*(int *)(lVar1 + 0x18) == 4 && *(char *)(lVar1 + 0x14) != '\0');
  }
  return lVar1 != 0 & uVar2;
}



void FUN_71019da838(long *param_1)

{
  long lVar1;
  
  lVar1 = (**(code **)(*param_1 + 0x268))();
  if (lVar1 != 0) {
    *(undefined1 *)(lVar1 + 0x14) = 0;
  }
  return;
}



undefined4 FUN_71019da85c(long *param_1)

{
  undefined4 uVar1;
  long lVar2;
  
  lVar2 = (**(code **)(*param_1 + 0x270))();
  uVar1 = 0;
  if (lVar2 != 0) {
    uVar1 = *(undefined4 *)(lVar2 + 0x10);
  }
  return uVar1;
}



int FUN_71019da880(undefined8 param_1,int param_2)

{
  int iVar1;
  int local_14;
  
  if (param_2 < 0) {
    iVar1 = 0;
  }
  else {
    local_14 = param_2;
    iVar1 = FUN_7100eeb9a0(&local_14);
  }
  return iVar1;
}



int FUN_71019da8b8(long *param_1,undefined4 param_2)

{
  int iVar1;
  int iVar2;
  
  iVar1 = (**(code **)(*param_1 + 0x128))();
  iVar2 = (**(code **)(*param_1 + 0x130))(param_1,param_2);
  return 999 - (iVar1 + iVar2);
}



undefined8 FUN_71019da910(long *param_1)

{
  long lVar1;
  undefined8 uVar2;
  
  lVar1 = (**(code **)(*param_1 + 0x270))();
  uVar2 = 0;
  if (lVar1 != 0) {
    uVar2 = *(undefined8 *)(lVar1 + 8);
  }
  return uVar2;
}



void FUN_71019da934(long *param_1)

{
  long lVar1;
  
  lVar1 = (**(code **)(*param_1 + 0x268))();
  if ((lVar1 != 0) && (*(int *)(lVar1 + 0x18) == 0)) {
    *(undefined4 *)(lVar1 + 0x18) = 1;
    return;
  }
  return;
}



void FUN_71019da96c(long *param_1)

{
  long lVar1;
  
  lVar1 = (**(code **)(*param_1 + 0x268))();
  if ((lVar1 != 0) && (*(int *)(lVar1 + 0x18) == 1)) {
    *(undefined4 *)(lVar1 + 0x18) = 3;
  }
  return;
}



bool FUN_71019da9e8(long *param_1,long *param_2,uint param_3,undefined8 param_4,undefined8 param_5,
                   undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  int iVar1;
  long lVar2;
  
  lVar2 = (**(code **)(*param_1 + 0x260))();
  if (param_3 < 0x65) {
    iVar1 = FUN_7101aa70ac((long *)(lVar2 + (ulong)param_3 * 0x2c0 + 0x10),param_2,2,param_4,param_5
                           ,param_6,param_7,param_8);
    *(int *)(param_2 + 10) = iVar1;
    if (iVar1 != 0) {
      return true;
    }
    lVar2 = (**(code **)(*param_1 + 0x260))(param_1);
    iVar1 = FUN_7101aa70ac((long *)(lVar2 + (ulong)param_3 * 0x2c0 + 0x10),param_2,0,param_4,param_5
                           ,param_6,param_7,param_8);
  }
  else {
    *(undefined4 *)(param_2 + 10) = 0;
    (**(code **)(*param_1 + 0x260))(param_1);
    iVar1 = 0;
  }
  *(int *)(param_2 + 10) = iVar1;
  return iVar1 != 0;
}



void FUN_71019dabe0(long *param_1,uint param_2,undefined8 param_3,int param_4)

{
  long *plVar1;
  long *plVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  long lVar7;
  long *plVar8;
  int *piVar9;
  long lVar10;
  long lVar11;
  uint uVar12;
  
  plVar2 = DAT_7103a5c098;
  lVar11 = *(long *)(*DAT_7103a5c098 + 0x80);
  iVar3 = (**(code **)(*param_1 + 0x138))();
  iVar3 = iVar3 * param_4;
  lVar7 = (**(code **)(*param_1 + 0x260))(param_1);
  plVar1 = DAT_7103a59e10;
  plVar8 = (long *)(lVar7 + (ulong)param_2 * 0x2c0 + 0x10);
  if (100 < param_2) {
    plVar8 = DAT_7103a59e10;
  }
  iVar4 = (**(code **)(*plVar8 + 0x20))();
  if (iVar4 - 1U < 7) {
    uVar12 = *(uint *)(&DAT_71032b46d8 + (long)(int)(iVar4 - 1U) * 4);
    FUN_7101a85f40(lVar11,-iVar3);
    thunk_EXT_FUN_02e95df0(lVar11 + 0x242f78);
    lVar7 = *plVar2;
    if ((lVar7 != 0) && (*(int *)(lVar7 + 0x944) == 1)) {
      if (*(int *)(lVar11 + 0x242f50) != *(int *)(lVar7 + 0x948)) {
        *(int *)(lVar11 + 0x242f50) = *(int *)(lVar7 + 0x948);
        *(undefined8 *)(lVar11 + 0x242f38) = *(undefined8 *)(lVar11 + 0x242f20);
        *(undefined8 *)(lVar11 + 0x242f40) = *(undefined8 *)(lVar11 + 0x242f28);
        *(undefined8 *)(lVar11 + 0x242f48) = *(undefined8 *)(lVar11 + 0x242f30);
      }
    }
    lVar7 = lVar11 + (ulong)uVar12 * 4;
    thunk_EXT_FUN_02e95df0(lVar11 + 0x242f78);
    *(int *)(lVar7 + 0x242f20) = *(int *)(lVar7 + 0x242f20) + iVar3;
  }
  else {
    FUN_7101a85f40(lVar11,-iVar3);
    uVar12 = 0xffffffff;
  }
  plVar8 = (long *)(**(code **)(*param_1 + 0x268))(param_1,param_2);
  if (plVar8 != (long *)0x0) {
    iVar4 = (int)plVar8[2] + param_4;
    iVar5 = (**(code **)(*plVar8 + 0x20))();
    iVar6 = iVar4;
    if (iVar5 <= iVar4) {
      iVar6 = iVar5;
    }
    iVar5 = 0;
    if (-1 < iVar4) {
      iVar5 = iVar6;
    }
    iVar6 = (**(code **)(*plVar8 + 0x20))(plVar8);
    iVar4 = iVar5;
    if (iVar6 <= iVar5) {
      iVar4 = iVar6;
    }
    iVar6 = 0;
    if (-1 < iVar5) {
      iVar6 = iVar4;
    }
    *(int *)(plVar8 + 2) = iVar6;
    if ((0 < iVar5) && ((int)plVar8[3] != 4)) {
      *(undefined4 *)(plVar8 + 3) = 4;
      *(undefined1 *)((long)plVar8 + 0x14) = 1;
    }
    if (0 < param_4) {
      (**(code **)(*plVar8 + 0x28))(plVar8);
    }
  }
  lVar11 = (**(code **)(*param_1 + 0x260))(param_1);
  lVar7 = DAT_71040e8780;
  if ((uVar12 == 2) && (DAT_71040e8780 != 0)) {
    piVar9 = (int *)(**(code **)(*(long *)(DAT_71040e8780 + 0xb08) + 0x20))(DAT_71040e8780 + 0xb08);
    iVar4 = *piVar9;
    thunk_EXT_FUN_02e95df0(lVar7 + 0xb40);
    lVar10 = *plVar2;
    if ((lVar10 != 0) &&
       ((*(int *)(lVar10 + 0x944) == 1 && (*(int *)(lVar7 + 0xb18) != *(int *)(lVar10 + 0x948))))) {
      *(int *)(lVar7 + 0xb18) = *(int *)(lVar10 + 0x948);
      *(undefined4 *)(lVar7 + 0xb14) = *(undefined4 *)(lVar7 + 0xb10);
    }
    uVar12 = iVar4 + iVar3;
    if (0x5f5e0fe < (uint)(iVar4 + iVar3)) {
      uVar12 = 99999999;
    }
    thunk_EXT_FUN_02e95df0(lVar7 + 0xb40);
    *(uint *)(lVar7 + 0xb10) = uVar12;
  }
  plVar8 = (long *)(lVar11 + (ulong)param_2 * 0x2c0 + 0x10);
  if (100 < param_2) {
    plVar8 = plVar1;
  }
  FUN_71017ff7a0(plVar8,param_4,iVar3);
  return;
}



void FUN_71019dafd0(long *param_1)

{
  long *plVar1;
  long *plVar2;
  long lVar3;
  long *plVar4;
  long lVar5;
  
  *param_1 = DAT_7103a65b60 + 0x10;
  plVar2 = DAT_7103a65db8;
  if (param_1[0x17] != 0) {
    if (0 < (int)param_1[0x16]) {
      lVar3 = 0;
      plVar1 = (long *)param_1[0x18];
      do {
        plVar4 = *(long **)(param_1[0x17] + lVar3 * 8);
        lVar3 = lVar3 + 1;
        *plVar4 = (long)plVar1;
        param_1[0x18] = (long)plVar4;
        plVar1 = plVar4;
      } while (lVar3 < (int)param_1[0x16]);
    }
    lVar5 = param_1[0x19];
    *(undefined4 *)(param_1 + 0x16) = 0;
    lVar3 = *plVar2;
    if (lVar3 == 0) {
      FUN_71005fbbd0(lVar5);
    }
    else if ((lVar5 != 0) && (plVar1 = FUN_71024ef490(lVar3,lVar5), plVar1 != (long *)0x0)) {
      (**(code **)(*plVar1 + 0x38))(plVar1,lVar5);
    }
    *(undefined4 *)((long)param_1 + 0xcc) = 0;
    *(undefined8 *)((long)param_1 + 0xc4) = 0;
    *(undefined8 *)((long)param_1 + 0xbc) = 0;
    *(undefined8 *)((long)param_1 + 0xb4) = 0;
  }
  if ((char)param_1[0x1b] != '\0') {
    *(undefined1 *)(param_1 + 0x1b) = 0;
  }
  lVar3 = *plVar2;
  if (lVar3 != 0) {
    plVar2 = FUN_71024ef490(lVar3,param_1);
    if (plVar2 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071019db0c8. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*plVar2 + 0x38))(plVar2,param_1);
      return;
    }
    return;
  }
  FUN_71005fbbd0((long)param_1);
  return;
}



int FUN_71019db0f0(long *param_1)

{
  int *piVar1;
  int *piVar2;
  long lVar3;
  int iVar4;
  long lVar5;
  
  lVar3 = (**(code **)(*param_1 + 0x260))();
  iVar4 = 0;
  lVar5 = 100;
  do {
    piVar1 = (int *)(lVar3 + 0x16c);
    piVar2 = (int *)(lVar3 + 0x404);
    lVar3 = lVar3 + 0x530;
    if (*piVar1 != 0) {
      iVar4 = iVar4 + 1;
    }
    if (*piVar2 != 0) {
      iVar4 = iVar4 + 1;
    }
    lVar5 = lVar5 + -2;
  } while (lVar5 != 0);
  return iVar4;
}



ulong FUN_71019db140(long *param_1,int param_2)

{
  long lVar1;
  ulong uVar2;
  int iVar3;
  int *piVar4;
  
  lVar1 = (**(code **)(*param_1 + 0x260))();
  uVar2 = 0;
  iVar3 = 0;
  piVar4 = (int *)(lVar1 + 0x16c);
  do {
    if (*piVar4 != 0) {
      if (iVar3 == param_2) {
        return uVar2 & 0xffffffff;
      }
      iVar3 = iVar3 + 1;
    }
    uVar2 = uVar2 + 1;
    piVar4 = piVar4 + 0xa6;
  } while (uVar2 != 100);
  return 0xffffffff;
}



void FUN_71019db410(long *param_1,uint param_2,undefined8 *param_3)

{
  uint uVar1;
  long lVar2;
  ushort *puVar3;
  ulong uVar4;
  ushort *puVar5;
  
  lVar2 = (**(code **)(*param_1 + 0x260))();
  lVar2 = lVar2 + (ulong)param_2 * 0x298 + 0x10;
  if (100 < param_2) {
    lVar2 = DAT_7103a59e20;
  }
  *(undefined2 *)(*(long *)(lVar2 + 0x30) + (long)*(int *)(lVar2 + 0x38) * 2 + -2) = 0;
  puVar5 = (ushort *)*param_3;
  puVar3 = *(ushort **)(lVar2 + 0x30);
  if (puVar5 != puVar3) {
    if (puVar3 == (ushort *)0x0) {
LAB_71019db4a4:
      uVar4 = 0;
    }
    else {
      uVar4 = (ulong)*puVar3;
      if (*puVar3 != 0) {
        uVar4 = 0;
        do {
          if (uVar4 == 0x400000) goto LAB_71019db4a4;
          if (puVar3[uVar4 + 1] == 0) {
            uVar4 = uVar4 + 1;
            break;
          }
          lVar2 = uVar4 + 2;
          uVar4 = uVar4 + 2;
        } while (puVar3[lVar2] != 0);
      }
    }
    uVar1 = (uint)uVar4;
    if (*(int *)(param_3 + 1) <= (int)(uint)uVar4) {
      uVar1 = *(int *)(param_3 + 1) - 1;
    }
    uVar4 = -(ulong)(uVar1 >> 0x1f) & 0xfffffffe00000000 | (ulong)uVar1 << 1;
    thunk_EXT_FUN_02e95df0(puVar5,puVar3,uVar4);
    *(undefined2 *)((long)puVar5 + uVar4) = 0;
  }
  return;
}



bool FUN_71019db4f0(long *param_1)

{
  bool bVar1;
  long lVar2;
  
  lVar2 = (**(code **)(*param_1 + 0x270))();
  bVar1 = false;
  if (lVar2 != 0) {
    bVar1 = *(int *)(lVar2 + 0x18) == 1;
  }
  return bVar1;
}



bool FUN_71019db51c(long *param_1)

{
  bool bVar1;
  long lVar2;
  
  lVar2 = (**(code **)(*param_1 + 0x270))();
  bVar1 = false;
  if (lVar2 != 0) {
    bVar1 = *(int *)(lVar2 + 0x18) == 0;
  }
  return bVar1;
}



bool FUN_71019db548(long *param_1)

{
  bool bVar1;
  long lVar2;
  
  lVar2 = (**(code **)(*param_1 + 0x270))();
  bVar1 = false;
  if (lVar2 != 0) {
    bVar1 = *(int *)(lVar2 + 0x18) == 4;
  }
  return bVar1;
}



uint FUN_71019db574(long *param_1)

{
  long lVar1;
  uint extraout_w8;
  uint uVar2;
  
  lVar1 = (**(code **)(*param_1 + 0x270))();
  uVar2 = extraout_w8;
  if (lVar1 != 0) {
    uVar2 = (uint)(*(int *)(lVar1 + 0x18) == 4 && *(char *)(lVar1 + 0x14) != '\0');
  }
  return lVar1 != 0 & uVar2;
}



void FUN_71019db5b8(long *param_1)

{
  long lVar1;
  
  lVar1 = (**(code **)(*param_1 + 0x268))();
  if (lVar1 != 0) {
    *(undefined1 *)(lVar1 + 0x14) = 0;
  }
  return;
}



undefined4 FUN_71019db5e4(long *param_1)

{
  undefined4 uVar1;
  long lVar2;
  
  lVar2 = (**(code **)(*param_1 + 0x270))();
  uVar1 = 0;
  if (lVar2 != 0) {
    uVar1 = *(undefined4 *)(lVar2 + 0x10);
  }
  return uVar1;
}



undefined8 FUN_71019db610(long *param_1)

{
  long lVar1;
  undefined8 uVar2;
  
  lVar1 = (**(code **)(*param_1 + 0x270))();
  uVar2 = 0;
  if (lVar1 != 0) {
    uVar2 = *(undefined8 *)(lVar1 + 8);
  }
  return uVar2;
}



void FUN_71019db634(long *param_1)

{
  long lVar1;
  
  lVar1 = (**(code **)(*param_1 + 0x268))();
  if ((lVar1 != 0) && (*(int *)(lVar1 + 0x18) == 0)) {
    *(undefined4 *)(lVar1 + 0x18) = 1;
    return;
  }
  return;
}



void FUN_71019db66c(long *param_1)

{
  long lVar1;
  
  lVar1 = (**(code **)(*param_1 + 0x268))();
  if ((lVar1 != 0) && (*(int *)(lVar1 + 0x18) == 1)) {
    *(undefined4 *)(lVar1 + 0x18) = 3;
  }
  return;
}



bool FUN_71019db6e8(long *param_1,long *param_2,uint param_3,undefined8 param_4,undefined8 param_5,
                   undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  int iVar1;
  long lVar2;
  
  lVar2 = (**(code **)(*param_1 + 0x260))();
  if (param_3 < 0x65) {
    iVar1 = FUN_7101aa70ac((long *)(lVar2 + (ulong)param_3 * 0x298 + 0x10),param_2,2,param_4,param_5
                           ,param_6,param_7,param_8);
    *(int *)(param_2 + 10) = iVar1;
    if (iVar1 != 0) {
      return true;
    }
    lVar2 = (**(code **)(*param_1 + 0x260))(param_1);
    iVar1 = FUN_7101aa70ac((long *)(lVar2 + (ulong)param_3 * 0x298 + 0x10),param_2,0,param_4,param_5
                           ,param_6,param_7,param_8);
  }
  else {
    *(undefined4 *)(param_2 + 10) = 0;
    (**(code **)(*param_1 + 0x260))(param_1);
    iVar1 = 0;
  }
  *(int *)(param_2 + 10) = iVar1;
  return iVar1 != 0;
}



void FUN_71019db8e0(long *param_1,uint param_2,undefined8 param_3,int param_4)

{
  long *plVar1;
  long *plVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  long lVar7;
  long *plVar8;
  int *piVar9;
  long lVar10;
  long lVar11;
  uint uVar12;
  
  plVar2 = DAT_7103a5c098;
  lVar11 = *(long *)(*DAT_7103a5c098 + 0x80);
  iVar3 = (**(code **)(*param_1 + 0x138))();
  iVar3 = iVar3 * param_4;
  lVar7 = (**(code **)(*param_1 + 0x260))(param_1);
  plVar1 = DAT_7103a59e20;
  plVar8 = (long *)(lVar7 + (ulong)param_2 * 0x298 + 0x10);
  if (100 < param_2) {
    plVar8 = DAT_7103a59e20;
  }
  iVar4 = (**(code **)(*plVar8 + 0x20))();
  if (iVar4 - 1U < 7) {
    uVar12 = *(uint *)(&DAT_71032b46d8 + (long)(int)(iVar4 - 1U) * 4);
    FUN_7101a85f40(lVar11,-iVar3);
    thunk_EXT_FUN_02e95df0(lVar11 + 0x242f78);
    lVar7 = *plVar2;
    if ((lVar7 != 0) && (*(int *)(lVar7 + 0x944) == 1)) {
      if (*(int *)(lVar11 + 0x242f50) != *(int *)(lVar7 + 0x948)) {
        *(int *)(lVar11 + 0x242f50) = *(int *)(lVar7 + 0x948);
        *(undefined8 *)(lVar11 + 0x242f38) = *(undefined8 *)(lVar11 + 0x242f20);
        *(undefined8 *)(lVar11 + 0x242f40) = *(undefined8 *)(lVar11 + 0x242f28);
        *(undefined8 *)(lVar11 + 0x242f48) = *(undefined8 *)(lVar11 + 0x242f30);
      }
    }
    lVar7 = lVar11 + (ulong)uVar12 * 4;
    thunk_EXT_FUN_02e95df0(lVar11 + 0x242f78);
    *(int *)(lVar7 + 0x242f20) = *(int *)(lVar7 + 0x242f20) + iVar3;
  }
  else {
    FUN_7101a85f40(lVar11,-iVar3);
    uVar12 = 0xffffffff;
  }
  plVar8 = (long *)(**(code **)(*param_1 + 0x268))(param_1,param_2);
  if (plVar8 != (long *)0x0) {
    iVar4 = (int)plVar8[2] + param_4;
    iVar5 = (**(code **)(*plVar8 + 0x20))();
    iVar6 = iVar4;
    if (iVar5 <= iVar4) {
      iVar6 = iVar5;
    }
    iVar5 = 0;
    if (-1 < iVar4) {
      iVar5 = iVar6;
    }
    iVar6 = (**(code **)(*plVar8 + 0x20))(plVar8);
    iVar4 = iVar5;
    if (iVar6 <= iVar5) {
      iVar4 = iVar6;
    }
    iVar6 = 0;
    if (-1 < iVar5) {
      iVar6 = iVar4;
    }
    *(int *)(plVar8 + 2) = iVar6;
    if ((0 < iVar5) && ((int)plVar8[3] != 4)) {
      *(undefined4 *)(plVar8 + 3) = 4;
      *(undefined1 *)((long)plVar8 + 0x14) = 1;
    }
    if (0 < param_4) {
      (**(code **)(*plVar8 + 0x28))(plVar8);
    }
  }
  lVar11 = (**(code **)(*param_1 + 0x260))(param_1);
  lVar7 = DAT_71040e8780;
  if ((uVar12 == 2) && (DAT_71040e8780 != 0)) {
    piVar9 = (int *)(**(code **)(*(long *)(DAT_71040e8780 + 0xb08) + 0x20))(DAT_71040e8780 + 0xb08);
    iVar4 = *piVar9;
    thunk_EXT_FUN_02e95df0(lVar7 + 0xb40);
    lVar10 = *plVar2;
    if ((lVar10 != 0) &&
       ((*(int *)(lVar10 + 0x944) == 1 && (*(int *)(lVar7 + 0xb18) != *(int *)(lVar10 + 0x948))))) {
      *(int *)(lVar7 + 0xb18) = *(int *)(lVar10 + 0x948);
      *(undefined4 *)(lVar7 + 0xb14) = *(undefined4 *)(lVar7 + 0xb10);
    }
    uVar12 = iVar4 + iVar3;
    if (0x5f5e0fe < (uint)(iVar4 + iVar3)) {
      uVar12 = 99999999;
    }
    thunk_EXT_FUN_02e95df0(lVar7 + 0xb40);
    *(uint *)(lVar7 + 0xb10) = uVar12;
  }
  plVar8 = (long *)(lVar11 + (ulong)param_2 * 0x298 + 0x10);
  if (100 < param_2) {
    plVar8 = plVar1;
  }
  FUN_71017ff7a0(plVar8,param_4,iVar3);
  return;
}



bool FUN_71019dbbf4(long *param_1)

{
  bool bVar1;
  long lVar2;
  
  lVar2 = (**(code **)(*param_1 + 0x270))();
  bVar1 = false;
  if (lVar2 != 0) {
    bVar1 = *(int *)(lVar2 + 0x18) == 4;
  }
  return bVar1;
}



undefined4 FUN_71019dbc20(long *param_1)

{
  undefined4 uVar1;
  long lVar2;
  
  lVar2 = (**(code **)(*param_1 + 0x270))();
  uVar1 = 0;
  if (lVar2 != 0) {
    uVar1 = *(undefined4 *)(lVar2 + 0x10);
  }
  return uVar1;
}



bool FUN_71019dbcdc(long *param_1)

{
  bool bVar1;
  long lVar2;
  
  lVar2 = (**(code **)(*param_1 + 0x270))();
  bVar1 = false;
  if (lVar2 != 0) {
    bVar1 = *(int *)(lVar2 + 0x18) == 4;
  }
  return bVar1;
}



undefined4 FUN_71019dbd08(long *param_1)

{
  undefined4 uVar1;
  long lVar2;
  
  lVar2 = (**(code **)(*param_1 + 0x270))();
  uVar1 = 0;
  if (lVar2 != 0) {
    uVar1 = *(undefined4 *)(lVar2 + 0x10);
  }
  return uVar1;
}



bool FUN_71019dbd74(long *param_1,long *param_2,uint param_3,undefined8 param_4,undefined8 param_5,
                   undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  int iVar1;
  long lVar2;
  
  lVar2 = (**(code **)(*param_1 + 0x260))();
  if (param_3 < 0x65) {
    iVar1 = FUN_7101aa70ac((long *)(lVar2 + (ulong)param_3 * 0x2b8 + 0x10),param_2,2,param_4,param_5
                           ,param_6,param_7,param_8);
    *(int *)(param_2 + 10) = iVar1;
    if (iVar1 != 0) {
      return true;
    }
    lVar2 = (**(code **)(*param_1 + 0x260))(param_1);
    iVar1 = FUN_7101aa70ac((long *)(lVar2 + (ulong)param_3 * 0x2b8 + 0x10),param_2,0,param_4,param_5
                           ,param_6,param_7,param_8);
  }
  else {
    *(undefined4 *)(param_2 + 10) = 0;
    (**(code **)(*param_1 + 0x260))(param_1);
    iVar1 = 0;
  }
  *(int *)(param_2 + 10) = iVar1;
  return iVar1 != 0;
}



void FUN_71019dbfb8(long param_1)

{
  byte *pbVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  byte *pbVar5;
  undefined8 *puVar6;
  
  iVar2 = *(int *)(param_1 + 0x28);
  iVar3 = *(int *)(param_1 + 0x2c);
  if (iVar2 < iVar3) {
    puVar6 = *(undefined8 **)(param_1 + 0x38);
    if (puVar6 != (undefined8 *)0x0) {
      *(undefined8 *)(param_1 + 0x38) = *puVar6;
    }
    *(undefined4 *)puVar6 = 9;
    iVar2 = *(int *)(param_1 + 0x28);
    iVar3 = *(int *)(param_1 + 0x2c);
    if (iVar2 < iVar3) {
      *(undefined8 **)(*(long *)(param_1 + 0x30) + (long)iVar2 * 8) = puVar6;
      iVar3 = *(int *)(param_1 + 0x2c);
      iVar2 = *(int *)(param_1 + 0x28) + 1;
      *(int *)(param_1 + 0x28) = iVar2;
    }
  }
  if (iVar2 < iVar3) {
    puVar6 = *(undefined8 **)(param_1 + 0x38);
    if (puVar6 != (undefined8 *)0x0) {
      *(undefined8 *)(param_1 + 0x38) = *puVar6;
    }
    *(undefined4 *)puVar6 = 4;
    if (*(int *)(param_1 + 0x28) < *(int *)(param_1 + 0x2c)) {
      *(undefined8 **)(*(long *)(param_1 + 0x30) + (long)*(int *)(param_1 + 0x28) * 8) = puVar6;
      *(int *)(param_1 + 0x28) = *(int *)(param_1 + 0x28) + 1;
    }
  }
  if ((DAT_7105a064a0 == (uint *)0x0) || ((char)DAT_7105a064a0[0x10] == '\0')) {
    iVar2 = FUN_71024fcfa0();
    iVar3 = FUN_71024fd1e0();
    uVar4 = (iVar2 - iVar3) + iVar3 * 8;
    pbVar5 = &DAT_71032c57c7;
    pbVar1 = &DAT_71032c57c7 + uVar4;
    if (0x5a < uVar4) {
      pbVar1 = pbVar5;
    }
    if ((char)*pbVar1 < '\0') {
      if (iVar2 - 1U < 6) {
        iVar3 = *(int *)(&DAT_71032b46f4 + (long)(int)(iVar2 - 1U) * 4);
      }
      else {
        iVar3 = 0;
      }
      if ((uint)(iVar3 + iVar2) < 0x5b) {
        pbVar5 = &DAT_71032c57c7 + (uint)(iVar3 + iVar2);
      }
      uVar4 = (int)(char)*pbVar5 & ((int)(char)*pbVar5 >> 0x1f ^ 0xffffffffU);
    }
    else {
      uVar4 = (uint)*pbVar1;
    }
  }
  else {
    uVar4 = *DAT_7105a064a0;
  }
  if (((uVar4 & 0xfffffffe) != 0xe) && (*(int *)(param_1 + 0x28) < *(int *)(param_1 + 0x2c))) {
    puVar6 = *(undefined8 **)(param_1 + 0x38);
    if (puVar6 != (undefined8 *)0x0) {
      *(undefined8 *)(param_1 + 0x38) = *puVar6;
    }
    *(undefined4 *)puVar6 = 3;
    if (*(int *)(param_1 + 0x28) < *(int *)(param_1 + 0x2c)) {
      *(undefined8 **)(*(long *)(param_1 + 0x30) + (long)*(int *)(param_1 + 0x28) * 8) = puVar6;
      *(int *)(param_1 + 0x28) = *(int *)(param_1 + 0x28) + 1;
    }
  }
  return;
}



void FUN_71019dc278(long param_1)

{
  byte *pbVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  byte *pbVar5;
  undefined8 *puVar6;
  
  iVar2 = *(int *)(param_1 + 0x28);
  iVar3 = *(int *)(param_1 + 0x2c);
  if (iVar2 < iVar3) {
    puVar6 = *(undefined8 **)(param_1 + 0x38);
    if (puVar6 != (undefined8 *)0x0) {
      *(undefined8 *)(param_1 + 0x38) = *puVar6;
    }
    *(undefined4 *)puVar6 = 9;
    iVar2 = *(int *)(param_1 + 0x28);
    iVar3 = *(int *)(param_1 + 0x2c);
    if (iVar2 < iVar3) {
      *(undefined8 **)(*(long *)(param_1 + 0x30) + (long)iVar2 * 8) = puVar6;
      iVar3 = *(int *)(param_1 + 0x2c);
      iVar2 = *(int *)(param_1 + 0x28) + 1;
      *(int *)(param_1 + 0x28) = iVar2;
    }
  }
  if (iVar2 < iVar3) {
    puVar6 = *(undefined8 **)(param_1 + 0x38);
    if (puVar6 != (undefined8 *)0x0) {
      *(undefined8 *)(param_1 + 0x38) = *puVar6;
    }
    *(undefined4 *)puVar6 = 4;
    if (*(int *)(param_1 + 0x28) < *(int *)(param_1 + 0x2c)) {
      *(undefined8 **)(*(long *)(param_1 + 0x30) + (long)*(int *)(param_1 + 0x28) * 8) = puVar6;
      *(int *)(param_1 + 0x28) = *(int *)(param_1 + 0x28) + 1;
    }
  }
  if ((DAT_7105a064a0 == (uint *)0x0) || ((char)DAT_7105a064a0[0x10] == '\0')) {
    iVar2 = FUN_71024fcfa0();
    iVar3 = FUN_71024fd1e0();
    uVar4 = (iVar2 - iVar3) + iVar3 * 8;
    pbVar5 = &DAT_71032c57c7;
    pbVar1 = &DAT_71032c57c7 + uVar4;
    if (0x5a < uVar4) {
      pbVar1 = pbVar5;
    }
    if ((char)*pbVar1 < '\0') {
      if (iVar2 - 1U < 6) {
        iVar3 = *(int *)(&DAT_71032b46f4 + (long)(int)(iVar2 - 1U) * 4);
      }
      else {
        iVar3 = 0;
      }
      if ((uint)(iVar3 + iVar2) < 0x5b) {
        pbVar5 = &DAT_71032c57c7 + (uint)(iVar3 + iVar2);
      }
      uVar4 = (int)(char)*pbVar5 & ((int)(char)*pbVar5 >> 0x1f ^ 0xffffffffU);
    }
    else {
      uVar4 = (uint)*pbVar1;
    }
  }
  else {
    uVar4 = *DAT_7105a064a0;
  }
  if (((uVar4 & 0xfffffffe) != 0xe) && (*(int *)(param_1 + 0x28) < *(int *)(param_1 + 0x2c))) {
    puVar6 = *(undefined8 **)(param_1 + 0x38);
    if (puVar6 != (undefined8 *)0x0) {
      *(undefined8 *)(param_1 + 0x38) = *puVar6;
    }
    *(undefined4 *)puVar6 = 3;
    if (*(int *)(param_1 + 0x28) < *(int *)(param_1 + 0x2c)) {
      *(undefined8 **)(*(long *)(param_1 + 0x30) + (long)*(int *)(param_1 + 0x28) * 8) = puVar6;
      *(int *)(param_1 + 0x28) = *(int *)(param_1 + 0x28) + 1;
    }
  }
  return;
}



void FUN_71019dc408(long *param_1,undefined4 param_2)

{
  long *plVar1;
  
  *(undefined2 *)(param_1 + 1) = 0;
  *(undefined8 *)((long)param_1 + 0xc) = 0xffffffffffffffff;
  *(undefined1 *)((long)param_1 + 10) = 0;
  param_1[0xe] = 0;
  param_1[0xd] = (long)(param_1 + 0xe);
  *(undefined2 *)((long)param_1 + 0x14) = 0;
  param_1[5] = 0;
  param_1[6] = 0;
  *param_1 = (long)&DAT_7103987b08;
  param_1[0xc] = (long)(param_1 + 0xd);
  param_1[3] = -0xc0800000;
  param_1[0xb] = (long)(param_1 + 0xc);
  *(undefined4 *)(param_1 + 4) = 0xffffffff;
  param_1[10] = (long)(param_1 + 0xb);
  plVar1 = param_1 + 9;
  *plVar1 = (long)(param_1 + 10);
  param_1[7] = (long)plVar1;
  param_1[8] = (long)plVar1;
  if (param_1 + 0xf != (long *)0x0) {
    param_1[6] = (long)(param_1 + 0xf);
    *(undefined4 *)((long)param_1 + 0x2c) = 6;
  }
  *(undefined4 *)(param_1 + 0x15) = 0;
  param_1[0x16] = 0;
  param_1[0x17] = 0;
  *(undefined1 *)(param_1 + 0x1a) = 1;
  *(undefined4 *)((long)param_1 + 0xd4) = 0;
  *(undefined1 *)(param_1 + 0x1b) = 0;
  *(undefined4 *)(param_1 + 0x1e) = param_2;
  param_1[0x18] = 0;
  param_1[0x19] = 0;
  param_1[0x1c] = 0;
  param_1[0x1d] = 0;
  param_1[0x1f] = 0;
  param_1[0x20] = 0;
  param_1[0x21] = 0;
  param_1[0x22] = 0;
  param_1[0x23] = 0;
  param_1[0x24] = 0;
  param_1[0x25] = 0;
  param_1[0x26] = 0;
  *param_1 = DAT_7103a65bb8 + 0x10;
  *(undefined1 *)(param_1 + 0x27) = 0;
  param_1[0x4b] = 0;
  param_1[0x2c] = (long)(param_1 + 0x2d);
  param_1[0x2d] = (long)(param_1 + 0x2e);
  param_1[0x2e] = (long)(param_1 + 0x2f);
  param_1[0x2f] = (long)(param_1 + 0x30);
  param_1[0x30] = (long)(param_1 + 0x31);
  param_1[0x31] = (long)(param_1 + 0x32);
  param_1[0x32] = (long)(param_1 + 0x33);
  param_1[0x33] = (long)(param_1 + 0x34);
  param_1[0x34] = (long)(param_1 + 0x35);
  param_1[0x35] = (long)(param_1 + 0x36);
  param_1[0x36] = (long)(param_1 + 0x37);
  param_1[0x37] = (long)(param_1 + 0x38);
  param_1[0x38] = (long)(param_1 + 0x39);
  param_1[0x39] = (long)(param_1 + 0x3a);
  param_1[0x3a] = (long)(param_1 + 0x3b);
  param_1[0x3b] = (long)(param_1 + 0x3c);
  param_1[0x3c] = (long)(param_1 + 0x3d);
  param_1[0x3d] = (long)(param_1 + 0x3e);
  param_1[0x3e] = (long)(param_1 + 0x3f);
  param_1[0x3f] = (long)(param_1 + 0x40);
  param_1[0x40] = (long)(param_1 + 0x41);
  param_1[0x41] = (long)(param_1 + 0x42);
  param_1[0x42] = (long)(param_1 + 0x43);
  param_1[0x43] = (long)(param_1 + 0x44);
  param_1[0x44] = (long)(param_1 + 0x45);
  param_1[0x45] = (long)(param_1 + 0x46);
  param_1[0x46] = (long)(param_1 + 0x47);
  param_1[0x47] = (long)(param_1 + 0x48);
  param_1[0x48] = (long)(param_1 + 0x49);
  param_1[0x49] = (long)(param_1 + 0x4a);
  param_1[0x4a] = (long)(param_1 + 0x4b);
  param_1[0x28] = 0;
  param_1[0x29] = 0;
  param_1[0x2a] = (long)(param_1 + 0x2c);
  param_1[0x2b] = (long)(param_1 + 0x2c);
  if (param_1 + 0x4c != (long *)0x0) {
    param_1[0x28] = 0x2000000000;
    param_1[0x29] = (long)(param_1 + 0x4c);
  }
  return;
}



undefined8 FUN_71019dc5c8(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if (((DAT_71040e3e88 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_71040e3e88), iVar1 != 0))
  {
    DAT_71040e3e80 = &DAT_710398db48;
    thunk_EXT_FUN_02e95df0(&DAT_71040e3e88);
  }
  if ((undefined **)param_2 != &DAT_71040e3e80) {
    if (((*DAT_7103a65b70 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a65b70), iVar1 != 0)
       ) {
      *DAT_7103a65b68 = DAT_7103a65b78 + 0x10;
      thunk_EXT_FUN_02e95df0(DAT_7103a65b70);
    }
    if (param_2 != DAT_7103a65b68) {
      if (((*DAT_7103a65b50 & 1) == 0) &&
         (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a65b50), iVar1 != 0)) {
        *DAT_7103a65b48 = DAT_7103a59af0 + 0x10;
        thunk_EXT_FUN_02e95df0(DAT_7103a65b50);
      }
      if (param_2 != DAT_7103a65b48) {
        param_1 = 0;
      }
    }
  }
  return param_1;
}



undefined8 * FUN_71019dc72c(void)

{
  int iVar1;
  
  if (((DAT_71040e3e88 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_71040e3e88), iVar1 != 0))
  {
    DAT_71040e3e80 = &DAT_710398db48;
    thunk_EXT_FUN_02e95df0(&DAT_71040e3e88);
  }
  return &DAT_71040e3e80;
}



void FUN_71019dc784(undefined8 *param_1)

{
  long *plVar1;
  
  FUN_710196e710(param_1);
  if (DAT_7105a06420 == 0) {
    FUN_71005fbbd0((long)param_1);
    return;
  }
  plVar1 = FUN_71024ef490(DAT_7105a06420,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071019dc7c8. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



void FUN_71019dc9b8(long param_1)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  char *pcVar4;
  uint uVar5;
  undefined8 *puVar6;
  
  iVar2 = *(int *)(param_1 + 0x28);
  iVar3 = *(int *)(param_1 + 0x2c);
  if (iVar2 < iVar3) {
    puVar6 = *(undefined8 **)(param_1 + 0x38);
    if (puVar6 != (undefined8 *)0x0) {
      *(undefined8 *)(param_1 + 0x38) = *puVar6;
    }
    *(undefined4 *)puVar6 = 9;
    iVar2 = *(int *)(param_1 + 0x28);
    iVar3 = *(int *)(param_1 + 0x2c);
    if (iVar2 < iVar3) {
      *(undefined8 **)(*(long *)(param_1 + 0x30) + (long)iVar2 * 8) = puVar6;
      iVar3 = *(int *)(param_1 + 0x2c);
      iVar2 = *(int *)(param_1 + 0x28) + 1;
      *(int *)(param_1 + 0x28) = iVar2;
    }
  }
  if (iVar2 < iVar3) {
    puVar6 = *(undefined8 **)(param_1 + 0x38);
    if (puVar6 != (undefined8 *)0x0) {
      *(undefined8 *)(param_1 + 0x38) = *puVar6;
    }
    *(undefined4 *)puVar6 = 4;
    if (*(int *)(param_1 + 0x28) < *(int *)(param_1 + 0x2c)) {
      *(undefined8 **)(*(long *)(param_1 + 0x30) + (long)*(int *)(param_1 + 0x28) * 8) = puVar6;
      *(int *)(param_1 + 0x28) = *(int *)(param_1 + 0x28) + 1;
    }
  }
  if ((DAT_7105a064a0 == (uint *)0x0) || ((char)DAT_7105a064a0[0x10] == '\0')) {
    iVar2 = FUN_71024fcfa0();
    iVar3 = FUN_71024fd1e0();
    uVar1 = (iVar2 - iVar3) + iVar3 * 8;
    pcVar4 = "";
    if (uVar1 < 0x5b) {
      uVar5 = (uint)(char)(&DAT_71032c57c7)[uVar1];
      if ((char)(&DAT_71032c57c7)[uVar1] < '\0') {
        if (iVar2 - 1U < 6) {
          iVar3 = *(int *)(&DAT_71032b46f4 + (long)(int)(iVar2 - 1U) * 4);
        }
        else {
          iVar3 = 0;
        }
        if ((uint)(iVar3 + iVar2) < 0x5b) {
          pcVar4 = &DAT_71032c57c7 + (uint)(iVar3 + iVar2);
        }
        uVar5 = (int)*pcVar4 & ((int)*pcVar4 >> 0x1f ^ 0xffffffffU);
        goto LAB_71019dcaf4;
      }
    }
    else {
      uVar5 = 0;
    }
    uVar5 = uVar5 & 0xff;
  }
  else {
    uVar5 = *DAT_7105a064a0;
  }
LAB_71019dcaf4:
  iVar2 = *(int *)(param_1 + 0x28);
  iVar3 = *(int *)(param_1 + 0x2c);
  if ((uVar5 & 0xfffffffe) != 0xe && iVar2 < iVar3) {
    puVar6 = *(undefined8 **)(param_1 + 0x38);
    if (puVar6 != (undefined8 *)0x0) {
      *(undefined8 *)(param_1 + 0x38) = *puVar6;
    }
    *(undefined4 *)puVar6 = 3;
    iVar2 = *(int *)(param_1 + 0x28);
    iVar3 = *(int *)(param_1 + 0x2c);
    if (iVar2 < iVar3) {
      *(undefined8 **)(*(long *)(param_1 + 0x30) + (long)iVar2 * 8) = puVar6;
      iVar3 = *(int *)(param_1 + 0x2c);
      iVar2 = *(int *)(param_1 + 0x28) + 1;
      *(int *)(param_1 + 0x28) = iVar2;
    }
  }
  if (iVar2 < iVar3) {
    puVar6 = *(undefined8 **)(param_1 + 0x38);
    if (puVar6 != (undefined8 *)0x0) {
      *(undefined8 *)(param_1 + 0x38) = *puVar6;
    }
    *(undefined4 *)puVar6 = 5;
    iVar2 = *(int *)(param_1 + 0x28);
    if (*(int *)(param_1 + 0x2c) <= iVar2) {
      if (*(int *)(param_1 + 0x2c) <= iVar2) {
        return;
      }
      goto LAB_71019dcb90;
    }
    *(undefined8 **)(*(long *)(param_1 + 0x30) + (long)iVar2 * 8) = puVar6;
    iVar3 = *(int *)(param_1 + 0x2c);
    iVar2 = *(int *)(param_1 + 0x28) + 1;
    *(int *)(param_1 + 0x28) = iVar2;
  }
  if (iVar3 <= iVar2) {
    return;
  }
LAB_71019dcb90:
  puVar6 = *(undefined8 **)(param_1 + 0x38);
  if (puVar6 != (undefined8 *)0x0) {
    *(undefined8 *)(param_1 + 0x38) = *puVar6;
  }
  *(undefined4 *)puVar6 = 6;
  if (*(int *)(param_1 + 0x28) < *(int *)(param_1 + 0x2c)) {
    *(undefined8 **)(*(long *)(param_1 + 0x30) + (long)*(int *)(param_1 + 0x28) * 8) = puVar6;
    *(int *)(param_1 + 0x28) = *(int *)(param_1 + 0x28) + 1;
  }
  return;
}



bool FUN_71019dcdc0(long *param_1,uint param_2)

{
  uint *puVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  long *plVar7;
  bool bVar8;
  int iVar9;
  long lVar10;
  
  plVar7 = DAT_7103a59ec8;
  lVar10 = FUN_7100d21570(*DAT_7103a59ec8);
  puVar1 = (uint *)(*(long *)(lVar10 + 0x88) + (ulong)param_2 * 4);
  if (*(int *)(lVar10 + 0x80) <= (int)param_2 || 0x7fffffff < param_2) {
    puVar1 = DAT_7103a5d090;
  }
  uVar2 = *puVar1;
  lVar10 = FUN_7100d21570(*plVar7);
  if ((uVar2 != 0) && (uVar3 = *(uint *)(lVar10 + 0x2c), uVar3 != 0)) {
    uVar5 = 0;
    if (uVar3 != 0) {
      uVar5 = uVar2 / uVar3;
    }
    uVar5 = uVar2 - uVar5 * uVar3;
    uVar6 = uVar5;
    do {
      uVar4 = *(uint *)(*(long *)(lVar10 + 0x20) +
                       (-(ulong)(uVar6 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar6 << 4));
      if (uVar4 == uVar2) {
        lVar10 = *(long *)(*(long *)(lVar10 + 0x20) + (long)(int)uVar6 * 0x10 + 8);
        if ((lVar10 != 0) && (iVar9 = *(int *)(lVar10 + 0xa0), iVar9 == 2 || iVar9 == 4)) {
          return false;
        }
        break;
      }
      if (uVar4 == 0) break;
      uVar4 = 0;
      if ((int)(uVar6 + 1) < (int)uVar3) {
        uVar4 = uVar6 + 1;
      }
      uVar6 = uVar4;
    } while (uVar4 != uVar5);
  }
  iVar9 = (**(code **)(*param_1 + 0x128))(param_1,param_2,0xffffffff);
  if (iVar9 < 1) {
    return false;
  }
  bVar8 = FUN_710197c180((long)param_1,param_2);
  return bVar8;
}



bool FUN_71019dd3fc(long *param_1,uint param_2)

{
  long lVar1;
  long lVar2;
  bool bVar3;
  ulong uVar4;
  long *plVar5;
  long local_50;
  long local_48;
  long local_40;
  long local_38;
  
  lVar1 = DAT_7103a62f28;
  local_48 = 0;
  local_50 = DAT_7103a62f28 + 0x10;
  FUN_7101572590((long)&local_50,param_2);
  lVar2 = local_48;
  if ((local_48 != 0) &&
     (uVar4 = (**(code **)(*param_1 + 0x260))(param_1,param_2), (uVar4 & 1) != 0)) {
    if ((DAT_71040e2530 != 0) && (bVar3 = FUN_710193a3f0(DAT_71040e2530,0x9a41ac3), !bVar3)) {
      return *(int *)(lVar2 + 4) == 0x3a379430;
    }
    uVar4 = (**(code **)(*param_1 + 0x100))(param_1,param_2);
    if (((uVar4 & 1) == 0) &&
       ((*(long *)(lVar2 + 0x60) == 0 || (*(int *)(*(long *)(lVar2 + 0x60) + 0x28) != 2)))) {
      local_40 = lVar1 + 0x10;
      local_38 = 0;
      FUN_7101572590((long)&local_40,param_2);
      if ((local_38 != 0) &&
         ((*(long *)(local_38 + 0x40) != 0 && (*(char *)(*(long *)(local_38 + 0x40) + 0xc) != '\0'))
         )) {
        local_40 = lVar1 + 0x10;
        local_38 = 0;
        FUN_7101572590((long)&local_40,param_2);
        if ((local_38 != 0) &&
           (plVar5 = *(long **)(*(long *)(*DAT_7103a5c098 + 0x80) + 0x12e18), plVar5 != (long *)0x0)
           ) {
          do {
            if (*(uint *)(plVar5 + 3) <= *(uint *)(local_38 + 4)) {
              if (*(uint *)(local_38 + 4) <= *(uint *)(plVar5 + 3)) {
                plVar5 = plVar5 + 4;
                goto LAB_71019dd550;
              }
              plVar5 = plVar5 + 1;
            }
            plVar5 = (long *)*plVar5;
          } while (plVar5 != (long *)0x0);
        }
        plVar5 = param_1 + 0x1f;
LAB_71019dd550:
        if ((int)plVar5[3] == 4) {
          return false;
        }
      }
      if (((*(long *)(lVar2 + 0x18) == 0) || (*(char *)(*(long *)(lVar2 + 0x18) + 0xc) == '\0')) &&
         (*(long *)(lVar2 + 0x40) != 0)) {
        return 0 < *(int *)(*(long *)(lVar2 + 0x40) + 8);
      }
    }
  }
  return false;
}



void FUN_71019dd6b0(undefined8 param_1,uint param_2)

{
  uint uVar1;
  long *plVar2;
  long local_30;
  long local_28;
  
  local_30 = DAT_7103a62f28 + 0x10;
  local_28 = 0;
  FUN_7101572590((long)&local_30,param_2);
  if ((local_28 != 0) && (*(long *)(DAT_71040e86a0 + 0x80) != 0)) {
    uVar1 = *(uint *)(local_28 + 4);
    plVar2 = (long *)FUN_7101a72200(*(long *)(DAT_71040e86a0 + 0x80) + 0x12e10);
    for (plVar2 = (long *)*plVar2; plVar2 != (long *)0x0; plVar2 = (long *)*plVar2) {
      if (*(uint *)(plVar2 + 3) <= uVar1) {
        if (uVar1 <= *(uint *)(plVar2 + 3)) {
          if (*(int *)(plVar2 + 7) == 1) {
            *(undefined4 *)(plVar2 + 7) = 3;
          }
          if (*(char *)((long)plVar2 + 0x4c) != '\0') {
            return;
          }
          *(undefined1 *)((long)plVar2 + 0x4c) = 1;
          return;
        }
        plVar2 = plVar2 + 1;
      }
    }
  }
  return;
}



void FUN_71019dd764(undefined1 param_1 [16],float param_2,undefined8 param_3,long param_4,
                   uint param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                   undefined8 param_9,undefined8 param_10)

{
  byte bVar1;
  int iVar2;
  long lVar3;
  undefined1 extraout_q0 [16];
  undefined1 auVar4 [16];
  undefined1 extraout_q0_00 [16];
  undefined1 *local_210;
  undefined4 local_208;
  undefined8 local_200;
  undefined1 auStack_1f8 [8];
  long local_1f0;
  undefined1 *local_1e8;
  undefined4 local_1e0;
  undefined1 local_1dc [127];
  undefined1 local_15d;
  undefined1 *local_158;
  undefined4 local_150;
  undefined8 local_148;
  undefined2 *local_140;
  int local_138;
  undefined1 local_134 [4];
  undefined8 local_130;
  undefined1 local_35;
  
  local_1f0 = 0;
  FUN_7101572590((long)auStack_1f8,param_5);
  if (local_1f0 != 0) {
    lVar3 = *(long *)(local_1f0 + 0x48);
    local_210 = (undefined1 *)0x0;
    local_208 = 0;
    local_200 = 0xffffffffffffffff;
    if (lVar3 != 0) {
      local_15d = 0;
      local_1e8 = local_1dc;
      local_1dc[0] = 0;
      local_1e0 = 0x80;
      if (*(char *)(lVar3 + 0x14) == '\0') {
        if (*(uint *)(lVar3 + 0x10) < 0x14) {
          local_158 = *(undefined1 **)(&DAT_710395ec10 + (ulong)*(uint *)(lVar3 + 0x10) * 8);
        }
        else {
          local_158 = &DAT_71030e70e0;
        }
        local_140 = (undefined2 *)local_134;
        local_138 = 0x100;
        local_35 = 0;
        local_134[0] = 0;
        FUN_7100bbdd20((long *)&local_140,0x71030cc5e0,(long *)&local_158,param_6,param_7,param_8,
                       param_9,param_10);
        *(undefined1 *)((long)local_140 + (long)local_138 + -1) = 0;
        FUN_7101d9eb80((long *)&local_158,&local_140,(undefined8 *)(lVar3 + 8));
        local_210 = local_158;
        local_208 = local_150;
        local_200 = local_148;
      }
      else {
        local_208 = 0;
        local_210 = (undefined1 *)0x0;
        local_200 = 0xffffffffffffffff;
      }
    }
    local_140 = (undefined2 *)((ulong)local_140 & 0xffffffffffffff00);
    iVar2 = FUN_710292ebe0(param_4,*(long **)(param_4 + 0x18),(long *)"T_TextLeft_00",&local_210,0,
                           -1,(undefined1 *)&local_140,0);
    if ((iVar2 != 0) && ((char)local_140 != '\0')) {
      bVar1 = *(byte *)(param_4 + 0x90);
      auVar4 = extraout_q0;
      if ((bVar1 & 1) != 0) {
        auVar4 = FUN_7102932010(extraout_q0,param_2,param_4,*(long **)(param_4 + 0x18));
        bVar1 = *(byte *)(param_4 + 0x90);
      }
      if (((bVar1 >> 2 & 1) != 0) && (lVar3 = *(long *)(param_4 + 0x88), lVar3 != 0)) {
        FUN_7102932010(auVar4,param_2,lVar3,*(long **)(lVar3 + 0x18));
      }
    }
    local_140 = &DAT_71032ab102;
    local_138 = 0;
    local_130 = 0xffffffffffffffff;
    local_1e8 = (undefined1 *)((ulong)local_1e8 & 0xffffffffffffff00);
    iVar2 = FUN_710292ebe0(param_4,*(long **)(param_4 + 0x18),(long *)"T_Text_00",&local_140,0,-1,
                           (undefined1 *)&local_1e8,0);
    if ((iVar2 != 0) && ((char)local_1e8 != '\0')) {
      bVar1 = *(byte *)(param_4 + 0x90);
      auVar4 = extraout_q0_00;
      if ((bVar1 & 1) != 0) {
        auVar4 = FUN_7102932010(extraout_q0_00,param_2,param_4,*(long **)(param_4 + 0x18));
        bVar1 = *(byte *)(param_4 + 0x90);
      }
      if (((bVar1 >> 2 & 1) != 0) && (lVar3 = *(long *)(param_4 + 0x88), lVar3 != 0)) {
        FUN_7102932010(auVar4,param_2,lVar3,*(long **)(lVar3 + 0x18));
      }
    }
  }
  return;
}



void FUN_71019dd970(undefined8 *param_1,undefined4 param_2)

{
  long *plVar1;
  undefined8 *puVar2;
  long lVar3;
  
  param_1[0xe] = 0;
  param_1[0xd] = param_1 + 0xe;
  param_1[0xc] = param_1 + 0xd;
  *(undefined2 *)(param_1 + 1) = 0;
  *(undefined1 *)((long)param_1 + 10) = 0;
  *(undefined2 *)((long)param_1 + 0x14) = 0;
  param_1[5] = 0;
  param_1[6] = 0;
  *param_1 = &DAT_7103987b08;
  param_1[0xb] = param_1 + 0xc;
  *(undefined8 *)((long)param_1 + 0xc) = 0xffffffffffffffff;
  param_1[10] = param_1 + 0xb;
  param_1[3] = 0xffffffff3f800000;
  *(undefined4 *)(param_1 + 4) = 0xffffffff;
  puVar2 = param_1 + 9;
  *puVar2 = param_1 + 10;
  param_1[7] = puVar2;
  param_1[8] = puVar2;
  if (param_1 + 0xf != (undefined8 *)0x0) {
    param_1[6] = param_1 + 0xf;
    *(undefined4 *)((long)param_1 + 0x2c) = 6;
  }
  *(undefined4 *)(param_1 + 0x15) = 0;
  *(undefined1 *)(param_1 + 0x1a) = 1;
  lVar3 = 0x17e;
  param_1[0x16] = 0;
  param_1[0x17] = 0;
  *(undefined4 *)((long)param_1 + 0xd4) = 0;
  *(undefined1 *)(param_1 + 0x1b) = 0;
  *(undefined4 *)(param_1 + 0x1e) = 2;
  *(undefined4 *)(param_1 + 0x21) = 0;
  *(undefined1 *)((long)param_1 + 0x10c) = 0;
  *(undefined4 *)(param_1 + 0x22) = 0;
  param_1[0x23] = 0;
  *(undefined4 *)(param_1 + 0x24) = 0;
  *(undefined1 *)((long)param_1 + 0x124) = 0;
  param_1[0x18] = 0;
  param_1[0x19] = 0;
  param_1[0x1c] = 0;
  param_1[0x1d] = 0;
  param_1[0x1f] = DAT_7103a65e88 + 0x10;
  param_1[0x20] = 0;
  param_1[0x27] = 0;
  param_1[0x28] = 0;
  *(undefined4 *)((long)param_1 + 0x144) = 0x180;
  param_1[0x25] = 0;
  param_1[0x26] = param_1 + 0x29;
  param_1[0x29] = param_1 + 0x41;
  plVar1 = param_1 + 0x41;
  do {
    lVar3 = lVar3 + -2;
    *plVar1 = (long)(plVar1 + 0x18);
    plVar1[0x18] = (long)(plVar1 + 0x30);
    plVar1 = plVar1 + 0x30;
  } while (lVar3 != 0);
  param_1[0x2411] = 0;
  param_1[0x27] = param_1 + 0x29;
  *param_1 = &DAT_710398e2d0;
  *(undefined4 *)(param_1 + 0x2429) = param_2;
  return;
}



void FUN_71019dde30(long *param_1)

{
  long *plVar1;
  long *plVar2;
  long lVar3;
  long *plVar4;
  long lVar5;
  
  *param_1 = DAT_7103a65b60 + 0x10;
  plVar2 = DAT_7103a65db8;
  if (param_1[0x17] != 0) {
    if (0 < (int)param_1[0x16]) {
      lVar3 = 0;
      plVar1 = (long *)param_1[0x18];
      do {
        plVar4 = *(long **)(param_1[0x17] + lVar3 * 8);
        lVar3 = lVar3 + 1;
        *plVar4 = (long)plVar1;
        param_1[0x18] = (long)plVar4;
        plVar1 = plVar4;
      } while (lVar3 < (int)param_1[0x16]);
    }
    lVar5 = param_1[0x19];
    *(undefined4 *)(param_1 + 0x16) = 0;
    lVar3 = *plVar2;
    if (lVar3 == 0) {
      FUN_71005fbbd0(lVar5);
    }
    else if ((lVar5 != 0) && (plVar1 = FUN_71024ef490(lVar3,lVar5), plVar1 != (long *)0x0)) {
      (**(code **)(*plVar1 + 0x38))(plVar1,lVar5);
    }
    *(undefined4 *)((long)param_1 + 0xcc) = 0;
    *(undefined8 *)((long)param_1 + 0xc4) = 0;
    *(undefined8 *)((long)param_1 + 0xbc) = 0;
    *(undefined8 *)((long)param_1 + 0xb4) = 0;
  }
  if ((char)param_1[0x1b] != '\0') {
    *(undefined1 *)(param_1 + 0x1b) = 0;
  }
  lVar3 = *plVar2;
  if (lVar3 != 0) {
    plVar2 = FUN_71024ef490(lVar3,param_1);
    if (plVar2 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071019ddf28. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*plVar2 + 0x38))(plVar2,param_1);
      return;
    }
    return;
  }
  FUN_71005fbbd0((long)param_1);
  return;
}



void FUN_71019ddf58(long param_1)

{
  byte *pbVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  byte *pbVar5;
  undefined8 *puVar6;
  
  iVar2 = *(int *)(param_1 + 0x28);
  iVar3 = *(int *)(param_1 + 0x2c);
  if (iVar2 < iVar3) {
    puVar6 = *(undefined8 **)(param_1 + 0x38);
    if (puVar6 != (undefined8 *)0x0) {
      *(undefined8 *)(param_1 + 0x38) = *puVar6;
    }
    *(undefined4 *)puVar6 = 9;
    iVar2 = *(int *)(param_1 + 0x28);
    iVar3 = *(int *)(param_1 + 0x2c);
    if (iVar2 < iVar3) {
      *(undefined8 **)(*(long *)(param_1 + 0x30) + (long)iVar2 * 8) = puVar6;
      iVar3 = *(int *)(param_1 + 0x2c);
      iVar2 = *(int *)(param_1 + 0x28) + 1;
      *(int *)(param_1 + 0x28) = iVar2;
    }
  }
  if (iVar2 < iVar3) {
    puVar6 = *(undefined8 **)(param_1 + 0x38);
    if (puVar6 != (undefined8 *)0x0) {
      *(undefined8 *)(param_1 + 0x38) = *puVar6;
    }
    *(undefined4 *)puVar6 = 4;
    if (*(int *)(param_1 + 0x28) < *(int *)(param_1 + 0x2c)) {
      *(undefined8 **)(*(long *)(param_1 + 0x30) + (long)*(int *)(param_1 + 0x28) * 8) = puVar6;
      *(int *)(param_1 + 0x28) = *(int *)(param_1 + 0x28) + 1;
    }
  }
  if ((DAT_7105a064a0 == (uint *)0x0) || ((char)DAT_7105a064a0[0x10] == '\0')) {
    iVar2 = FUN_71024fcfa0();
    iVar3 = FUN_71024fd1e0();
    uVar4 = (iVar2 - iVar3) + iVar3 * 8;
    pbVar5 = &DAT_71032c57c7;
    pbVar1 = &DAT_71032c57c7 + uVar4;
    if (0x5a < uVar4) {
      pbVar1 = pbVar5;
    }
    if ((char)*pbVar1 < '\0') {
      if (iVar2 - 1U < 6) {
        iVar3 = *(int *)(&DAT_71032b46f4 + (long)(int)(iVar2 - 1U) * 4);
      }
      else {
        iVar3 = 0;
      }
      if ((uint)(iVar3 + iVar2) < 0x5b) {
        pbVar5 = &DAT_71032c57c7 + (uint)(iVar3 + iVar2);
      }
      uVar4 = (int)(char)*pbVar5 & ((int)(char)*pbVar5 >> 0x1f ^ 0xffffffffU);
    }
    else {
      uVar4 = (uint)*pbVar1;
    }
  }
  else {
    uVar4 = *DAT_7105a064a0;
  }
  if (((uVar4 & 0xfffffffe) != 0xe) && (*(int *)(param_1 + 0x28) < *(int *)(param_1 + 0x2c))) {
    puVar6 = *(undefined8 **)(param_1 + 0x38);
    if (puVar6 != (undefined8 *)0x0) {
      *(undefined8 *)(param_1 + 0x38) = *puVar6;
    }
    *(undefined4 *)puVar6 = 3;
    if (*(int *)(param_1 + 0x28) < *(int *)(param_1 + 0x2c)) {
      *(undefined8 **)(*(long *)(param_1 + 0x30) + (long)*(int *)(param_1 + 0x28) * 8) = puVar6;
      *(int *)(param_1 + 0x28) = *(int *)(param_1 + 0x28) + 1;
    }
  }
  return;
}



void FUN_71019de218(long param_1)

{
  byte *pbVar1;
  char *pcVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  undefined8 *puVar6;
  
  if (*(int *)(param_1 + 0x28) < *(int *)(param_1 + 0x2c)) {
    puVar6 = *(undefined8 **)(param_1 + 0x38);
    if (puVar6 != (undefined8 *)0x0) {
      *(undefined8 *)(param_1 + 0x38) = *puVar6;
    }
    *(undefined4 *)puVar6 = 9;
    if (*(int *)(param_1 + 0x28) < *(int *)(param_1 + 0x2c)) {
      *(undefined8 **)(*(long *)(param_1 + 0x30) + (long)*(int *)(param_1 + 0x28) * 8) = puVar6;
      *(int *)(param_1 + 0x28) = *(int *)(param_1 + 0x28) + 1;
    }
  }
  if ((DAT_7105a064a0 == (uint *)0x0) || ((char)DAT_7105a064a0[0x10] == '\0')) {
    iVar3 = FUN_71024fcfa0();
    iVar4 = FUN_71024fd1e0();
    uVar5 = (iVar3 - iVar4) + iVar4 * 8;
    pbVar1 = &DAT_71032c57c7 + uVar5;
    if (0x5a < uVar5) {
      pbVar1 = &DAT_71032c57c7;
    }
    if ((char)*pbVar1 < '\0') {
      if (iVar3 - 1U < 6) {
        iVar4 = *(int *)(&DAT_71032b46f4 + (long)(int)(iVar3 - 1U) * 4);
      }
      else {
        iVar4 = 0;
      }
      pcVar2 = &DAT_71032c57c7 + (uint)(iVar4 + iVar3);
      if (0x5a < (uint)(iVar4 + iVar3)) {
        pcVar2 = "";
      }
      uVar5 = (int)*pcVar2 & ((int)*pcVar2 >> 0x1f ^ 0xffffffffU);
    }
    else {
      uVar5 = (uint)*pbVar1;
    }
  }
  else {
    uVar5 = *DAT_7105a064a0;
  }
  if (((uVar5 & 0xfffffffe) != 0xe) && (*(int *)(param_1 + 0x28) < *(int *)(param_1 + 0x2c))) {
    puVar6 = *(undefined8 **)(param_1 + 0x38);
    if (puVar6 != (undefined8 *)0x0) {
      *(undefined8 *)(param_1 + 0x38) = *puVar6;
    }
    *(undefined4 *)puVar6 = 3;
    if (*(int *)(param_1 + 0x28) < *(int *)(param_1 + 0x2c)) {
      *(undefined8 **)(*(long *)(param_1 + 0x30) + (long)*(int *)(param_1 + 0x28) * 8) = puVar6;
      *(int *)(param_1 + 0x28) = *(int *)(param_1 + 0x28) + 1;
    }
  }
  return;
}



void FUN_71019de440(long *param_1)

{
  long *plVar1;
  long *plVar2;
  long lVar3;
  long *plVar4;
  long lVar5;
  
  *param_1 = DAT_7103a65b60 + 0x10;
  plVar2 = DAT_7103a65db8;
  if (param_1[0x17] != 0) {
    if (0 < (int)param_1[0x16]) {
      lVar3 = 0;
      plVar1 = (long *)param_1[0x18];
      do {
        plVar4 = *(long **)(param_1[0x17] + lVar3 * 8);
        lVar3 = lVar3 + 1;
        *plVar4 = (long)plVar1;
        param_1[0x18] = (long)plVar4;
        plVar1 = plVar4;
      } while (lVar3 < (int)param_1[0x16]);
    }
    lVar5 = param_1[0x19];
    *(undefined4 *)(param_1 + 0x16) = 0;
    lVar3 = *plVar2;
    if (lVar3 == 0) {
      FUN_71005fbbd0(lVar5);
    }
    else if ((lVar5 != 0) && (plVar1 = FUN_71024ef490(lVar3,lVar5), plVar1 != (long *)0x0)) {
      (**(code **)(*plVar1 + 0x38))(plVar1,lVar5);
    }
    *(undefined4 *)((long)param_1 + 0xcc) = 0;
    *(undefined8 *)((long)param_1 + 0xc4) = 0;
    *(undefined8 *)((long)param_1 + 0xbc) = 0;
    *(undefined8 *)((long)param_1 + 0xb4) = 0;
  }
  if ((char)param_1[0x1b] != '\0') {
    *(undefined1 *)(param_1 + 0x1b) = 0;
  }
  lVar3 = *plVar2;
  if (lVar3 != 0) {
    plVar2 = FUN_71024ef490(lVar3,param_1);
    if (plVar2 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071019de538. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*plVar2 + 0x38))(plVar2,param_1);
      return;
    }
    return;
  }
  FUN_71005fbbd0((long)param_1);
  return;
}



void FUN_71019de568(long param_1)

{
  byte *pbVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  byte *pbVar5;
  undefined8 *puVar6;
  
  iVar2 = *(int *)(param_1 + 0x28);
  iVar3 = *(int *)(param_1 + 0x2c);
  if (iVar2 < iVar3) {
    puVar6 = *(undefined8 **)(param_1 + 0x38);
    if (puVar6 != (undefined8 *)0x0) {
      *(undefined8 *)(param_1 + 0x38) = *puVar6;
    }
    *(undefined4 *)puVar6 = 9;
    iVar2 = *(int *)(param_1 + 0x28);
    iVar3 = *(int *)(param_1 + 0x2c);
    if (iVar2 < iVar3) {
      *(undefined8 **)(*(long *)(param_1 + 0x30) + (long)iVar2 * 8) = puVar6;
      iVar3 = *(int *)(param_1 + 0x2c);
      iVar2 = *(int *)(param_1 + 0x28) + 1;
      *(int *)(param_1 + 0x28) = iVar2;
    }
  }
  if (iVar2 < iVar3) {
    puVar6 = *(undefined8 **)(param_1 + 0x38);
    if (puVar6 != (undefined8 *)0x0) {
      *(undefined8 *)(param_1 + 0x38) = *puVar6;
    }
    *(undefined4 *)puVar6 = 4;
    if (*(int *)(param_1 + 0x28) < *(int *)(param_1 + 0x2c)) {
      *(undefined8 **)(*(long *)(param_1 + 0x30) + (long)*(int *)(param_1 + 0x28) * 8) = puVar6;
      *(int *)(param_1 + 0x28) = *(int *)(param_1 + 0x28) + 1;
    }
  }
  if ((DAT_7105a064a0 == (uint *)0x0) || ((char)DAT_7105a064a0[0x10] == '\0')) {
    iVar2 = FUN_71024fcfa0();
    iVar3 = FUN_71024fd1e0();
    uVar4 = (iVar2 - iVar3) + iVar3 * 8;
    pbVar5 = &DAT_71032c57c7;
    pbVar1 = &DAT_71032c57c7 + uVar4;
    if (0x5a < uVar4) {
      pbVar1 = pbVar5;
    }
    if ((char)*pbVar1 < '\0') {
      if (iVar2 - 1U < 6) {
        iVar3 = *(int *)(&DAT_71032b46f4 + (long)(int)(iVar2 - 1U) * 4);
      }
      else {
        iVar3 = 0;
      }
      if ((uint)(iVar3 + iVar2) < 0x5b) {
        pbVar5 = &DAT_71032c57c7 + (uint)(iVar3 + iVar2);
      }
      uVar4 = (int)(char)*pbVar5 & ((int)(char)*pbVar5 >> 0x1f ^ 0xffffffffU);
    }
    else {
      uVar4 = (uint)*pbVar1;
    }
  }
  else {
    uVar4 = *DAT_7105a064a0;
  }
  if (((uVar4 & 0xfffffffe) != 0xe) && (*(int *)(param_1 + 0x28) < *(int *)(param_1 + 0x2c))) {
    puVar6 = *(undefined8 **)(param_1 + 0x38);
    if (puVar6 != (undefined8 *)0x0) {
      *(undefined8 *)(param_1 + 0x38) = *puVar6;
    }
    *(undefined4 *)puVar6 = 3;
    if (*(int *)(param_1 + 0x28) < *(int *)(param_1 + 0x2c)) {
      *(undefined8 **)(*(long *)(param_1 + 0x30) + (long)*(int *)(param_1 + 0x28) * 8) = puVar6;
      *(int *)(param_1 + 0x28) = *(int *)(param_1 + 0x28) + 1;
    }
  }
  return;
}



void FUN_71019de7d0(long *param_1)

{
  long *plVar1;
  long *plVar2;
  long lVar3;
  long *plVar4;
  long lVar5;
  
  *param_1 = DAT_7103a65b60 + 0x10;
  plVar2 = DAT_7103a65db8;
  if (param_1[0x17] != 0) {
    if (0 < (int)param_1[0x16]) {
      lVar3 = 0;
      plVar1 = (long *)param_1[0x18];
      do {
        plVar4 = *(long **)(param_1[0x17] + lVar3 * 8);
        lVar3 = lVar3 + 1;
        *plVar4 = (long)plVar1;
        param_1[0x18] = (long)plVar4;
        plVar1 = plVar4;
      } while (lVar3 < (int)param_1[0x16]);
    }
    lVar5 = param_1[0x19];
    *(undefined4 *)(param_1 + 0x16) = 0;
    lVar3 = *plVar2;
    if (lVar3 == 0) {
      FUN_71005fbbd0(lVar5);
    }
    else if ((lVar5 != 0) && (plVar1 = FUN_71024ef490(lVar3,lVar5), plVar1 != (long *)0x0)) {
      (**(code **)(*plVar1 + 0x38))(plVar1,lVar5);
    }
    *(undefined4 *)((long)param_1 + 0xcc) = 0;
    *(undefined8 *)((long)param_1 + 0xc4) = 0;
    *(undefined8 *)((long)param_1 + 0xbc) = 0;
    *(undefined8 *)((long)param_1 + 0xb4) = 0;
  }
  if ((char)param_1[0x1b] != '\0') {
    *(undefined1 *)(param_1 + 0x1b) = 0;
  }
  lVar3 = *plVar2;
  if (lVar3 != 0) {
    plVar2 = FUN_71024ef490(lVar3,param_1);
    if (plVar2 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071019de8c8. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*plVar2 + 0x38))(plVar2,param_1);
      return;
    }
    return;
  }
  FUN_71005fbbd0((long)param_1);
  return;
}



bool FUN_71019de8f0(long *param_1,uint param_2)

{
  uint *puVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  bool bVar7;
  long lVar8;
  ulong uVar9;
  long lVar10;
  
  lVar10 = *DAT_7103a5ca10;
  if (lVar10 != 0) {
    lVar8 = FUN_7100d21570(DAT_710407a3f8);
    puVar1 = (uint *)(*(long *)(lVar8 + 0x88) + (ulong)param_2 * 4);
    if (*(int *)(lVar8 + 0x80) <= (int)param_2 || 0x7fffffff < param_2) {
      puVar1 = DAT_7103a5d090;
    }
    uVar9 = FUN_7101a293c0(lVar10,*puVar1);
    if ((uVar9 & 1) == 0) {
      return false;
    }
  }
  uVar9 = (**(code **)(*param_1 + 0x100))(param_1,(ulong)param_2);
  if ((uVar9 & 1) != 0) {
    return false;
  }
  lVar10 = FUN_7100d21570(DAT_710407a3f8);
  puVar1 = (uint *)(*(long *)(lVar10 + 0x88) + (ulong)param_2 * 4);
  if (*(int *)(lVar10 + 0x80) <= (int)param_2 || 0x7fffffff < param_2) {
    puVar1 = DAT_7103a5d090;
  }
  uVar2 = *puVar1;
  lVar10 = FUN_7100d21570(DAT_710407a3f8);
  if ((uVar2 != 0) && (uVar3 = *(uint *)(lVar10 + 0x2c), uVar3 != 0)) {
    uVar5 = 0;
    if (uVar3 != 0) {
      uVar5 = uVar2 / uVar3;
    }
    uVar5 = uVar2 - uVar5 * uVar3;
    uVar6 = uVar5;
    do {
      uVar4 = *(uint *)(*(long *)(lVar10 + 0x20) +
                       (-(ulong)(uVar6 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar6 << 4));
      if (uVar4 == uVar2) {
        lVar10 = *(long *)(*(long *)(lVar10 + 0x20) + (long)(int)uVar6 * 0x10 + 8);
        if ((lVar10 != 0) && (*(int *)(lVar10 + 0x7c) != 0)) {
          return false;
        }
        break;
      }
      if (uVar4 == 0) break;
      uVar4 = 0;
      if ((int)(uVar6 + 1) < (int)uVar3) {
        uVar4 = uVar6 + 1;
      }
      uVar6 = uVar4;
    } while (uVar4 != uVar5);
  }
  bVar7 = FUN_710197c180((long)param_1,param_2);
  return bVar7;
}



int FUN_71019dea40(long *param_1,uint *param_2,uint *param_3)

{
  uint *puVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint *puVar8;
  ulong uVar9;
  long lVar10;
  long lVar11;
  ulong uVar12;
  
  uVar2 = *param_2;
  uVar12 = (ulong)uVar2;
  uVar3 = *param_3;
  uVar9 = (**(code **)(*param_1 + 0x108))(param_1,uVar12);
  if (((uVar9 & 1) == 0) ||
     (uVar9 = (**(code **)(*param_1 + 0x108))(param_1,uVar3), (uVar9 & 1) != 0)) {
    uVar9 = (**(code **)(*param_1 + 0x108))(param_1,uVar12);
    if (((uVar9 & 1) == 0) &&
       (uVar9 = (**(code **)(*param_1 + 0x108))(param_1,uVar3), (uVar9 & 1) != 0)) {
      return -1;
    }
    lVar10 = FUN_710197c2a0(param_1,uVar2);
    lVar11 = FUN_710197c2a0(param_1,uVar3);
    if (*(ulong *)(lVar11 + 8) < *(ulong *)(lVar10 + 8)) {
      return -1;
    }
    if (*(ulong *)(lVar11 + 8) <= *(ulong *)(lVar10 + 8)) {
      lVar10 = FUN_7100d21570(DAT_710407a3f8);
      puVar8 = DAT_7103a5d090;
      puVar1 = (uint *)(*(long *)(lVar10 + 0x88) + uVar12 * 4);
      if (*(int *)(lVar10 + 0x80) <= (int)uVar2 || 0x7fffffff < uVar2) {
        puVar1 = DAT_7103a5d090;
      }
      uVar3 = *puVar1;
      lVar10 = FUN_7100d21570(DAT_710407a3f8);
      if ((uVar3 != 0) && (uVar4 = *(uint *)(lVar10 + 0x2c), uVar4 != 0)) {
        uVar7 = 0;
        if (uVar4 != 0) {
          uVar7 = uVar3 / uVar4;
        }
        uVar7 = uVar3 - uVar7 * uVar4;
        uVar6 = uVar7;
        do {
          uVar5 = *(uint *)(*(long *)(lVar10 + 0x20) +
                           (-(ulong)(uVar6 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar6 << 4));
          if (uVar5 == uVar3) {
            lVar10 = *(long *)(*(long *)(lVar10 + 0x20) + (long)(int)uVar6 * 0x10 + 8);
            goto LAB_71019deba0;
          }
          if (uVar5 == 0) break;
          uVar5 = 0;
          if ((int)(uVar6 + 1) < (int)uVar4) {
            uVar5 = uVar6 + 1;
          }
          uVar6 = uVar5;
        } while (uVar5 != uVar7);
      }
      lVar10 = 0;
LAB_71019deba0:
      lVar11 = FUN_7100d21570(DAT_710407a3f8);
      puVar1 = (uint *)(*(long *)(lVar11 + 0x88) + uVar12 * 4);
      if (*(int *)(lVar11 + 0x80) <= (int)uVar2 || 0x7fffffff < uVar2) {
        puVar1 = puVar8;
      }
      uVar2 = *puVar1;
      lVar11 = FUN_7100d21570(DAT_710407a3f8);
      if ((uVar2 == 0) || (uVar3 = *(uint *)(lVar11 + 0x2c), uVar3 == 0)) {
        return 0;
      }
      uVar4 = 0;
      if (uVar3 != 0) {
        uVar4 = uVar2 / uVar3;
      }
      uVar4 = uVar2 - uVar4 * uVar3;
      uVar7 = uVar4;
      do {
        uVar6 = *(uint *)(*(long *)(lVar11 + 0x20) +
                         (-(ulong)(uVar7 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar7 << 4));
        if (uVar6 == uVar2) {
          if (lVar10 == 0) {
            return 0;
          }
          lVar11 = *(long *)(*(long *)(lVar11 + 0x20) + (long)(int)uVar7 * 0x10 + 8);
          if (lVar11 == 0) {
            return 0;
          }
          return *(int *)(lVar10 + 0x9c) - *(int *)(lVar11 + 0x9c);
        }
        if (uVar6 == 0) {
          return 0;
        }
        uVar6 = 0;
        if ((int)(uVar7 + 1) < (int)uVar3) {
          uVar6 = uVar7 + 1;
        }
        uVar7 = uVar6;
      } while (uVar6 != uVar4);
      return 0;
    }
  }
  return 1;
}



bool FUN_71019dec5c(undefined8 param_1,uint param_2)

{
  bool bVar1;
  long lVar2;
  
  lVar2 = FUN_710197c2a0(param_1,param_2);
  bVar1 = false;
  if (lVar2 != 0) {
    bVar1 = *(int *)(lVar2 + 0x18) == 4 && *(char *)(lVar2 + 0x14) != '\0' ||
            *(int *)(lVar2 + 0x18) == 1;
  }
  return bVar1;
}



void FUN_71019dee08(undefined8 param_1,uint param_2)

{
  long lVar1;
  
  lVar1 = FUN_710197c3b0(param_1,param_2);
  if (lVar1 != 0) {
    if (*(int *)(lVar1 + 0x18) == 1) {
      *(undefined4 *)(lVar1 + 0x18) = 3;
      return;
    }
    if ((*(int *)(lVar1 + 0x18) == 4) && (*(char *)(lVar1 + 0x14) != '\0')) {
      *(undefined1 *)(lVar1 + 0x14) = 0;
    }
  }
  return;
}



void FUN_71019dee50(undefined1 param_1 [16],float param_2,undefined8 param_3,long param_4,
                   uint param_5)

{
  uint *puVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  byte bVar5;
  uint uVar6;
  uint uVar7;
  long *plVar8;
  int iVar9;
  long lVar10;
  undefined1 extraout_q0 [16];
  undefined1 auVar11 [16];
  long alStack_180 [3];
  long local_168;
  uint local_160;
  long local_158;
  long local_150;
  int local_148;
  char local_c0;
  undefined7 uStack_bf;
  int local_b8;
  
  plVar8 = DAT_7103a59ec8;
  lVar10 = FUN_7100d21570(*DAT_7103a59ec8);
  puVar1 = (uint *)(*(long *)(lVar10 + 0x88) + (ulong)param_5 * 4);
  if (*(int *)(lVar10 + 0x80) <= (int)param_5 || 0x7fffffff < param_5) {
    puVar1 = DAT_7103a5d090;
  }
  uVar2 = *puVar1;
  local_160 = uVar2;
  lVar10 = FUN_7100d21570(*plVar8);
  if ((uVar2 != 0) && (uVar3 = *(uint *)(lVar10 + 0x2c), uVar3 != 0)) {
    uVar6 = 0;
    if (uVar3 != 0) {
      uVar6 = uVar2 / uVar3;
    }
    uVar6 = uVar2 - uVar6 * uVar3;
    uVar7 = uVar6;
    do {
      uVar4 = *(uint *)(*(long *)(lVar10 + 0x20) +
                       (-(ulong)(uVar7 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar7 << 4));
      if (uVar4 == uVar2) {
        local_158 = *(long *)(*(long *)(lVar10 + 0x20) + (long)(int)uVar7 * 0x10 + 8);
        local_168 = DAT_7103a5c980 + 0x10;
        if (local_158 == 0) {
          return;
        }
        FUN_7101508e50((long *)&local_c0,&local_168);
        *(undefined1 *)((long)local_b8 + CONCAT71(uStack_bf,local_c0) + -1) = 0;
        (**(code **)(local_168 + 0x20))(&local_150,&local_168);
        *(undefined1 *)(local_148 + local_150 + -1) = 0;
        FUN_7101d9eaf0(alStack_180,(undefined8 *)&local_c0,&local_150);
        local_c0 = '\0';
        iVar9 = FUN_710292ebe0(param_4,*(long **)(param_4 + 0x18),(long *)"T_Item_00",alStack_180,0,
                               -1,&local_c0,0);
        if (iVar9 == 0) {
          return;
        }
        if (local_c0 == '\0') {
          return;
        }
        bVar5 = *(byte *)(param_4 + 0x90);
        auVar11 = extraout_q0;
        if ((bVar5 & 1) != 0) {
          auVar11 = FUN_7102932010(extraout_q0,param_2,param_4,*(long **)(param_4 + 0x18));
          bVar5 = *(byte *)(param_4 + 0x90);
        }
        if ((bVar5 >> 2 & 1) == 0) {
          return;
        }
        lVar10 = *(long *)(param_4 + 0x88);
        if (lVar10 == 0) {
          return;
        }
        FUN_7102932010(auVar11,param_2,lVar10,*(long **)(lVar10 + 0x18));
        return;
      }
      if (uVar4 == 0) {
        return;
      }
      uVar4 = 0;
      if ((int)(uVar7 + 1) < (int)uVar3) {
        uVar4 = uVar7 + 1;
      }
      uVar7 = uVar4;
    } while (uVar4 != uVar6);
  }
  return;
}



undefined8 FUN_71019defe8(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if (((DAT_71040e3e98 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_71040e3e98), iVar1 != 0))
  {
    DAT_71040e3e90 = &DAT_710398ce90;
    thunk_EXT_FUN_02e95df0(&DAT_71040e3e98);
  }
  if ((undefined **)param_2 != &DAT_71040e3e90) {
    if (((*DAT_7103a65b50 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a65b50), iVar1 != 0)
       ) {
      *DAT_7103a65b48 = DAT_7103a59af0 + 0x10;
      thunk_EXT_FUN_02e95df0(DAT_7103a65b50);
    }
    if (param_2 != DAT_7103a65b48) {
      param_1 = 0;
    }
  }
  return param_1;
}



undefined8 * FUN_71019df0d8(void)

{
  int iVar1;
  
  if (((DAT_71040e3e98 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_71040e3e98), iVar1 != 0))
  {
    DAT_71040e3e90 = &DAT_710398ce90;
    thunk_EXT_FUN_02e95df0(&DAT_71040e3e98);
  }
  return &DAT_71040e3e90;
}



void FUN_71019df130(long *param_1)

{
  long *plVar1;
  long *plVar2;
  long lVar3;
  long *plVar4;
  long lVar5;
  
  *param_1 = DAT_7103a65b60 + 0x10;
  plVar2 = DAT_7103a65db8;
  if (param_1[0x17] != 0) {
    if (0 < (int)param_1[0x16]) {
      lVar3 = 0;
      plVar1 = (long *)param_1[0x18];
      do {
        plVar4 = *(long **)(param_1[0x17] + lVar3 * 8);
        lVar3 = lVar3 + 1;
        *plVar4 = (long)plVar1;
        param_1[0x18] = (long)plVar4;
        plVar1 = plVar4;
      } while (lVar3 < (int)param_1[0x16]);
    }
    lVar5 = param_1[0x19];
    *(undefined4 *)(param_1 + 0x16) = 0;
    lVar3 = *plVar2;
    if (lVar3 == 0) {
      FUN_71005fbbd0(lVar5);
    }
    else if ((lVar5 != 0) && (plVar1 = FUN_71024ef490(lVar3,lVar5), plVar1 != (long *)0x0)) {
      (**(code **)(*plVar1 + 0x38))(plVar1,lVar5);
    }
    *(undefined4 *)((long)param_1 + 0xcc) = 0;
    *(undefined8 *)((long)param_1 + 0xc4) = 0;
    *(undefined8 *)((long)param_1 + 0xbc) = 0;
    *(undefined8 *)((long)param_1 + 0xb4) = 0;
  }
  if ((char)param_1[0x1b] != '\0') {
    *(undefined1 *)(param_1 + 0x1b) = 0;
  }
  lVar3 = *plVar2;
  if (lVar3 != 0) {
    plVar2 = FUN_71024ef490(lVar3,param_1);
    if (plVar2 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071019df228. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*plVar2 + 0x38))(plVar2,param_1);
      return;
    }
    return;
  }
  FUN_71005fbbd0((long)param_1);
  return;
}



bool FUN_71019df250(long *param_1,uint param_2)

{
  uint *puVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint *puVar7;
  ulong uVar8;
  long lVar9;
  
  uVar8 = (**(code **)(*param_1 + 0x100))();
  if ((uVar8 & 1) == 0) {
    lVar9 = FUN_7100d53f40(DAT_710407a3f8);
    puVar7 = DAT_7103a5cdf0;
    puVar1 = (uint *)(*(long *)(lVar9 + 0x88) + (ulong)param_2 * 4);
    if (*(int *)(lVar9 + 0x80) <= (int)param_2 || 0x7fffffff < param_2) {
      puVar1 = DAT_7103a5cdf0;
    }
    uVar2 = *puVar1;
    lVar9 = FUN_7100d53f40(DAT_710407a3f8);
    if ((uVar2 != 0) && (uVar3 = *(uint *)(lVar9 + 0x2c), uVar3 != 0)) {
      uVar5 = 0;
      if (uVar3 != 0) {
        uVar5 = uVar2 / uVar3;
      }
      uVar5 = uVar2 - uVar5 * uVar3;
      uVar6 = uVar5;
      do {
        uVar4 = *(uint *)(*(long *)(lVar9 + 0x20) +
                         (-(ulong)(uVar6 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar6 << 4));
        if (uVar4 == uVar2) {
          if (*(long *)(*(long *)(lVar9 + 0x20) + (long)(int)uVar6 * 0x10 + 8) == 0) {
            return false;
          }
          lVar9 = FUN_7100d53f40(DAT_710407a3f8);
          puVar1 = (uint *)(*(long *)(lVar9 + 0x88) + (ulong)param_2 * 4);
          if (*(int *)(lVar9 + 0x80) <= (int)param_2 || 0x7fffffff < param_2) {
            puVar1 = puVar7;
          }
          uVar2 = *puVar1;
          lVar9 = FUN_7100d53f40(DAT_710407a3f8);
          if (uVar2 != 0) {
            uVar3 = *(uint *)(lVar9 + 0x2c);
            if (uVar3 == 0) {
              return true;
            }
            uVar5 = 0;
            if (uVar3 != 0) {
              uVar5 = uVar2 / uVar3;
            }
            uVar5 = uVar2 - uVar5 * uVar3;
            uVar6 = uVar5;
            while( true ) {
              uVar4 = *(uint *)(*(long *)(lVar9 + 0x20) +
                               (-(ulong)(uVar6 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar6 << 4));
              if (uVar4 == uVar2) {
                lVar9 = *(long *)(*(long *)(lVar9 + 0x20) + (long)(int)uVar6 * 0x10 + 8);
                if (lVar9 == 0) {
                  return true;
                }
                return *(int *)(lVar9 + 0x54) != 2;
              }
              if (uVar4 == 0) break;
              uVar4 = 0;
              if ((int)(uVar6 + 1) < (int)uVar3) {
                uVar4 = uVar6 + 1;
              }
              uVar6 = uVar4;
              if (uVar4 == uVar5) {
                return true;
              }
            }
            return true;
          }
          return true;
        }
        if (uVar4 == 0) {
          return false;
        }
        uVar4 = 0;
        if ((int)(uVar6 + 1) < (int)uVar3) {
          uVar4 = uVar6 + 1;
        }
        uVar6 = uVar4;
      } while (uVar4 != uVar5);
    }
  }
  return false;
}



bool FUN_71019df3d4(undefined8 param_1,uint param_2)

{
  bool bVar1;
  long lVar2;
  
  lVar2 = FUN_71019d9f00(param_2);
  bVar1 = false;
  if (lVar2 != 0) {
    bVar1 = *(int *)(lVar2 + 0x18) == 4 && *(char *)(lVar2 + 0x14) != '\0' ||
            *(int *)(lVar2 + 0x18) == 1;
  }
  return bVar1;
}



void FUN_71019df578(undefined8 param_1,uint param_2)

{
  long lVar1;
  
  lVar1 = FUN_71019da010(param_2);
  if (lVar1 != 0) {
    if (*(int *)(lVar1 + 0x18) == 1) {
      *(undefined4 *)(lVar1 + 0x18) = 3;
      return;
    }
    if ((*(int *)(lVar1 + 0x18) == 4) && (*(char *)(lVar1 + 0x14) != '\0')) {
      *(undefined1 *)(lVar1 + 0x14) = 0;
    }
  }
  return;
}



void FUN_71019df5d0(undefined8 *param_1,undefined4 param_2)

{
  long lVar1;
  long lVar2;
  long lVar3;
  undefined8 *puVar4;
  long lVar5;
  long lVar6;
  
  param_1[0xe] = 0;
  param_1[0xd] = param_1 + 0xe;
  param_1[0xc] = param_1 + 0xd;
  *(undefined2 *)(param_1 + 1) = 0;
  *(undefined1 *)((long)param_1 + 10) = 0;
  *(undefined8 *)((long)param_1 + 0xc) = 0xffffffffffffffff;
  *(undefined2 *)((long)param_1 + 0x14) = 0;
  *(undefined4 *)(param_1 + 4) = 0xffffffff;
  *param_1 = &DAT_7103987b08;
  param_1[5] = 0;
  param_1[6] = 0;
  param_1[0xb] = param_1 + 0xc;
  param_1[10] = param_1 + 0xb;
  param_1[3] = 0xffffffff3f800000;
  puVar4 = param_1 + 9;
  *puVar4 = param_1 + 10;
  param_1[7] = puVar4;
  param_1[8] = puVar4;
  if (param_1 + 0xf != (undefined8 *)0x0) {
    param_1[6] = param_1 + 0xf;
    *(undefined4 *)((long)param_1 + 0x2c) = 6;
  }
  *(undefined4 *)(param_1 + 0x15) = 0;
  *(undefined1 *)(param_1 + 0x1a) = 1;
  param_1[0x16] = 0;
  param_1[0x17] = 0;
  *(undefined4 *)((long)param_1 + 0xd4) = 0;
  *(undefined1 *)(param_1 + 0x1b) = 0;
  param_1[0x18] = 0;
  param_1[0x19] = 0;
  thunk_EXT_FUN_02e95df0(param_1 + 0x1c,0,0x1010);
  lVar5 = 0x114c;
  lVar6 = 0x10fc;
  lVar3 = 0;
  do {
    *(long *)((long)param_1 + lVar3 + 0x10f0) = (long)param_1 + lVar6;
    lVar1 = lVar3 + 0xa0;
    lVar2 = (long)param_1 + lVar5;
    *(undefined4 *)((long)param_1 + lVar3 + 0x10f8) = 0x20;
    lVar5 = lVar5 + 0xa0;
    lVar6 = lVar6 + 0xa0;
    *(undefined2 *)((long)param_1 + lVar3 + 0x113a) = 0;
    *(undefined2 *)((long)param_1 + lVar3 + 0x10fc) = 0;
    *(long *)((long)param_1 + lVar3 + 0x1140) = lVar2;
    *(undefined4 *)((long)param_1 + lVar3 + 0x1148) = 0x20;
    *(undefined2 *)((long)param_1 + lVar3 + 0x118a) = 0;
    *(undefined2 *)((long)param_1 + lVar3 + 0x114c) = 0;
    lVar3 = lVar1;
  } while (lVar1 != 0x14000);
  *(undefined4 *)(param_1 + 0x2a20) = 0xffffffff;
  *(undefined4 *)((long)param_1 + 0x15104) = param_2;
  param_1[0x2a1e] = 0;
  param_1[0x2a1f] = 0xffffffffffffffff;
  *param_1 = &DAT_710398a4d8;
  return;
}



void FUN_71019df720(void)

{
  byte bVar1;
  char cVar2;
  byte *pbVar3;
  bool bVar4;
  bool bVar5;
  uint uVar6;
  int iVar7;
  long *plVar8;
  long *plVar9;
  undefined8 uVar10;
  long lVar11;
  int *piVar12;
  undefined8 *puVar13;
  undefined4 auStack_38 [2];
  
  iVar7 = *(int *)(*DAT_7103a5a158 + 0x18);
  if (iVar7 == 0) {
    uVar6 = DAT_7103a59b30[1];
    piVar12 = DAT_7103a59b30;
    if (-1 < (int)uVar6) goto LAB_71019df77c;
LAB_71019df7d8:
    plVar8 = FUN_7100c880c4();
  }
  else {
    lVar11 = *(long *)(*DAT_7103a5a158 + 8);
    if (iVar7 < 1) {
      lVar11 = 0;
    }
    piVar12 = (int *)0x0;
    if (lVar11 != 0) {
      piVar12 = (int *)(lVar11 + -8);
    }
    uVar6 = piVar12[1];
    if ((int)uVar6 < 0) goto LAB_71019df7d8;
LAB_71019df77c:
    lVar11 = *(long *)((uint *)*DAT_7103a59c40 + 2);
    if (lVar11 == 0) goto LAB_71019df7d8;
    if (*(uint *)*DAT_7103a59c40 <= uVar6) {
      uVar6 = 0;
    }
    if (*(int *)(lVar11 + (ulong)uVar6 * 0x10 + 4) != *piVar12) goto LAB_71019df7d8;
    puVar13 = *(undefined8 **)(lVar11 + (ulong)uVar6 * 0x10 + 8);
    if (puVar13 == (undefined8 *)0x0) {
      puVar13 = FUN_7100baff84();
    }
    plVar8 = (long *)((long)puVar13 + (long)*(int *)((long)puVar13 + 0x104) + 0x104);
    if (*(int *)((long)puVar13 + 0x104) == 0 || plVar8 == (long *)0x0) goto LAB_71019df7d8;
  }
  plVar9 = DAT_7103a5bd20;
  puVar13 = (undefined8 *)plVar8[8];
  lVar11 = *DAT_7103a5bd20;
  uVar6 = (**(code **)(**(long **)(lVar11 + 0x28) + 0x48))(*(long **)(lVar11 + 0x28),0xdfdc70b6);
  pbVar3 = DAT_7103a5bca8;
  if (*(uint *)(lVar11 + 8) <= uVar6) {
    uVar6 = 0;
  }
  plVar8 = *(long **)(*(long *)(lVar11 + 0x10) + (long)(int)uVar6 * 8);
  if (((*DAT_7103a5bca8 & 1) == 0) && (iVar7 = thunk_EXT_FUN_02e95df0(DAT_7103a5bca8), iVar7 != 0))
  {
    *DAT_7103a5bca0 = DAT_7103a5bcb0 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5bca8);
  }
  if ((plVar8 == (long *)0x0) ||
     (plVar8 = (long *)(**(code **)(*plVar8 + 0x10))(plVar8,DAT_7103a5bca0), plVar8 == (long *)0x0))
  {
    plVar8 = (long *)0x0;
  }
  if (((*DAT_7103a5bf78 & 1) == 0) && (iVar7 = thunk_EXT_FUN_02e95df0(DAT_7103a5bf78), iVar7 != 0))
  {
    *DAT_7103a5bf70 = DAT_7103a5bc98 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5bf78);
  }
  if ((plVar8 == (long *)0x0) ||
     (plVar8 = (long *)(**(code **)(*plVar8 + 0x10))(plVar8,DAT_7103a5bf70), plVar8 == (long *)0x0))
  {
    plVar8 = (long *)0x0;
  }
  lVar11 = *plVar9;
  uVar6 = (**(code **)(**(long **)(lVar11 + 0x28) + 0x48))(*(long **)(lVar11 + 0x28),0x70c10367);
  if (*(uint *)(lVar11 + 8) <= uVar6) {
    uVar6 = 0;
  }
  plVar9 = *(long **)(*(long *)(lVar11 + 0x10) + (long)(int)uVar6 * 8);
  if (((*pbVar3 & 1) == 0) && (iVar7 = thunk_EXT_FUN_02e95df0(DAT_7103a5bca8), iVar7 != 0)) {
    *DAT_7103a5bca0 = DAT_7103a5bcb0 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5bca8);
  }
  if ((plVar9 == (long *)0x0) ||
     (plVar9 = (long *)(**(code **)(*plVar9 + 0x10))(plVar9,DAT_7103a5bca0), plVar9 == (long *)0x0))
  {
    plVar9 = (long *)0x0;
  }
  if (((*DAT_7103a5c8e8 & 1) == 0) && (iVar7 = thunk_EXT_FUN_02e95df0(DAT_7103a5c8e8), iVar7 != 0))
  {
    *DAT_7103a5c8e0 = DAT_7103a5bc98 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5c8e8);
  }
  lVar11 = (**(code **)(*plVar9 + 0x10))(plVar9,DAT_7103a5c8e0);
  bVar1 = *(byte *)(lVar11 + 0x11e);
  cVar2 = *(char *)(lVar11 + 0x11d);
  bVar4 = false;
  bVar5 = false;
  if (bVar1 == 0) {
    bVar5 = SBORROW4((int)cVar2,1);
    bVar4 = cVar2 + -1 < 0;
  }
  if (((bVar1 != 3) && (bVar4 == bVar5)) && ((-1 < cVar2 || (1 < bVar1 - 1)))) {
    if (puVar13 == (undefined8 *)0x0) {
      puVar13 = FUN_7101487090();
    }
    FUN_710145e958(auStack_38,*(undefined4 *)(puVar13 + 1));
    iVar7 = *(int *)((long)puVar13 + 0x144);
    lVar11 = FUN_710145ea90(auStack_38);
    if (iVar7 != *(int *)(lVar11 + 8) + -1) {
      bVar1 = *(byte *)((long)plVar8 + 0x11e);
      cVar2 = *(char *)((long)plVar8 + 0x11d);
      bVar4 = false;
      bVar5 = false;
      if (bVar1 == 0) {
        bVar5 = SBORROW4((int)cVar2,1);
        bVar4 = cVar2 + -1 < 0;
      }
      if ((bVar1 != 3) && (bVar4 == bVar5)) {
        if (-1 < cVar2) {
          return;
        }
        if (1 < bVar1 - 1) {
          return;
        }
      }
      uVar10 = 1;
      lVar11 = 5;
      *(undefined1 *)(plVar8 + 0x69) = 1;
      goto LAB_71019df9e0;
    }
  }
  cVar2 = *(char *)((long)plVar8 + 0x11e);
  uVar10 = 0xffffffff;
  lVar11 = 6;
  if ((cVar2 != '\x01') && (cVar2 != '\x02' || *(char *)((long)plVar8 + 0x11d) < '\0')) {
    if ((*(char *)((long)plVar8 + 0x11d) < '\x01') || (cVar2 != '\x03' && cVar2 != '\0')) {
      return;
    }
    lVar11 = 6;
  }
LAB_71019df9e0:
                    // WARNING: Could not recover jumptable at 0x0071019df9fc. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*plVar8 + lVar11 * 8))(plVar8,uVar10);
  return;
}



void FUN_71019dfb50(undefined1 *param_1,ulong param_2)

{
  int *piVar1;
  uint uVar2;
  int iVar3;
  long *plVar4;
  undefined8 *puVar5;
  long lVar6;
  
  FUN_7100ee94c0(1);
  lVar6 = *DAT_7103a5bd20;
  uVar2 = (**(code **)(**(long **)(lVar6 + 0x28) + 0x48))(*(long **)(lVar6 + 0x28),0x70c10367);
  if (*(uint *)(lVar6 + 8) <= uVar2) {
    uVar2 = 0;
  }
  plVar4 = *(long **)(*(long *)(lVar6 + 0x10) + (long)(int)uVar2 * 8);
  if (((*DAT_7103a5bca8 & 1) == 0) && (iVar3 = thunk_EXT_FUN_02e95df0(DAT_7103a5bca8), iVar3 != 0))
  {
    *DAT_7103a5bca0 = DAT_7103a5bcb0 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a5bca8);
  }
  if ((plVar4 != (long *)0x0) &&
     (plVar4 = (long *)(**(code **)(*plVar4 + 0x10))(plVar4,DAT_7103a5bca0), plVar4 != (long *)0x0))
  {
    if ((param_2 & 1) == 0) {
      (**(code **)(*plVar4 + 0x30))(plVar4,0xffffffff);
    }
    else {
      *(undefined1 *)((long)plVar4 + 0x122) = 1;
    }
  }
  iVar3 = *(int *)(*DAT_7103a5a158 + 0x18);
  if (iVar3 == 0) {
    uVar2 = DAT_7103a59b30[1];
    piVar1 = DAT_7103a59b30;
  }
  else {
    lVar6 = *(long *)(*DAT_7103a5a158 + 8);
    if (iVar3 < 1) {
      lVar6 = 0;
    }
    piVar1 = (int *)0x0;
    if (lVar6 != 0) {
      piVar1 = (int *)(lVar6 + -8);
    }
    uVar2 = piVar1[1];
  }
  if (-1 < (int)uVar2) {
    lVar6 = *(long *)((uint *)*DAT_7103a59c40 + 2);
    if (lVar6 != 0) {
      if (*(uint *)*DAT_7103a59c40 <= uVar2) {
        uVar2 = 0;
      }
      if (*(int *)(lVar6 + (ulong)uVar2 * 0x10 + 4) == *piVar1) {
        puVar5 = *(undefined8 **)(lVar6 + (ulong)uVar2 * 0x10 + 8);
        if (puVar5 == (undefined8 *)0x0) {
          puVar5 = FUN_7100baff84();
          iVar3 = *(int *)((long)puVar5 + 0x104);
        }
        else {
          iVar3 = *(int *)((long)puVar5 + 0x104);
        }
        if ((iVar3 != 0) &&
           (plVar4 = (long *)((long)puVar5 + (long)iVar3 + 0x104), plVar4 != (long *)0x0))
        goto LAB_71019dfc98;
      }
    }
  }
  plVar4 = FUN_7100c87cb8();
LAB_71019dfc98:
  lVar6 = plVar4[8];
  if (lVar6 != 0) {
    if (param_1 != (undefined1 *)0x0) {
      *param_1 = *(undefined1 *)(lVar6 + 0x1f8);
    }
    *(undefined1 *)(lVar6 + 0x1f8) = 0;
  }
  return;
}



undefined4
FUN_71019dff10(undefined1 param_1 [16],float param_2,long param_3,long *param_4,undefined8 *param_5,
              undefined8 *param_6,undefined8 param_7,undefined8 param_8,undefined8 param_9,
              undefined8 param_10,undefined8 *param_11,undefined8 *param_12,undefined8 *param_13,
              undefined8 param_14,byte param_15)

{
  undefined4 uVar1;
  undefined4 uVar2;
  int iVar3;
  uint uVar4;
  long local_a0 [3];
  undefined8 uStack_88;
  undefined8 local_80;
  undefined4 local_78;
  undefined8 local_70;
  undefined8 uStack_68;
  int local_60;
  ulong local_5c;
  undefined4 local_54;
  undefined8 local_50;
  undefined1 *local_48;
  undefined1 *puStack_40;
  undefined4 local_38;
  
  uVar2 = (undefined4)param_9;
  if ((*(int *)(param_3 + 4) == 0) && (*(char *)(param_3 + 0x23) != '\0')) {
    local_a0[2] = *param_5;
    local_80 = 0;
    local_78 = 0;
    uStack_88 = *param_6;
    local_5c = 0;
    local_a0[0] = DAT_7103a67c10 + 0x10;
    local_a0[1] = 0x6c4471a3;
    local_70 = 0xffffffffffffffff;
    uStack_68 = param_14;
    local_54 = 4;
    local_38 = 0;
    local_48 = &DAT_71032a8da0;
    puStack_40 = &DAT_71032a8da0;
    if ((int)param_7 == 1) {
      local_48 = (undefined1 *)*param_11;
      puStack_40 = (undefined1 *)*param_12;
      param_11 = param_13;
    }
    local_50 = *param_11;
    if ((param_15 & 1) != 0) {
      local_5c = 0x1000000;
    }
    local_5c = CONCAT71(local_5c._1_7_,(char)param_10) & 0xffffffffffffff01;
    local_60 = (int)param_7;
    FUN_7102109680(param_1,param_2,(long)param_4,local_a0,(long)param_5,param_6,param_7,param_8,
                   param_9,param_10);
    FUN_7102109cf8((long)param_4);
  }
  if (*(char *)(DAT_7104202ae8 + 0xf4) == '\0') {
    FUN_71019e91c4((uint *)(param_4 + 4));
    (**(code **)(*param_4 + 0x30))(param_4);
    iVar3 = (int)param_4[4];
  }
  else {
    iVar3 = (int)param_4[4];
  }
  if ((iVar3 != 0) || (uVar4 = *(uint *)(param_4 + 0xd), 6 < uVar4)) {
    uVar4 = 0;
  }
  if ((&DAT_71038b7800)[uVar4] != 3) {
    uVar2 = 0xffffffff;
  }
  uVar1 = (int)param_8;
  if (1 < (&DAT_71038b7800)[uVar4] - 1) {
    uVar1 = uVar2;
  }
  return uVar1;
}



void FUN_71019e0140(int *param_1,int *param_2,int *param_3)

{
  uint uVar1;
  byte bVar2;
  int iVar3;
  long *plVar4;
  undefined8 *puVar5;
  long lVar6;
  uint uVar7;
  
  uVar1 = param_3[1];
  if ((int)uVar1 < 0) {
    return;
  }
  lVar6 = *(long *)(DAT_71040e7d48 + 2);
  if (lVar6 == 0) {
    return;
  }
  uVar7 = uVar1;
  if (*DAT_71040e7d48 <= uVar1) {
    uVar7 = 0;
  }
  if (*(int *)(lVar6 + (ulong)uVar7 * 0x10 + 4) != *param_3) {
    return;
  }
  lVar6 = *(long *)(lVar6 + (ulong)uVar7 * 0x10 + 8);
  if (lVar6 == 0) {
    plVar4 = FUN_7100bc6230();
    uVar1 = param_3[1];
    uVar7 = (uint)*(byte *)((long)plVar4 + 0x24);
    puVar5 = DAT_7103a59c40;
    if (-1 < (int)uVar1) goto LAB_71019e01a4;
  }
  else {
    uVar7 = (uint)*(byte *)(lVar6 + 0x24);
    puVar5 = &DAT_71040e7d48;
LAB_71019e01a4:
    lVar6 = *(long *)((uint *)*puVar5 + 2);
    if (*(uint *)*puVar5 <= uVar1) {
      uVar1 = 0;
    }
    if (((lVar6 != 0) && (lVar6 = lVar6 + (ulong)uVar1 * 0x10, *(int *)(lVar6 + 4) == *param_3)) &&
       (plVar4 = *(long **)(lVar6 + 8), plVar4 != (long *)0x0)) goto LAB_71019e0210;
  }
  plVar4 = FUN_7100bc6230();
LAB_71019e0210:
  bVar2 = *(byte *)((long)plVar4 + 0x25);
  iVar3 = uVar7 * bVar2;
  if (param_1 != (int *)0x0) {
    *param_1 = iVar3 * 0x1c;
  }
  if (param_2 != (int *)0x0) {
    *param_2 = uVar7 * 2 + iVar3 * 0x22 + (uint)bVar2 * 2;
  }
  return;
}



// WARNING: Removing unreachable block (ram,0x0071019e0ff4)
// WARNING: Removing unreachable block (ram,0x0071019e0fac)

int FUN_71019e0260(long param_1,int *param_2,long param_3)

{
  long lVar1;
  ulong uVar2;
  undefined8 *puVar3;
  float *pfVar4;
  float *pfVar5;
  int iVar6;
  uint uVar7;
  int iVar8;
  byte bVar9;
  char cVar10;
  int iVar11;
  long *plVar12;
  byte *pbVar13;
  bool bVar14;
  int iVar15;
  uint uVar16;
  uint uVar17;
  long *plVar18;
  long lVar19;
  undefined8 *puVar20;
  float *pfVar21;
  uint uVar22;
  uint uVar23;
  int *piVar24;
  int *piVar25;
  uint uVar26;
  uint uVar27;
  int iVar28;
  long lVar29;
  long lVar30;
  uint *puVar31;
  undefined8 *puVar32;
  ulong uVar33;
  undefined8 *puVar34;
  ulong uVar35;
  ulong uVar36;
  undefined8 *puVar37;
  undefined8 uVar38;
  uint uVar39;
  long lVar40;
  long lVar41;
  uint uVar42;
  uint uVar43;
  uint uVar44;
  float fVar45;
  float fVar46;
  float fVar47;
  float fVar48;
  float fVar49;
  float fVar50;
  float fVar51;
  float fVar52;
  float fVar53;
  ulong local_258;
  ulong local_250;
  float local_230 [90];
  long local_c8;
  undefined1 local_c0;
  undefined1 local_bf;
  char local_be;
  int local_b8;
  int local_b4 [4];
  undefined8 local_a4;
  undefined4 local_9c;
  
  local_9c = 0;
  local_b8 = -1;
  local_a4 = 0xffffffffffffffff;
  if ((param_3 != 0) && (*(long *)(param_3 + 0x210) != 0)) {
    FUN_7100d7e470(param_3,param_2);
  }
  uVar26 = param_2[1];
  if ((int)uVar26 < 0) {
LAB_71019e0320:
    plVar18 = FUN_7100bc6230();
    uVar26 = param_2[1];
    uVar43 = (uint)*(byte *)((long)plVar18 + 0x24);
    if (-1 < (int)uVar26) goto LAB_71019e0330;
LAB_71019e037c:
    plVar18 = FUN_7100bc6230();
  }
  else {
    lVar29 = *(long *)((uint *)*DAT_7103a59c40 + 2);
    if (*(uint *)*DAT_7103a59c40 <= uVar26) {
      uVar43 = 0;
      if (lVar29 != 0) goto LAB_71019e02f0;
      goto LAB_71019e0320;
    }
    uVar43 = uVar26;
    if (lVar29 == 0) goto LAB_71019e0320;
LAB_71019e02f0:
    lVar29 = lVar29 + (ulong)uVar43 * 0x10;
    if ((*(int *)(lVar29 + 4) != *param_2) || (lVar29 = *(long *)(lVar29 + 8), lVar29 == 0))
    goto LAB_71019e0320;
    uVar43 = (uint)*(byte *)(lVar29 + 0x24);
LAB_71019e0330:
    lVar29 = *(long *)((uint *)*DAT_7103a59c40 + 2);
    if (*(uint *)*DAT_7103a59c40 <= uVar26) {
      uVar26 = 0;
      if (lVar29 != 0) goto LAB_71019e0350;
      goto LAB_71019e037c;
    }
    if (lVar29 == 0) goto LAB_71019e037c;
LAB_71019e0350:
    lVar29 = lVar29 + (ulong)uVar26 * 0x10;
    if ((*(int *)(lVar29 + 4) != *param_2) ||
       (plVar18 = *(long **)(lVar29 + 8), plVar18 == (long *)0x0)) goto LAB_71019e037c;
  }
  uVar26 = (uint)*(byte *)((long)plVar18 + 0x25);
  lVar29 = *(long *)(*DAT_7103a5ba40 + 8);
  if (lVar29 != 0) {
    piVar25 = (int *)(lVar29 + 0x164);
    do {
      cVar10 = '\x01';
      bVar14 = (bool)ExclusiveMonitorPass(piVar25,0x10);
      if (bVar14) {
        *piVar25 = *piVar25 + 1;
        cVar10 = ExclusiveMonitorsStatus();
      }
    } while (cVar10 != '\0');
  }
  lVar40 = *(long *)(param_3 + 0x240);
  lVar41 = *(long *)(param_3 + 0x230);
  uVar22 = param_2[1];
  if (-1 < (int)uVar22) {
    lVar30 = *(long *)((uint *)*DAT_7103a59c40 + 2);
    if (*(uint *)*DAT_7103a59c40 <= uVar22) {
      uVar22 = 0;
    }
    if (((lVar30 != 0) && (lVar30 = lVar30 + (ulong)uVar22 * 0x10, *(int *)(lVar30 + 4) == *param_2)
        ) && (plVar18 = *(long **)(lVar30 + 8), plVar18 != (long *)0x0)) goto LAB_71019e0420;
  }
  plVar18 = FUN_7100bc6230();
LAB_71019e0420:
  pbVar13 = DAT_7103a5ba10;
  plVar12 = DAT_7103a5ba08;
  fVar45 = *(float *)((long)plVar18 + 0x3c) - *(float *)((long)plVar18 + 0x34);
  fVar50 = (*(float *)(plVar18 + 7) - *(float *)(plVar18 + 6)) / (float)uVar43;
  fVar51 = fVar45 / (float)uVar26;
  if (lVar29 == 0) {
    lVar30 = 0;
  }
  else {
    lVar30 = *(long *)(lVar29 + 0x150);
  }
  fVar52 = fVar50 * 0.5 + (*(float *)(plVar18 + 7) - *(float *)(plVar18 + 6)) * -0.5;
  fVar45 = fVar51 * 0.5 + fVar45 * -0.5;
  lVar1 = DAT_7103a59c60 + 0x10;
  do {
    lVar19 = lVar30;
    if ((((*(byte *)(lVar19 + 0x114) & 1) != 0) || (*(long *)(lVar19 + 0x10) == 0)) ||
       ((plVar18 = *(long **)(lVar19 + 0x18), plVar18 == (long *)0x0 ||
        ((*(int *)((long)plVar18 + 0xc) != *(int *)(lVar19 + 0x20) ||
         (puVar20 = (undefined8 *)*plVar18, puVar20 == (undefined8 *)0x0)))))) break;
    if (((*pbVar13 & 1) == 0) && (iVar15 = thunk_EXT_FUN_02e95df0(pbVar13), iVar15 != 0)) {
      *plVar12 = lVar1;
      thunk_EXT_FUN_02e95df0(pbVar13);
    }
    lVar30 = (**(code **)*puVar20)(puVar20,plVar12);
  } while (lVar30 != 0);
  if ((uVar26 == 0) || (uVar43 == 0)) {
    lVar40 = *(long *)(param_1 + 0x20);
    uVar26 = *(uint *)(param_1 + 0x2c);
    if ((int)(*(uint *)(lVar40 + 0x34) & 0x7fffffff) < (int)uVar26) {
      FUN_7101a0bf68((undefined8 *)(lVar40 + 0x28),DAT_7103a65fc8,(ulong)uVar26);
    }
    if (*(uint *)(lVar40 + 0x30) != uVar26) {
      *(uint *)(lVar40 + 0x30) = uVar26;
    }
    lVar40 = *(long *)(param_1 + 0x20);
    iVar15 = 0;
  }
  else {
    puVar20 = (undefined8 *)(lVar41 + 0xe8);
    local_258 = 0;
    fVar53 = *(float *)(lVar19 + 0xe4);
    puVar3 = (undefined8 *)(lVar40 + 0x29d0);
    lVar40 = DAT_7103a5a2a8 + 0x10;
    uVar22 = 0;
    do {
      uVar44 = uVar22 + 1;
      uVar16 = 0;
      fVar49 = fVar45 + (float)(int)uVar22 * fVar51;
      uVar33 = (ulong)(uint)(fVar45 + (float)(int)uVar44 * fVar51);
      do {
        uVar23 = param_2[1];
        local_c8 = lVar40;
        if ((int)uVar23 < 0) {
LAB_71019e0620:
          plVar18 = FUN_7100bc6230();
        }
        else {
          puVar31 = (uint *)*DAT_7103a59c40;
          if (*puVar31 <= uVar23) {
            uVar23 = 0;
            lVar41 = *(long *)(puVar31 + 2);
            if (lVar41 != 0) goto LAB_71019e05e8;
            goto LAB_71019e0620;
          }
          lVar41 = *(long *)(puVar31 + 2);
          if (lVar41 == 0) goto LAB_71019e0620;
LAB_71019e05e8:
          lVar41 = lVar41 + (ulong)uVar23 * 0x10;
          if ((*(int *)(lVar41 + 4) != *param_2) ||
             (plVar18 = *(long **)(lVar41 + 8), plVar18 == (long *)0x0)) goto LAB_71019e0620;
        }
        uVar23 = *(uint *)(plVar18 + 4);
        local_c0 = (char)uVar16;
        local_bf = (char)uVar22;
        local_be = (char)uVar23;
        if (((uVar23 ^ 0xffffffff) & 0xff) != 0) {
          piVar25 = DAT_7103a5c420;
          if (*DAT_7103a5a160 == 0) {
            uVar17 = DAT_7103a5c420[1];
          }
          else {
            lVar41 = *(long *)(*DAT_7103a5a160 + ((ulong)uVar23 & 0xff) * 8 + 8);
            if (lVar41 != 0) {
              piVar25 = (int *)(lVar41 + 0x150);
            }
            uVar17 = piVar25[1];
          }
          if (-1 < (int)uVar17) {
            puVar31 = (uint *)*DAT_7103a59c40;
            if (uVar17 < *puVar31) {
              lVar41 = *(long *)(puVar31 + 2);
            }
            else {
              uVar17 = 0;
              lVar41 = *(long *)(puVar31 + 2);
            }
            if ((((lVar41 != 0) &&
                 (lVar41 = lVar41 + (ulong)uVar17 * 0x10, *(int *)(lVar41 + 4) == *piVar25)) &&
                (lVar41 = *(long *)(lVar41 + 8), lVar41 != 0)) &&
               (((uVar16 & 0xff) < (uint)*(byte *)(lVar41 + 0x24) &&
                ((uVar22 & 0xff) < (uint)*(byte *)(lVar41 + 0x25))))) {
              if ((param_3 == 0) || (*(long *)(param_3 + 0x210) == 0)) {
                piVar25 = &local_b8;
              }
              else {
                piVar25 = DAT_7103a5d120;
                if (((uVar16 < *(uint *)(param_3 + 0x5c8)) && (uVar22 < *(uint *)(param_3 + 0x5cc)))
                   && (*(long *)(param_3 + 0x5d0) != 0)) {
                  piVar25 = (int *)(*(long *)(param_3 + 0x5d0) +
                                   (long)(int)(uVar16 + *(uint *)(param_3 + 0x5c8) * uVar22) * 0x20)
                  ;
                }
              }
              FUN_7101d33efc((long)&local_c8);
              uVar17 = piVar25[5];
              if (uVar17 == 0xffffffff) {
                uVar17 = piVar25[6];
                if (uVar17 == 0xffffffff) {
                  lVar41 = *(long *)(*(long *)(*DAT_7103a5a160 + 0x818) + 0x20);
                  if ((lVar41 == 0) || ((char)uVar23 < '\0')) {
LAB_71019e0a74:
                    plVar18 = FUN_7100c83958();
                  }
                  else {
                    uVar23 = *(uint *)(lVar41 + ((ulong)uVar23 & 0xff) * 4 + 8);
                    if (uVar23 == 0xffffffff) goto LAB_71019e0a74;
                    puVar31 = (uint *)(lVar41 + 0x208);
                    if (uVar23 < 7) {
                      puVar31 = puVar31 + (ulong)uVar23 * 4;
                    }
                    if ((((*(long *)(puVar31 + 2) == 0) || (*puVar31 <= uVar16)) ||
                        (puVar31[1] <= uVar22)) ||
                       (plVar18 = *(long **)(*(long *)(puVar31 + 2) +
                                            (long)(int)(uVar16 + *puVar31 * uVar22) * 8),
                       plVar18 == (long *)0x0)) goto LAB_71019e0a74;
                  }
                  fVar46 = FUN_7101d0eb20((int)plVar18[4]);
                  fVar47 = fVar52 + (float)(int)uVar16 * fVar50;
                  uVar35 = -(local_258 >> 0x1f) & 0xfffffff000000000 | local_258 << 4;
                  local_258 = (ulong)((int)local_258 + 4);
                  puVar32 = (undefined8 *)(*(long *)(*(long *)(param_1 + 0x20) + 0x18) + uVar35);
                  puVar32[1] = (ulong)(uint)fVar49;
                  *puVar32 = CONCAT44(fVar46,fVar47);
                  lVar41 = uVar35 + *(long *)(*(long *)(param_1 + 0x20) + 0x18);
                  fVar48 = fVar52 + (float)(int)(uVar16 + 1) * fVar50;
                  *(ulong *)(lVar41 + 0x18) = (ulong)(uint)fVar49;
                  *(ulong *)(lVar41 + 0x10) = CONCAT44(fVar46,fVar48);
                  lVar41 = uVar35 + *(long *)(*(long *)(param_1 + 0x20) + 0x18);
                  *(ulong *)(lVar41 + 0x28) = uVar33;
                  *(ulong *)(lVar41 + 0x20) = CONCAT44(fVar46,fVar47);
                  lVar41 = uVar35 + *(long *)(*(long *)(param_1 + 0x20) + 0x18);
                  *(ulong *)(lVar41 + 0x38) = uVar33;
                  *(ulong *)(lVar41 + 0x30) = CONCAT44(fVar46,fVar48);
                }
                else {
                  puVar32 = puVar20;
                  if (uVar17 < 0xe) {
                    puVar32 = puVar20 + (ulong)uVar17 * 0xde;
                  }
                  uVar23 = *(uint *)(puVar32 + 0xdd);
                  if (0 < (int)uVar23) {
                    if ((uint)piVar25[7] < 4) {
                      puVar32 = puVar32 + (ulong)(uint)piVar25[7] * 0x2a;
                    }
                    uVar35 = 0;
                    if (uVar23 != 1) {
                      uVar2 = 0;
                      do {
                        uVar36 = uVar2;
                        puVar34 = (undefined8 *)((long)puVar32 + uVar35);
                        if (0x1b < uVar36) {
                          puVar34 = puVar32;
                        }
                        pfVar21 = (float *)((long)local_230 + uVar35);
                        if (0x1b < uVar36) {
                          pfVar21 = local_230;
                        }
                        uVar38 = *puVar34;
                        pfVar21[2] = *(float *)(puVar34 + 1);
                        uVar2 = uVar36 + 1;
                        *(undefined8 *)pfVar21 = uVar38;
                        if (uVar2 < 0x1c) {
                          puVar34 = (undefined8 *)((long)((long)puVar32 + uVar35) + 0xc);
                          if (0x1b < uVar2) goto LAB_71019e0944;
LAB_71019e0900:
                          pfVar21 = (float *)((long)local_230 + uVar35 + 0xc);
                        }
                        else {
                          puVar34 = puVar32;
                          if (uVar2 < 0x1c) goto LAB_71019e0900;
LAB_71019e0944:
                          pfVar21 = local_230;
                        }
                        uVar38 = *puVar34;
                        uVar35 = uVar35 + 0x18;
                        pfVar21[2] = *(float *)(puVar34 + 1);
                        *(undefined8 *)pfVar21 = uVar38;
                        uVar2 = uVar36 + 2;
                      } while (uVar36 + 2 != ((long)(int)uVar23 & 0xfffffffffffffffeU));
                      uVar35 = uVar36 + 2;
                    }
                    if (((long)(int)uVar23 & 1U) != 0) {
                      if (uVar35 < 0x1c) {
                        puVar32 = (undefined8 *)((long)puVar32 + uVar35 * 0xc);
                        pfVar21 = local_230 + uVar35 * 3;
                      }
                      else {
                        pfVar21 = local_230;
                      }
                      uVar38 = *puVar32;
                      pfVar21[2] = *(float *)(puVar32 + 1);
                      *(undefined8 *)pfVar21 = uVar38;
                    }
                    uVar35 = 0;
                    pfVar21 = local_230;
                    do {
                      pfVar4 = pfVar21 + 2;
                      pfVar5 = pfVar21;
                      if (0x1b < uVar35) {
                        pfVar4 = local_230 + 2;
                        pfVar5 = local_230;
                      }
                      fVar46 = *pfVar5;
                      pfVar5 = pfVar21 + 1;
                      if (0x1b < uVar35) {
                        pfVar5 = local_230 + 1;
                      }
                      pfVar21 = pfVar21 + 3;
                      fVar48 = *pfVar5;
                      puVar32 = (undefined8 *)
                                (*(long *)(*(long *)(param_1 + 0x20) + 0x18) +
                                 (-(local_258 >> 0x1f) & 0xfffffff000000000 | local_258 << 4) +
                                uVar35 * 0x10);
                      puVar32[1] = (ulong)(uint)(fVar49 + *pfVar4);
                      *puVar32 = CONCAT44(fVar48,fVar52 + (float)(int)uVar16 * fVar50 + fVar46);
                      uVar35 = uVar35 + 1;
                    } while (uVar23 != uVar35);
                    goto LAB_71019e0bd8;
                  }
                }
              }
              else {
                puVar32 = puVar3;
                if (uVar17 < 0xe) {
                  puVar32 = puVar3 + (ulong)uVar17 * 0xde;
                }
                uVar23 = *(uint *)(puVar32 + 0xdd);
                if (0 < (int)uVar23) {
                  if ((uint)piVar25[7] < 4) {
                    puVar32 = puVar32 + (ulong)(uint)piVar25[7] * 0x2a;
                  }
                  uVar35 = 0;
                  if (uVar23 != 1) {
                    uVar2 = 0;
                    do {
                      uVar36 = uVar2;
                      puVar34 = (undefined8 *)((long)puVar32 + uVar35);
                      if (0x1b < uVar36) {
                        puVar34 = puVar32;
                      }
                      pfVar21 = (float *)((long)local_230 + uVar35);
                      if (0x1b < uVar36) {
                        pfVar21 = local_230;
                      }
                      uVar38 = *puVar34;
                      pfVar21[2] = *(float *)(puVar34 + 1);
                      uVar2 = uVar36 + 1;
                      *(undefined8 *)pfVar21 = uVar38;
                      if (uVar2 < 0x1c) {
                        puVar34 = (undefined8 *)((long)((long)puVar32 + uVar35) + 0xc);
                        if (0x1b < uVar2) goto LAB_71019e0844;
LAB_71019e0800:
                        pfVar21 = (float *)((long)local_230 + uVar35 + 0xc);
                      }
                      else {
                        puVar34 = puVar32;
                        if (uVar2 < 0x1c) goto LAB_71019e0800;
LAB_71019e0844:
                        pfVar21 = local_230;
                      }
                      uVar38 = *puVar34;
                      uVar35 = uVar35 + 0x18;
                      pfVar21[2] = *(float *)(puVar34 + 1);
                      *(undefined8 *)pfVar21 = uVar38;
                      uVar2 = uVar36 + 2;
                    } while (uVar36 + 2 != ((long)(int)uVar23 & 0xfffffffffffffffeU));
                    uVar35 = uVar36 + 2;
                  }
                  if (((long)(int)uVar23 & 1U) != 0) {
                    if (uVar35 < 0x1c) {
                      puVar32 = (undefined8 *)((long)puVar32 + uVar35 * 0xc);
                      pfVar21 = local_230 + uVar35 * 3;
                    }
                    else {
                      pfVar21 = local_230;
                    }
                    uVar38 = *puVar32;
                    pfVar21[2] = *(float *)(puVar32 + 1);
                    *(undefined8 *)pfVar21 = uVar38;
                  }
                  uVar35 = 0;
                  pfVar21 = local_230;
                  do {
                    bVar14 = 0x1b < uVar35;
                    pfVar4 = pfVar21;
                    if (bVar14) {
                      pfVar4 = local_230;
                    }
                    fVar46 = *pfVar4;
                    pfVar4 = pfVar21 + 1;
                    if (bVar14) {
                      pfVar4 = local_230 + 1;
                    }
                    fVar48 = *pfVar4;
                    pfVar4 = pfVar21 + 2;
                    pfVar21 = pfVar21 + 3;
                    if (bVar14) {
                      pfVar4 = local_230 + 2;
                    }
                    puVar32 = (undefined8 *)
                              (*(long *)(*(long *)(param_1 + 0x20) + 0x18) +
                               (-(local_258 >> 0x1f) & 0xfffffff000000000 | local_258 << 4) +
                              uVar35 * 0x10);
                    puVar32[1] = (ulong)(uint)(fVar49 + *pfVar4);
                    *puVar32 = CONCAT44(fVar53 + fVar48,
                                        fVar52 + (float)(int)uVar16 * fVar50 + fVar46);
                    uVar35 = uVar35 + 1;
                  } while (uVar23 != uVar35);
LAB_71019e0bd8:
                  local_258 = (ulong)(uint)((int)local_258 + (int)uVar35);
                }
              }
            }
          }
        }
        uVar16 = uVar16 + 1;
      } while (uVar16 != uVar43);
      uVar22 = uVar44;
    } while (uVar44 != uVar26);
    lVar40 = *(long *)(param_1 + 0x20);
    uVar22 = *(uint *)(param_1 + 0x2c);
    if ((int)(*(uint *)(lVar40 + 0x34) & 0x7fffffff) < (int)uVar22) {
      FUN_7101a0bf68((undefined8 *)(lVar40 + 0x28),DAT_7103a65fc8,(ulong)uVar22);
    }
    if (*(uint *)(lVar40 + 0x30) != uVar22) {
      *(uint *)(lVar40 + 0x30) = uVar22;
    }
    local_250 = 0;
    uVar22 = 0;
    do {
      uVar44 = 0;
      do {
        if (param_3 == 0) {
          piVar25 = &local_b8;
          uVar16 = param_2[1];
joined_r0x0071019e0dbc:
          if ((int)uVar16 < 0) goto LAB_71019e0dc0;
LAB_71019e0d6c:
          puVar31 = (uint *)*DAT_7103a59c40;
          if (*puVar31 <= uVar16) {
            uVar16 = 0;
            lVar40 = *(long *)(puVar31 + 2);
            if (lVar40 != 0) goto LAB_71019e0d8c;
            goto LAB_71019e0dc0;
          }
          lVar40 = *(long *)(puVar31 + 2);
          if (lVar40 == 0) goto LAB_71019e0dc0;
LAB_71019e0d8c:
          lVar40 = lVar40 + (ulong)uVar16 * 0x10;
          if ((*(int *)(lVar40 + 4) != *param_2) ||
             (plVar18 = *(long **)(lVar40 + 8), plVar18 == (long *)0x0)) goto LAB_71019e0dc0;
        }
        else {
          if (*(long *)(param_3 + 0x210) != 0) {
            piVar25 = DAT_7103a5d120;
            if (uVar44 < *(uint *)(param_3 + 0x5c8)) {
              if (*(uint *)(param_3 + 0x5cc) <= uVar22) goto LAB_71019e0d64;
              if (*(long *)(param_3 + 0x5d0) != 0) {
                piVar25 = (int *)(*(long *)(param_3 + 0x5d0) +
                                 (long)(int)(uVar44 + *(uint *)(param_3 + 0x5c8) * uVar22) * 0x20);
              }
              uVar16 = param_2[1];
            }
            else {
              uVar16 = param_2[1];
            }
            goto joined_r0x0071019e0dbc;
          }
          piVar25 = &local_b8;
LAB_71019e0d64:
          uVar16 = param_2[1];
          if (-1 < (int)uVar16) goto LAB_71019e0d6c;
LAB_71019e0dc0:
          plVar18 = FUN_7100bc6230();
        }
        if (((*(uint *)(plVar18 + 4) ^ 0xffffffff) & 0xff) == 0) {
LAB_71019e0f60:
          iVar15 = -1;
        }
        else {
          uVar33 = (ulong)*(uint *)(plVar18 + 4) & 0xff;
          lVar40 = *DAT_7103a5a160;
          piVar24 = DAT_7103a5c420;
          if (lVar40 == 0) {
            uVar16 = DAT_7103a5c420[1];
            if (-1 < (int)uVar16) goto LAB_71019e0e20;
            goto LAB_71019e0f60;
          }
          lVar41 = *(long *)(lVar40 + uVar33 * 8 + 8);
          if (lVar41 != 0) {
            piVar24 = (int *)(lVar41 + 0x150);
          }
          uVar16 = piVar24[1];
          if ((int)uVar16 < 0) goto LAB_71019e0f60;
LAB_71019e0e20:
          puVar31 = (uint *)*DAT_7103a59c40;
          if (uVar16 < *puVar31) {
            lVar41 = *(long *)(puVar31 + 2);
          }
          else {
            uVar16 = 0;
            lVar41 = *(long *)(puVar31 + 2);
          }
          if (lVar41 == 0) goto LAB_71019e0f60;
          lVar41 = lVar41 + (ulong)uVar16 * 0x10;
          iVar15 = -1;
          if (((*(int *)(lVar41 + 4) == *piVar24) && (lVar41 = *(long *)(lVar41 + 8), lVar41 != 0))
             && ((iVar15 = -1, (uVar44 & 0xff) < (uint)*(byte *)(lVar41 + 0x24) &&
                 (iVar15 = -1, (uVar22 & 0xff) < (uint)*(byte *)(lVar41 + 0x25))))) {
            lVar40 = *(long *)(*(long *)(lVar40 + 0x818) + 0x20);
            if ((lVar40 == 0) || ((uint)uVar33 >> 7 != 0)) {
LAB_71019e0eec:
              plVar18 = FUN_7100c83958();
            }
            else {
              uVar16 = *(uint *)(lVar40 + uVar33 * 4 + 8);
              if (uVar16 == 0xffffffff) goto LAB_71019e0eec;
              puVar31 = (uint *)(lVar40 + 0x208);
              if (uVar16 < 7) {
                puVar31 = puVar31 + (ulong)uVar16 * 4;
              }
              if (*(long *)(puVar31 + 2) == 0) goto LAB_71019e0eec;
              if (((*puVar31 <= (uVar44 & 0xff)) || (puVar31[1] <= (uVar22 & 0xff))) ||
                 (plVar18 = *(long **)(*(long *)(puVar31 + 2) +
                                      (long)(int)((uVar44 & 0xff) + *puVar31 * (uVar22 & 0xff)) * 8)
                 , plVar18 == (long *)0x0)) goto LAB_71019e0eec;
            }
            uVar16 = FUN_7101d29450((long)plVar18);
            lVar40 = *(long *)(*(long *)(param_1 + 0x20) + 0x40);
            if (lVar40 != 0) {
              for (plVar18 = *(long **)(lVar40 + 0x58); plVar18 != (long *)0x0;
                  plVar18 = (long *)*plVar18) {
                if (*(uint *)(plVar18 + 3) <= uVar16) {
                  if (uVar16 <= *(uint *)(plVar18 + 3)) {
                    iVar15 = *(int *)((long)plVar18 + 0x1c);
                    if (iVar15 != -1) goto LAB_71019e0f64;
                    break;
                  }
                  plVar18 = plVar18 + 1;
                }
              }
            }
            iVar15 = 0;
          }
        }
LAB_71019e0f64:
        uVar16 = piVar25[5];
        iVar6 = *piVar25;
        if (uVar16 == 0xffffffff) {
          uVar16 = piVar25[6];
          if (uVar16 == 0xffffffff) {
            uVar33 = -(local_250 >> 0x1f) & 0xfffffff000000000 | local_250 << 4;
            local_250 = (ulong)((int)local_250 + 2);
            piVar25 = (int *)(*(long *)(*(long *)(param_1 + 0x20) + 0x28) + uVar33);
            *piVar25 = iVar6;
            piVar25[1] = iVar6 + 2;
            piVar25[2] = iVar6 + 1;
            piVar25[3] = iVar15;
            lVar40 = uVar33 + *(long *)(*(long *)(param_1 + 0x20) + 0x28);
            *(int *)(lVar40 + 0x10) = iVar6 + 1;
            *(int *)(lVar40 + 0x14) = iVar6 + 2;
            *(int *)(lVar40 + 0x18) = iVar6 + 3;
            *(int *)(lVar40 + 0x1c) = iVar15;
          }
          else {
            puVar32 = puVar20;
            if (uVar16 < 0xe) {
              puVar32 = puVar20 + (ulong)uVar16 * 0xde;
            }
            uVar16 = *(uint *)((long)puVar32 + 0x6ec);
            if (0 < (int)uVar16) {
              puVar34 = puVar32 + 0xb0;
              if (uVar16 == 1) {
                uVar35 = 0;
LAB_71019e1240:
                if (uVar35 < 0x1e) {
                  puVar34 = (undefined8 *)((long)puVar34 + uVar35 * 0xc);
                  pfVar21 = local_230 + uVar35 * 3;
                }
                else {
                  pfVar21 = local_230;
                }
                *(undefined8 *)pfVar21 = *puVar34;
                pfVar21[2] = *(float *)(puVar34 + 1);
              }
              else {
                lVar40 = 0;
                uVar33 = 0;
                do {
                  uVar35 = uVar33;
                  puVar37 = puVar34;
                  if (uVar35 < 0x1e) {
                    puVar37 = (undefined8 *)((long)puVar32 + lVar40 + 0x580);
                  }
                  pfVar21 = (float *)((long)local_230 + lVar40);
                  if (0x1d < uVar35) {
                    pfVar21 = local_230;
                  }
                  *(undefined8 *)pfVar21 = *puVar37;
                  pfVar21[2] = *(float *)(puVar37 + 1);
                  uVar33 = uVar35 + 1;
                  if (uVar33 < 0x1e) {
                    puVar37 = (undefined8 *)((long)puVar32 + lVar40 + 0x58c);
                    if (0x1d < uVar33) goto LAB_71019e1230;
LAB_71019e11ec:
                    pfVar21 = (float *)((long)local_230 + lVar40 + 0xc);
                  }
                  else {
                    puVar37 = puVar34;
                    if (uVar33 < 0x1e) goto LAB_71019e11ec;
LAB_71019e1230:
                    pfVar21 = local_230;
                  }
                  lVar40 = lVar40 + 0x18;
                  *(undefined8 *)pfVar21 = *puVar37;
                  pfVar21[2] = *(float *)(puVar37 + 1);
                  uVar33 = uVar35 + 2;
                } while (uVar35 + 2 != ((long)(int)uVar16 & 0xfffffffffffffffeU));
                uVar35 = uVar35 + 2;
                if ((uVar16 & 1) != 0) goto LAB_71019e1240;
              }
              lVar40 = 0;
              uVar33 = 0;
              uVar35 = -(local_250 >> 0x1f) & 0xfffffff000000000 | local_250 << 4;
              do {
                pfVar21 = (float *)((long)local_230 + lVar40 + 8);
                pfVar4 = (float *)((long)local_230 + lVar40 + 4);
                pfVar5 = (float *)((long)local_230 + lVar40);
                if (0x1d < uVar33) {
                  pfVar21 = local_230 + 2;
                  pfVar4 = local_230 + 1;
                  pfVar5 = local_230;
                }
                fVar45 = *pfVar4;
                fVar50 = *pfVar21;
                uVar33 = uVar33 + 1;
                lVar40 = lVar40 + 0xc;
                piVar25 = (int *)(*(long *)(*(long *)(param_1 + 0x20) + 0x28) + uVar35);
                uVar35 = uVar35 + 0x10;
                *piVar25 = (int)*pfVar5 + iVar6;
                piVar25[1] = (int)fVar45 + iVar6;
                piVar25[2] = (int)fVar50 + iVar6;
                piVar25[3] = iVar15;
              } while (uVar16 != uVar33);
              goto LAB_71019e0ce0;
            }
          }
        }
        else {
          puVar32 = puVar3;
          if (uVar16 < 0xe) {
            puVar32 = puVar3 + (ulong)uVar16 * 0xde;
          }
          uVar16 = *(uint *)((long)puVar32 + 0x6ec);
          if ((int)uVar16 < 1) goto LAB_71019e0ce4;
          puVar34 = puVar32 + 0xb0;
          if (uVar16 == 1) {
            uVar35 = 0;
LAB_71019e10a4:
            if (uVar35 < 0x1e) {
              puVar34 = (undefined8 *)((long)puVar34 + uVar35 * 0xc);
              pfVar21 = local_230 + uVar35 * 3;
            }
            else {
              pfVar21 = local_230;
            }
            *(undefined8 *)pfVar21 = *puVar34;
            pfVar21[2] = *(float *)(puVar34 + 1);
          }
          else {
            lVar40 = 0;
            uVar33 = 0;
            do {
              uVar35 = uVar33;
              puVar37 = puVar34;
              if (uVar35 < 0x1e) {
                puVar37 = (undefined8 *)((long)puVar32 + lVar40 + 0x580);
              }
              pfVar21 = (float *)((long)local_230 + lVar40);
              if (0x1d < uVar35) {
                pfVar21 = local_230;
              }
              *(undefined8 *)pfVar21 = *puVar37;
              pfVar21[2] = *(float *)(puVar37 + 1);
              uVar33 = uVar35 + 1;
              if (uVar33 < 0x1e) {
                puVar37 = (undefined8 *)((long)puVar32 + lVar40 + 0x58c);
                if (0x1d < uVar33) goto LAB_71019e1094;
LAB_71019e1050:
                pfVar21 = (float *)((long)local_230 + lVar40 + 0xc);
              }
              else {
                puVar37 = puVar34;
                if (uVar33 < 0x1e) goto LAB_71019e1050;
LAB_71019e1094:
                pfVar21 = local_230;
              }
              lVar40 = lVar40 + 0x18;
              *(undefined8 *)pfVar21 = *puVar37;
              pfVar21[2] = *(float *)(puVar37 + 1);
              uVar33 = uVar35 + 2;
            } while (uVar35 + 2 != ((long)(int)uVar16 & 0xfffffffffffffffeU));
            uVar35 = uVar35 + 2;
            if ((uVar16 & 1) != 0) goto LAB_71019e10a4;
          }
          lVar40 = 0;
          uVar33 = 0;
          uVar35 = -(local_250 >> 0x1f) & 0xfffffff000000000 | local_250 << 4;
          do {
            pfVar21 = (float *)((long)local_230 + lVar40 + 8);
            pfVar4 = (float *)((long)local_230 + lVar40 + 4);
            pfVar5 = (float *)((long)local_230 + lVar40);
            if (0x1d < uVar33) {
              pfVar21 = local_230 + 2;
              pfVar4 = local_230 + 1;
              pfVar5 = local_230;
            }
            fVar45 = *pfVar4;
            fVar50 = *pfVar21;
            uVar33 = uVar33 + 1;
            lVar40 = lVar40 + 0xc;
            piVar25 = (int *)(*(long *)(*(long *)(param_1 + 0x20) + 0x28) + uVar35);
            uVar35 = uVar35 + 0x10;
            *piVar25 = (int)*pfVar5 + iVar6;
            piVar25[1] = (int)fVar45 + iVar6;
            piVar25[2] = (int)fVar50 + iVar6;
            piVar25[3] = iVar15;
          } while (uVar16 != uVar33);
LAB_71019e0ce0:
          local_250 = (ulong)(uint)((int)local_250 + (int)uVar33);
        }
LAB_71019e0ce4:
        uVar44 = uVar44 + 1;
      } while (uVar44 != uVar43);
      uVar22 = uVar22 + 1;
    } while (uVar22 != uVar26);
    uVar22 = 0;
    do {
      uVar16 = uVar22 - 1;
      uVar44 = 0;
      uVar23 = uVar22 & 0xff;
      do {
        uVar17 = param_2[1];
        if ((int)uVar17 < 0) {
LAB_71019e13a4:
          plVar18 = FUN_7100bc6230();
        }
        else {
          puVar31 = (uint *)*DAT_7103a59c40;
          if (*puVar31 <= uVar17) {
            uVar17 = 0;
            lVar40 = *(long *)(puVar31 + 2);
            if (lVar40 != 0) goto LAB_71019e1374;
            goto LAB_71019e13a4;
          }
          lVar40 = *(long *)(puVar31 + 2);
          if (lVar40 == 0) goto LAB_71019e13a4;
LAB_71019e1374:
          lVar40 = lVar40 + (ulong)uVar17 * 0x10;
          if ((*(int *)(lVar40 + 4) != *param_2) ||
             (plVar18 = *(long **)(lVar40 + 8), plVar18 == (long *)0x0)) goto LAB_71019e13a4;
        }
        if (((*(uint *)(plVar18 + 4) ^ 0xffffffff) & 0xff) != 0) {
          uVar33 = (ulong)*(uint *)(plVar18 + 4) & 0xff;
          piVar25 = DAT_7103a5c420;
          if (*DAT_7103a5a160 == 0) {
            uVar17 = DAT_7103a5c420[1];
          }
          else {
            lVar40 = *(long *)(*DAT_7103a5a160 + uVar33 * 8 + 8);
            if (lVar40 != 0) {
              piVar25 = (int *)(lVar40 + 0x150);
            }
            uVar17 = piVar25[1];
          }
          if (-1 < (int)uVar17) {
            puVar31 = (uint *)*DAT_7103a59c40;
            if (uVar17 < *puVar31) {
              lVar40 = *(long *)(puVar31 + 2);
            }
            else {
              uVar17 = 0;
              lVar40 = *(long *)(puVar31 + 2);
            }
            if (((lVar40 != 0) &&
                (lVar41 = lVar40 + (ulong)uVar17 * 0x10, *(int *)(lVar41 + 4) == *piVar25)) &&
               ((lVar41 = *(long *)(lVar41 + 8), lVar41 != 0 &&
                (((uVar44 & 0xff) < (uint)*(byte *)(lVar41 + 0x24) &&
                 ((uVar22 & 0xff) < (uint)*(byte *)(lVar41 + 0x25))))))) {
              uVar17 = (uint)uVar33;
              if (param_3 == 0) {
                piVar25 = &local_b8;
joined_r0x0071019e1664:
                if (uVar22 == 0) goto LAB_71019e14b8;
LAB_71019e14e4:
                uVar39 = param_2[1];
                if ((int)uVar39 < 0) {
LAB_71019e1518:
                  plVar18 = FUN_7100bc6230();
                }
                else {
                  if (*puVar31 <= uVar39) {
                    uVar39 = 0;
                  }
                  if ((*(int *)(lVar40 + (ulong)uVar39 * 0x10 + 4) != *param_2) ||
                     (plVar18 = *(long **)(lVar40 + (ulong)uVar39 * 0x10 + 8),
                     plVar18 == (long *)0x0)) goto LAB_71019e1518;
                }
                bVar9 = *(byte *)(plVar18 + 4);
                uVar39 = uVar16;
                uVar42 = uVar44;
                if (bVar9 != 0xff) goto LAB_71019e153c;
joined_r0x0071019e1730:
                if (uVar44 == 0) goto LAB_71019e195c;
LAB_71019e1734:
                uVar39 = param_2[1];
                if ((int)uVar39 < 0) {
LAB_71019e192c:
                  plVar18 = FUN_7100bc6230();
                }
                else {
                  puVar31 = (uint *)*DAT_7103a59c40;
                  if (*puVar31 <= uVar39) {
                    uVar39 = 0;
                    lVar40 = *(long *)(puVar31 + 2);
                    if (lVar40 != 0) goto LAB_71019e175c;
                    goto LAB_71019e192c;
                  }
                  lVar40 = *(long *)(puVar31 + 2);
                  if (lVar40 == 0) goto LAB_71019e192c;
LAB_71019e175c:
                  lVar40 = lVar40 + (ulong)uVar39 * 0x10;
                  if ((*(int *)(lVar40 + 4) != *param_2) ||
                     (plVar18 = *(long **)(lVar40 + 8), plVar18 == (long *)0x0))
                  goto LAB_71019e192c;
                }
                bVar9 = *(byte *)(plVar18 + 4);
                uVar39 = uVar44 - 1;
                uVar42 = uVar22;
              }
              else {
                if (*(long *)(param_3 + 0x210) != 0) {
                  piVar25 = DAT_7103a5d120;
                  if (uVar44 < *(uint *)(param_3 + 0x5c8)) {
                    if (*(uint *)(param_3 + 0x5cc) <= uVar22) goto LAB_71019e14e0;
                    if (*(long *)(param_3 + 0x5d0) != 0) {
                      piVar25 = (int *)(*(long *)(param_3 + 0x5d0) +
                                       ((long)(int)(*(uint *)(param_3 + 0x5c8) * uVar22) +
                                       (long)(int)uVar44) * 0x20);
                    }
                  }
                  goto joined_r0x0071019e1664;
                }
                piVar25 = &local_b8;
LAB_71019e14e0:
                if (uVar22 != 0) goto LAB_71019e14e4;
LAB_71019e14b8:
                uVar42 = (uint)*(byte *)(DAT_7103a5ba30 + 8);
                uVar39 = (uint)*(byte *)(DAT_7103a5ba30 + 9);
                bVar9 = *(byte *)(DAT_7103a5ba30 + 10);
                if (bVar9 == 0xff) goto joined_r0x0071019e1730;
LAB_71019e153c:
                piVar24 = DAT_7103a5c420;
                if (*DAT_7103a5a160 == 0) {
                  uVar27 = DAT_7103a5c420[1];
                  if (-1 < (int)uVar27) goto LAB_71019e1584;
                  goto joined_r0x0071019e1730;
                }
                lVar40 = *(long *)(*DAT_7103a5a160 + (ulong)bVar9 * 8 + 8);
                if (lVar40 != 0) {
                  piVar24 = (int *)(lVar40 + 0x150);
                }
                uVar27 = piVar24[1];
                if ((int)uVar27 < 0) goto joined_r0x0071019e1730;
LAB_71019e1584:
                puVar31 = (uint *)*DAT_7103a59c40;
                if (*puVar31 <= uVar27) {
                  uVar27 = 0;
                  lVar40 = *(long *)(puVar31 + 2);
                  if (lVar40 != 0) goto LAB_71019e15a4;
                  goto joined_r0x0071019e1730;
                }
                lVar40 = *(long *)(puVar31 + 2);
                if (lVar40 == 0) goto joined_r0x0071019e1730;
LAB_71019e15a4:
                lVar40 = lVar40 + (ulong)uVar27 * 0x10;
                if ((((*(int *)(lVar40 + 4) != *piVar24) ||
                     (lVar40 = *(long *)(lVar40 + 8), lVar40 == 0)) ||
                    ((uint)*(byte *)(lVar40 + 0x24) <= (uVar42 & 0xff))) ||
                   ((uint)*(byte *)(lVar40 + 0x25) <= (uVar39 & 0xff))) goto joined_r0x0071019e1730;
                lVar40 = *(long *)(*(long *)(*DAT_7103a5a160 + 0x818) + 0x20);
                if ((lVar40 == 0) || (uVar17 >> 7 != 0)) {
LAB_71019e166c:
                  plVar18 = FUN_7100c83958();
                  uVar27 = *(uint *)(plVar18 + 4);
                  lVar40 = *(long *)(*(long *)(*DAT_7103a5a160 + 0x818) + 0x20);
                  if (lVar40 != 0) goto LAB_71019e168c;
LAB_71019e16e4:
                  plVar18 = FUN_7100c83958();
                }
                else {
                  uVar27 = *(uint *)(lVar40 + uVar33 * 4 + 8);
                  if (uVar27 == 0xffffffff) goto LAB_71019e166c;
                  puVar31 = (uint *)(lVar40 + 0x208);
                  if (uVar27 < 7) {
                    puVar31 = puVar31 + (ulong)uVar27 * 4;
                  }
                  if (*(long *)(puVar31 + 2) == 0) goto LAB_71019e166c;
                  if (((*puVar31 <= (uVar44 & 0xff)) || (puVar31[1] <= uVar23)) ||
                     (lVar41 = *(long *)(*(long *)(puVar31 + 2) +
                                        (long)(int)((uVar44 & 0xff) + *puVar31 * uVar23) * 8),
                     lVar41 == 0)) goto LAB_71019e166c;
                  uVar27 = *(uint *)(lVar41 + 0x20);
LAB_71019e168c:
                  if ((char)bVar9 < '\0') goto LAB_71019e16e4;
                  uVar7 = *(uint *)(lVar40 + (ulong)bVar9 * 4 + 8);
                  if (uVar7 == 0xffffffff) goto LAB_71019e16e4;
                  puVar31 = (uint *)(lVar40 + 0x208);
                  if (uVar7 < 7) {
                    puVar31 = puVar31 + (ulong)uVar7 * 4;
                  }
                  if (*(long *)(puVar31 + 2) == 0) goto LAB_71019e16e4;
                  if (((*puVar31 <= (uVar42 & 0xff)) || (puVar31[1] <= (uVar39 & 0xff))) ||
                     (plVar18 = *(long **)(*(long *)(puVar31 + 2) +
                                          (long)(int)((uVar42 & 0xff) + *puVar31 * (uVar39 & 0xff))
                                          * 8), plVar18 == (long *)0x0)) goto LAB_71019e16e4;
                }
                uVar39 = (uint)(uVar27 < 9) & 0x1a0U >> (ulong)(uVar27 & 0x1f);
                if ((*(uint *)(plVar18 + 4) < 9) &&
                   ((1 << (ulong)(*(uint *)(plVar18 + 4) & 0x1f) & 0x1a0U) != 0)) {
                  if (uVar39 != 0) goto joined_r0x0071019e1730;
                }
                else if (uVar39 == 0) goto joined_r0x0071019e1730;
                piVar24 = local_b4;
                if ((param_3 != 0) && (*(long *)(param_3 + 0x210) != 0)) {
                  piVar24 = DAT_7103a5d120;
                  if ((uVar44 < *(uint *)(param_3 + 0x5c8)) &&
                     ((uVar16 < *(uint *)(param_3 + 0x5cc) && (*(long *)(param_3 + 0x5d0) != 0)))) {
                    piVar24 = (int *)(*(long *)(param_3 + 0x5d0) +
                                     ((long)(int)(*(uint *)(param_3 + 0x5c8) * uVar16) +
                                     (long)(int)uVar44) * 0x20);
                  }
                  piVar24 = piVar24 + 1;
                }
                iVar15 = piVar24[2];
                iVar11 = piVar24[3];
                iVar6 = piVar25[1];
                iVar8 = piVar25[2];
                lVar40 = *(long *)(*(long *)(*DAT_7103a5a160 + 0x818) + 0x20);
                if ((lVar40 == 0) || (uVar17 >> 7 != 0)) {
LAB_71019e1890:
                  plVar18 = FUN_7100c83958();
                }
                else {
                  uVar39 = *(uint *)(lVar40 + uVar33 * 4 + 8);
                  if (uVar39 == 0xffffffff) goto LAB_71019e1890;
                  puVar31 = (uint *)(lVar40 + 0x208);
                  if (uVar39 < 7) {
                    puVar31 = puVar31 + (ulong)uVar39 * 4;
                  }
                  if (*(long *)(puVar31 + 2) == 0) goto LAB_71019e1890;
                  if (((*puVar31 <= (uVar44 & 0xff)) || (puVar31[1] <= uVar23)) ||
                     (plVar18 = *(long **)(*(long *)(puVar31 + 2) +
                                          (long)(int)((uVar44 & 0xff) + *puVar31 * uVar23) * 8),
                     plVar18 == (long *)0x0)) goto LAB_71019e1890;
                }
                uVar39 = FUN_7101d29450((long)plVar18);
                lVar40 = *(long *)(*(long *)(param_1 + 0x20) + 0x40);
                if (lVar40 != 0) {
                  for (plVar18 = *(long **)(lVar40 + 0x58); plVar18 != (long *)0x0;
                      plVar18 = (long *)*plVar18) {
                    if (*(uint *)(plVar18 + 3) <= uVar39) {
                      if (uVar39 <= *(uint *)(plVar18 + 3)) {
                        iVar28 = *(int *)((long)plVar18 + 0x1c);
                        goto LAB_71019e18b0;
                      }
                      plVar18 = plVar18 + 1;
                    }
                  }
                }
                iVar28 = -1;
LAB_71019e18b0:
                uVar35 = -(local_250 >> 0x1f) & 0xfffffff000000000 | local_250 << 4;
                local_250 = (ulong)((int)local_250 + 2);
                piVar25 = (int *)(*(long *)(*(long *)(param_1 + 0x20) + 0x28) + uVar35);
                *piVar25 = iVar15;
                piVar25[1] = iVar6;
                piVar25[2] = iVar11;
                piVar25[3] = iVar28 + 1;
                lVar40 = uVar35 + *(long *)(*(long *)(param_1 + 0x20) + 0x28);
                *(int *)(lVar40 + 0x10) = iVar11;
                *(int *)(lVar40 + 0x14) = iVar6;
                *(int *)(lVar40 + 0x18) = iVar8;
                *(int *)(lVar40 + 0x1c) = iVar28 + 1;
                if (uVar44 != 0) goto LAB_71019e1734;
LAB_71019e195c:
                uVar39 = (uint)*(byte *)(DAT_7103a5ba30 + 8);
                uVar42 = (uint)*(byte *)(DAT_7103a5ba30 + 9);
                bVar9 = *(byte *)(DAT_7103a5ba30 + 10);
              }
              if (bVar9 != 0xff) {
                lVar40 = *DAT_7103a5a160;
                piVar25 = DAT_7103a5c420;
                if (lVar40 == 0) {
                  uVar27 = DAT_7103a5c420[1];
                }
                else {
                  lVar41 = *(long *)(lVar40 + (ulong)bVar9 * 8 + 8);
                  if (lVar41 != 0) {
                    piVar25 = (int *)(lVar41 + 0x150);
                  }
                  uVar27 = piVar25[1];
                }
                if (-1 < (int)uVar27) {
                  puVar31 = (uint *)*DAT_7103a59c40;
                  if (uVar27 < *puVar31) {
                    lVar41 = *(long *)(puVar31 + 2);
                  }
                  else {
                    uVar27 = 0;
                    lVar41 = *(long *)(puVar31 + 2);
                  }
                  if (((lVar41 != 0) &&
                      (lVar41 = lVar41 + (ulong)uVar27 * 0x10, *(int *)(lVar41 + 4) == *piVar25)) &&
                     ((lVar41 = *(long *)(lVar41 + 8), lVar41 != 0 &&
                      (((uVar39 & 0xff) < (uint)*(byte *)(lVar41 + 0x24) &&
                       ((uVar42 & 0xff) < (uint)*(byte *)(lVar41 + 0x25))))))) {
                    lVar40 = *(long *)(*(long *)(lVar40 + 0x818) + 0x20);
                    if ((lVar40 == 0) || (uVar17 >> 7 != 0)) {
LAB_71019e1a8c:
                      plVar18 = FUN_7100c83958();
                      uVar27 = *(uint *)(plVar18 + 4);
                      lVar40 = *(long *)(*(long *)(*DAT_7103a5a160 + 0x818) + 0x20);
                      if (lVar40 != 0) goto LAB_71019e1aac;
LAB_71019e1b04:
                      plVar18 = FUN_7100c83958();
                    }
                    else {
                      uVar27 = *(uint *)(lVar40 + uVar33 * 4 + 8);
                      if (uVar27 == 0xffffffff) goto LAB_71019e1a8c;
                      puVar31 = (uint *)(lVar40 + 0x208);
                      if (uVar27 < 7) {
                        puVar31 = puVar31 + (ulong)uVar27 * 4;
                      }
                      if (*(long *)(puVar31 + 2) == 0) goto LAB_71019e1a8c;
                      if (((*puVar31 <= (uVar44 & 0xff)) || (puVar31[1] <= uVar23)) ||
                         (lVar41 = *(long *)(*(long *)(puVar31 + 2) +
                                            (long)(int)((uVar44 & 0xff) + *puVar31 * uVar23) * 8),
                         lVar41 == 0)) goto LAB_71019e1a8c;
                      uVar27 = *(uint *)(lVar41 + 0x20);
LAB_71019e1aac:
                      if ((char)bVar9 < '\0') goto LAB_71019e1b04;
                      uVar7 = *(uint *)(lVar40 + (ulong)bVar9 * 4 + 8);
                      if (uVar7 == 0xffffffff) goto LAB_71019e1b04;
                      puVar31 = (uint *)(lVar40 + 0x208);
                      if (uVar7 < 7) {
                        puVar31 = puVar31 + (ulong)uVar7 * 4;
                      }
                      if (*(long *)(puVar31 + 2) == 0) goto LAB_71019e1b04;
                      if (((*puVar31 <= (uVar39 & 0xff)) || (puVar31[1] <= (uVar42 & 0xff))) ||
                         (plVar18 = *(long **)(*(long *)(puVar31 + 2) +
                                              (long)(int)((uVar39 & 0xff) +
                                                         *puVar31 * (uVar42 & 0xff)) * 8),
                         plVar18 == (long *)0x0)) goto LAB_71019e1b04;
                    }
                    uVar39 = (uint)(uVar27 < 9) & 0x1a0U >> (ulong)(uVar27 & 0x1f);
                    if ((*(uint *)(plVar18 + 4) < 9) &&
                       ((1 << (ulong)(*(uint *)(plVar18 + 4) & 0x1f) & 0x1a0U) != 0)) {
                      if (uVar39 == 0) {
LAB_71019e1b54:
                        if ((param_3 == 0) || (*(long *)(param_3 + 0x210) == 0)) {
                          piVar25 = &local_b8;
                          piVar24 = local_b4;
                        }
                        else {
                          uVar39 = *(uint *)(param_3 + 0x5c8);
                          piVar25 = DAT_7103a5d120;
                          if (((uVar44 < uVar39) && (uVar22 < *(uint *)(param_3 + 0x5cc))) &&
                             (*(long *)(param_3 + 0x5d0) != 0)) {
                            piVar25 = (int *)(*(long *)(param_3 + 0x5d0) +
                                             ((long)(int)(uVar39 * uVar22) + (long)(int)uVar44) *
                                             0x20);
                          }
                          piVar24 = DAT_7103a5d120;
                          if ((((uint)((long)(int)uVar44 + -1) < uVar39) &&
                              (uVar22 < *(uint *)(param_3 + 0x5cc))) &&
                             (*(long *)(param_3 + 0x5d0) != 0)) {
                            piVar24 = (int *)(*(long *)(param_3 + 0x5d0) +
                                             ((long)(int)uVar44 + -1 + (long)(int)(uVar39 * uVar22))
                                             * 0x20);
                          }
                          piVar24 = piVar24 + 1;
                        }
                        iVar15 = piVar25[1];
                        iVar6 = piVar25[3];
                        iVar11 = piVar24[1];
                        iVar8 = piVar24[3];
                        lVar40 = *(long *)(*(long *)(*DAT_7103a5a160 + 0x818) + 0x20);
                        if ((lVar40 == 0) || (uVar17 >> 7 != 0)) {
LAB_71019e1c90:
                          plVar18 = FUN_7100c83958();
                        }
                        else {
                          uVar17 = *(uint *)(lVar40 + uVar33 * 4 + 8);
                          if (uVar17 == 0xffffffff) goto LAB_71019e1c90;
                          puVar31 = (uint *)(lVar40 + 0x208);
                          if (uVar17 < 7) {
                            puVar31 = puVar31 + (ulong)uVar17 * 4;
                          }
                          if (*(long *)(puVar31 + 2) == 0) goto LAB_71019e1c90;
                          if (((*puVar31 <= (uVar44 & 0xff)) || (puVar31[1] <= uVar23)) ||
                             (plVar18 = *(long **)(*(long *)(puVar31 + 2) +
                                                  (long)(int)((uVar44 & 0xff) + *puVar31 * uVar23) *
                                                  8), plVar18 == (long *)0x0)) goto LAB_71019e1c90;
                        }
                        uVar17 = FUN_7101d29450((long)plVar18);
                        lVar40 = *(long *)(*(long *)(param_1 + 0x20) + 0x40);
                        if (lVar40 != 0) {
                          for (plVar18 = *(long **)(lVar40 + 0x58); plVar18 != (long *)0x0;
                              plVar18 = (long *)*plVar18) {
                            if (*(uint *)(plVar18 + 3) <= uVar17) {
                              if (uVar17 <= *(uint *)(plVar18 + 3)) {
                                iVar28 = *(int *)((long)plVar18 + 0x1c);
                                goto LAB_71019e1cb0;
                              }
                              plVar18 = plVar18 + 1;
                            }
                          }
                        }
                        iVar28 = -1;
LAB_71019e1cb0:
                        uVar33 = -(local_250 >> 0x1f) & 0xfffffff000000000 | local_250 << 4;
                        piVar25 = (int *)(*(long *)(*(long *)(param_1 + 0x20) + 0x28) + uVar33);
                        *piVar25 = iVar11;
                        piVar25[1] = iVar8;
                        piVar25[2] = iVar15;
                        piVar25[3] = iVar28 + 1;
                        lVar40 = uVar33 + *(long *)(*(long *)(param_1 + 0x20) + 0x28);
                        *(int *)(lVar40 + 0x10) = iVar15;
                        *(int *)(lVar40 + 0x14) = iVar8;
                        *(int *)(lVar40 + 0x18) = iVar6;
                        *(int *)(lVar40 + 0x1c) = iVar28 + 1;
                        local_250 = (ulong)((int)local_250 + 2);
                      }
                    }
                    else if (uVar39 != 0) goto LAB_71019e1b54;
                  }
                }
              }
            }
          }
        }
        uVar44 = uVar44 + 1;
      } while (uVar44 != uVar43);
      uVar22 = uVar22 + 1;
    } while (uVar22 != uVar26);
    lVar40 = *(long *)(param_1 + 0x20);
    iVar15 = (int)local_250;
    if ((int)(*(uint *)(lVar40 + 0x34) & 0x7fffffff) < iVar15) {
      FUN_7101a0bf68((undefined8 *)(lVar40 + 0x28),DAT_7103a65fc8,local_250);
    }
  }
  if (*(int *)(lVar40 + 0x30) != iVar15) {
    *(int *)(lVar40 + 0x30) = iVar15;
  }
  plVar18 = DAT_7103a59d28;
  if (lVar29 == 0) {
    return iVar15;
  }
  piVar25 = (int *)(lVar29 + 0x164);
  do {
    while( true ) {
      iVar6 = *piVar25;
      iVar11 = iVar6 + -1;
      if (iVar11 == 0) break;
      while (iVar6 == *piVar25) {
        cVar10 = '\x01';
        bVar14 = (bool)ExclusiveMonitorPass(piVar25,0x10);
        if (bVar14) {
          *piVar25 = iVar11;
          cVar10 = ExclusiveMonitorsStatus();
        }
        if (cVar10 == '\0') {
          return iVar15;
        }
      }
    }
    FUN_71028f1c50(*plVar18,lVar29);
    while (*piVar25 == 1) {
      cVar10 = '\x01';
      bVar14 = (bool)ExclusiveMonitorPass(piVar25,0x10);
      if (bVar14) {
        *piVar25 = 0;
        cVar10 = ExclusiveMonitorsStatus();
      }
      if (cVar10 == '\0') {
        return iVar15;
      }
    }
  } while( true );
}



void FUN_71019e1e10(void)

{
  char *pcVar1;
  char cVar2;
  long *plVar3;
  int iVar4;
  long lVar5;
  long lVar6;
  undefined8 *puVar7;
  long *plVar8;
  char cVar9;
  long lVar10;
  long lVar11;
  undefined8 *local_d8;
  long *plStack_d0;
  char *local_c8;
  char local_54 [4];
  long local_50;
  undefined8 uStack_48;
  long local_28;
  
  plVar3 = DAT_7103a5c098;
  local_28 = *(long *)(*DAT_7103a5c098 + 0x80);
  if (((local_28 != 0) && (*DAT_7103a59ec8 != 0)) &&
     (puVar7 = *(undefined8 **)(*DAT_7103a59ec8 + 0x58), puVar7 != (undefined8 *)0x0)) {
    if (((*DAT_7103a62bc8 & 1) == 0) && (iVar4 = thunk_EXT_FUN_02e95df0(DAT_7103a62bc8), iVar4 != 0)
       ) {
      *DAT_7103a62bc0 = DAT_7103a59e80 + 0x10;
      thunk_EXT_FUN_02e95df0(DAT_7103a62bc8);
    }
    lVar5 = (**(code **)*puVar7)(puVar7,DAT_7103a62bc0);
    if (lVar5 != 0) {
      local_54[0] = '\0';
      plStack_d0 = &local_28;
      local_d8 = &DAT_710398f1c0;
      local_c8 = local_54;
      iVar4 = *(int *)(lVar5 + 0x24);
      if (0 < iVar4) {
        lVar10 = 0;
        lVar11 = 0;
        lVar6 = DAT_7103a62f28 + 0x10;
        do {
          if (*(int *)(*(long *)(lVar5 + 0x18) + lVar10) != 0) {
            uStack_48 = *(undefined8 *)(*(long *)(lVar5 + 0x18) + lVar10 + 8);
            local_50 = lVar6;
            (*(code *)*local_d8)(&local_d8,&local_50);
            iVar4 = *(int *)(lVar5 + 0x24);
          }
          lVar11 = lVar11 + 1;
          lVar10 = lVar10 + 0x10;
        } while (lVar11 < iVar4);
      }
      (*(code *)local_d8[3])(&local_d8);
      cVar9 = '\x01';
      if (local_54[0] == '\0') {
        lVar5 = 0x115c0;
        plVar8 = (long *)(*(long *)(*plVar3 + 0x88) + 0xb5fb0);
        do {
          if ((*(int *)((long)plVar8 + 0x15c) != 0 && local_54[0] == '\0') &&
             (lVar6 = (**(code **)(*plVar8 + 0x18))(plVar8), *(int *)(lVar6 + 0x18) == 1)) {
            local_54[0] = '\x01';
          }
          plVar8 = plVar8 + 0x58;
          lVar5 = lVar5 + -0x2c0;
          cVar9 = local_54[0];
        } while (lVar5 != 0);
      }
      lVar6 = local_28;
      lVar5 = local_28 + 0x242d50;
      pcVar1 = (char *)(local_28 + 0x242d20);
      thunk_EXT_FUN_02e95df0(lVar5);
      lVar11 = *plVar3;
      if (((lVar11 != 0) && (*(int *)(lVar11 + 0x944) == 1)) &&
         (*(int *)(lVar6 + 0x242d24) != *(int *)(lVar11 + 0x948))) {
        cVar2 = *pcVar1;
        *(int *)(lVar6 + 0x242d24) = *(int *)(lVar11 + 0x948);
        *(char *)(lVar6 + 0x242d21) = cVar2;
      }
      thunk_EXT_FUN_02e95df0(lVar5);
      *pcVar1 = cVar9;
    }
  }
  return;
}



void FUN_71019e2040(void)

{
  undefined8 *puVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  bool bVar7;
  long lVar8;
  long lVar9;
  long *plVar10;
  ulong uVar11;
  int *piVar12;
  ulong uVar13;
  ulong uVar14;
  ulong uVar15;
  int *piVar16;
  long lVar17;
  undefined8 *puVar18;
  long lVar19;
  uint *puVar20;
  
  lVar17 = *(long *)(DAT_71040e86a0 + 0x80);
  if (lVar17 == 0) {
    return;
  }
  if (DAT_710407a3f8 == 0) {
    return;
  }
  lVar8 = FUN_7100c80ed0(DAT_710407a3f8);
  if (lVar8 == 0) {
    return;
  }
  if (*(char *)(lVar8 + 0x14) == '\0') {
    return;
  }
  uVar2 = *(uint *)(lVar17 + 0x242c18);
  if (uVar2 != 0) {
    lVar8 = FUN_71010fed90(DAT_710407a3f8);
    uVar3 = *(uint *)(lVar8 + 0x2c);
    if (uVar3 != 0) {
      uVar5 = 0;
      if (uVar3 != 0) {
        uVar5 = uVar2 / uVar3;
      }
      uVar5 = uVar2 - uVar5 * uVar3;
      uVar6 = uVar5;
      do {
        uVar4 = *(uint *)(*(long *)(lVar8 + 0x20) +
                         (-(ulong)(uVar6 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar6 << 4));
        if (uVar4 == uVar2 || uVar4 == 0) break;
        uVar4 = 0;
        if ((int)(uVar6 + 1) < (int)uVar3) {
          uVar4 = uVar6 + 1;
        }
        uVar6 = uVar4;
      } while (uVar4 != uVar5);
    }
    lVar8 = FUN_71010fed90(DAT_710407a3f8);
    for (plVar10 = *(long **)(lVar8 + 0x80); plVar10 != (long *)0x0; plVar10 = (long *)*plVar10) {
      if (*(uint *)(plVar10 + 3) <= uVar2) {
        if (uVar2 <= *(uint *)(plVar10 + 3)) {
          if (*(int *)(plVar10 + 8) != 0) {
            puVar18 = (undefined8 *)plVar10[9];
            puVar1 = puVar18 + *(int *)(plVar10 + 8);
            do {
              uVar2 = *(uint *)*puVar18;
              plVar10 = (long *)FUN_7101a720d0(*(long *)(DAT_71040e86a0 + 0x80) + 0x22a310);
              for (plVar10 = (long *)*plVar10; plVar10 != (long *)0x0; plVar10 = (long *)*plVar10) {
                if (*(uint *)(plVar10 + 3) <= uVar2) {
                  if (uVar2 <= *(uint *)(plVar10 + 3)) {
                    if (*(char *)(plVar10 + 9) == '\0') goto LAB_71019e23b8;
                    break;
                  }
                  plVar10 = plVar10 + 1;
                }
              }
              puVar18 = puVar18 + 1;
            } while (puVar18 != puVar1);
          }
          break;
        }
        plVar10 = plVar10 + 1;
      }
    }
  }
  lVar8 = FUN_7100c80ed0(DAT_710407a3f8);
  uVar11 = (ulong)*(uint *)(lVar8 + 0x2c);
  if (0 < (int)*(uint *)(lVar8 + 0x2c)) {
    piVar12 = *(int **)(lVar8 + 0x20);
    if (*piVar12 == 0) {
      uVar14 = 0;
      piVar16 = piVar12;
      do {
        piVar16 = piVar16 + 4;
        uVar15 = uVar11;
        uVar13 = uVar11 - 1;
        if (uVar11 - 1 == uVar14) break;
        uVar15 = uVar14 + 1;
        uVar14 = uVar15;
        uVar13 = uVar15;
      } while (*piVar16 == 0);
      if (uVar11 <= uVar15) {
        uVar13 = uVar11;
      }
      if (uVar13 != uVar11) goto LAB_71019e2334;
    }
    else {
      uVar13 = 0;
      if (uVar11 != 0) {
LAB_71019e2334:
        puVar20 = (uint *)(piVar12 + uVar13 * 4);
LAB_71019e2358:
        uVar2 = *puVar20;
        plVar10 = (long *)FUN_7101a720d0(lVar17 + 0x22a310);
        plVar10 = (long *)*plVar10;
joined_r0x0071019e2368:
        if (plVar10 == (long *)0x0) goto LAB_71019e23a0;
        if (uVar2 < *(uint *)(plVar10 + 3)) {
LAB_71019e2370:
          plVar10 = (long *)*plVar10;
          goto joined_r0x0071019e2368;
        }
        if (*(uint *)(plVar10 + 3) < uVar2) {
          plVar10 = plVar10 + 1;
          goto LAB_71019e2370;
        }
        if ((*(int *)(plVar10 + 7) == 0) || (*(char *)(plVar10 + 9) != '\0')) goto LAB_71019e23a0;
        if (uVar2 == 0) goto LAB_71019e2218;
LAB_71019e23b8:
        thunk_EXT_FUN_02e95df0(lVar17 + 0x242ca0);
        if (((DAT_71040e86a0 == 0) || (*(int *)(DAT_71040e86a0 + 0x944) != 1)) ||
           (*(int *)(lVar17 + 0x242c74) == *(int *)(DAT_71040e86a0 + 0x948))) {
          bVar7 = true;
        }
        else {
          *(int *)(lVar17 + 0x242c74) = *(int *)(DAT_71040e86a0 + 0x948);
          bVar7 = true;
          *(undefined1 *)(lVar17 + 0x242c71) = *(undefined1 *)(lVar17 + 0x242c70);
        }
        goto LAB_71019e22bc;
      }
    }
  }
LAB_71019e2218:
  lVar19 = 0x105f8;
  lVar8 = 0x11298;
  plVar10 = (long *)(*(long *)(DAT_71040e86a0 + 0x88) + 0x11a478);
  while ((*(int *)((long)plVar10 + 0x15c) == 0 ||
         (lVar9 = (**(code **)(*plVar10 + 0x18))(plVar10), *(int *)(lVar9 + 0x18) != 1))) {
    plVar10 = plVar10 + 0x57;
    lVar8 = lVar8 + -0x2b8;
    if (lVar8 == 0) {
      plVar10 = (long *)(*(long *)(DAT_71040e86a0 + 0x88) + 0xf9810);
      bVar7 = false;
      do {
        if (*(int *)((long)plVar10 + 0x15c) != 0 && !bVar7) {
          lVar8 = (**(code **)(*plVar10 + 0x18))(plVar10);
          bVar7 = *(int *)(lVar8 + 0x18) == 1;
        }
        plVar10 = plVar10 + 0x53;
        lVar19 = lVar19 + -0x298;
      } while (lVar19 != 0);
LAB_71019e2274:
      thunk_EXT_FUN_02e95df0(lVar17 + 0x242ca0);
      if (((DAT_71040e86a0 != 0) && (*(int *)(DAT_71040e86a0 + 0x944) == 1)) &&
         (*(int *)(lVar17 + 0x242c74) != *(int *)(DAT_71040e86a0 + 0x948))) {
        *(int *)(lVar17 + 0x242c74) = *(int *)(DAT_71040e86a0 + 0x948);
        *(undefined1 *)(lVar17 + 0x242c71) = *(undefined1 *)(lVar17 + 0x242c70);
      }
LAB_71019e22bc:
      thunk_EXT_FUN_02e95df0(lVar17 + 0x242ca0);
      *(bool *)(lVar17 + 0x242c70) = bVar7;
      return;
    }
  }
  bVar7 = true;
  goto LAB_71019e2274;
  while (puVar20 = puVar20 + 4, *puVar20 == 0) {
LAB_71019e23a0:
    if (piVar12 + uVar11 * 4 <= puVar20) break;
  }
  if (puVar20 == (uint *)(piVar12 + uVar11 * 4)) goto LAB_71019e2218;
  goto LAB_71019e2358;
}



undefined8 FUN_71019e2410(uint param_1)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  long lVar5;
  
  lVar5 = FUN_7100d258c0(*DAT_7103a59ec8);
  if ((param_1 != 0) && (uVar1 = *(uint *)(lVar5 + 0x2c), uVar1 != 0)) {
    uVar3 = 0;
    if (uVar1 != 0) {
      uVar3 = param_1 / uVar1;
    }
    uVar3 = param_1 - uVar3 * uVar1;
    uVar4 = uVar3;
    do {
      uVar2 = *(uint *)(*(long *)(lVar5 + 0x20) +
                       (-(ulong)(uVar4 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar4 << 4));
      if (uVar2 == param_1 || uVar2 == 0) {
        return 0;
      }
      uVar2 = 0;
      if ((int)(uVar4 + 1) < (int)uVar1) {
        uVar2 = uVar4 + 1;
      }
      uVar4 = uVar2;
    } while (uVar2 != uVar3);
  }
  return 0;
}



void FUN_71019e252c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071019e256c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



bool FUN_71019e2590(long *param_1,undefined8 *param_2,ulong param_3)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  long lVar4;
  byte *pbVar5;
  ulong uVar6;
  int iVar7;
  uint uVar8;
  long lVar9;
  ulong uVar10;
  char *pcVar11;
  
  *(undefined1 *)((long)(int)param_1[1] + *param_1 + -1) = 0;
  pcVar11 = (char *)*param_1;
  if ((pcVar11 == (char *)0x0) || (*pcVar11 == '\0')) {
    iVar7 = 0;
    pbVar5 = (byte *)*param_2;
joined_r0x0071019e25f8:
    if (pbVar5 != (byte *)0x0) goto LAB_71019e25fc;
LAB_71019e2650:
    uVar10 = 0;
  }
  else {
    lVar9 = 0;
    do {
      if (lVar9 == 0x400000) {
        lVar9 = 0;
        pbVar5 = (byte *)*param_2;
        goto joined_r0x0071019e263c;
      }
      if (pcVar11[lVar9 + 1] == '\0') {
        iVar7 = (int)lVar9 + 1;
        pbVar5 = (byte *)*param_2;
        goto joined_r0x0071019e25f8;
      }
      lVar4 = lVar9 + 2;
      lVar9 = lVar9 + 2;
    } while (pcVar11[lVar4] != '\0');
    pbVar5 = (byte *)*param_2;
joined_r0x0071019e263c:
    iVar7 = (int)lVar9;
    if (pbVar5 == (byte *)0x0) goto LAB_71019e2650;
LAB_71019e25fc:
    uVar10 = (ulong)*pbVar5;
    if (*pbVar5 != 0) {
      uVar10 = 0;
      do {
        if (uVar10 == 0x400000) goto LAB_71019e2650;
        if (pbVar5[uVar10 + 1] == 0) {
          uVar10 = uVar10 + 1;
          break;
        }
        lVar9 = uVar10 + 2;
        uVar10 = uVar10 + 2;
      } while (pbVar5[lVar9] != 0);
    }
  }
  iVar2 = (int)param_1[1];
  lVar9 = (long)iVar2 + -1;
  uVar3 = (int)lVar9 - iVar7;
  uVar6 = (ulong)uVar3;
  if (uVar3 != 0 && iVar7 <= (int)lVar9) {
    iVar7 = (int)uVar10 + iVar7;
    if (iVar7 < iVar2) {
      pcVar11[lVar9] = '\0';
      pbVar5 = (byte *)*param_1;
      if (pbVar5 == (byte *)0x0) {
LAB_71019e26f8:
        uVar10 = 0;
      }
      else {
        uVar10 = (ulong)*pbVar5;
        if (*pbVar5 != 0) {
          uVar10 = 0;
          do {
            if (uVar10 == 0x400000) goto LAB_71019e26f8;
            if (pbVar5[uVar10 + 1] == 0) {
              uVar10 = uVar10 + 1;
              break;
            }
            lVar9 = uVar10 + 2;
            uVar10 = uVar10 + 2;
          } while (pbVar5[lVar9] != 0);
        }
      }
      pbVar5 = (byte *)*param_2;
      uVar8 = (uint)uVar10 & ((int)(uint)uVar10 >> 0x1f ^ 0xffffffffU);
      if (pbVar5 == (byte *)0x0) {
LAB_71019e2784:
        uVar10 = 0;
      }
      else {
        uVar10 = (ulong)*pbVar5;
        if (*pbVar5 != 0) {
          uVar10 = 0;
          do {
            if (uVar10 == 0x400000) goto LAB_71019e2784;
            if (pbVar5[uVar10 + 1] == 0) {
              uVar10 = uVar10 + 1;
              break;
            }
            lVar9 = uVar10 + 2;
            uVar10 = uVar10 + 2;
          } while (pbVar5[lVar9] != 0);
        }
      }
      iVar1 = (int)uVar10;
      if ((int)((int)param_1[1] - uVar8) <= (int)uVar10) {
        iVar1 = (int)param_1[1] + ~uVar8;
      }
      if (iVar1 < 1) {
        return true;
      }
LAB_71019e27f8:
      thunk_EXT_FUN_02e95df0(pcVar11 + uVar8,pbVar5,iVar1);
      pcVar11[(int)(iVar1 + uVar8)] = '\0';
      return iVar7 < iVar2;
    }
    if ((param_3 & 1) != 0) {
      pcVar11[lVar9] = '\0';
      pbVar5 = (byte *)*param_1;
      if (pbVar5 == (byte *)0x0) {
LAB_71019e2700:
        uVar10 = 0;
      }
      else {
        uVar10 = (ulong)*pbVar5;
        if (*pbVar5 != 0) {
          uVar10 = 0;
          do {
            if (uVar10 == 0x400000) goto LAB_71019e2700;
            if (pbVar5[uVar10 + 1] == 0) {
              uVar8 = (int)uVar10 + 1;
              uVar8 = uVar8 & ((int)uVar8 >> 0x1f ^ 0xffffffffU);
              goto joined_r0x0071019e27c8;
            }
            lVar9 = uVar10 + 2;
            uVar10 = uVar10 + 2;
          } while (pbVar5[lVar9] != 0);
        }
      }
      uVar8 = (uint)uVar10 & ((int)(uint)uVar10 >> 0x1f ^ 0xffffffffU);
joined_r0x0071019e27c8:
      if ((int)uVar3 < 0) {
        pbVar5 = (byte *)*param_2;
        if (pbVar5 == (byte *)0x0) {
LAB_71019e27b8:
          uVar6 = 0;
        }
        else {
          uVar6 = (ulong)*pbVar5;
          if (*pbVar5 != 0) {
            uVar6 = 0;
            do {
              if (uVar6 == 0x400000) goto LAB_71019e27b8;
              if (pbVar5[uVar6 + 1] == 0) {
                uVar6 = uVar6 + 1;
                break;
              }
              lVar9 = uVar6 + 2;
              uVar6 = uVar6 + 2;
            } while (pbVar5[lVar9] != 0);
          }
        }
      }
      iVar1 = (int)uVar6;
      if ((int)((int)param_1[1] - uVar8) <= (int)uVar6) {
        iVar1 = (int)param_1[1] + ~uVar8;
      }
      if (0 < iVar1) {
        pbVar5 = (byte *)*param_2;
        goto LAB_71019e27f8;
      }
    }
  }
  return false;
}



// WARNING: Type propagation algorithm not settling

bool FUN_71019e2830(long *param_1,undefined8 *param_2,uint *param_3)

{
  int iVar1;
  char cVar2;
  int iVar3;
  uint uVar4;
  long lVar5;
  uint uVar6;
  ulong uVar7;
  ulong uVar8;
  short *psVar9;
  uint uVar10;
  int iVar11;
  long lVar12;
  ushort *puVar13;
  bool bVar14;
  short *psVar15;
  
  *(undefined2 *)(*param_1 + (long)(int)param_1[1] * 2 + -2) = 0;
  psVar15 = (short *)*param_1;
  if ((psVar15 == (short *)0x0) || (*psVar15 == 0)) {
    lVar12 = 0;
    cVar2 = (char)param_3[1];
joined_r0x0071019e297c:
    if (cVar2 != '\0') goto LAB_71019e288c;
LAB_71019e28a0:
    iVar11 = (int)lVar12;
    puVar13 = (ushort *)*param_2;
    if (puVar13 == (ushort *)0x0) {
LAB_71019e28d8:
      uVar7 = 0;
    }
    else {
      uVar7 = (ulong)*puVar13;
      if (*puVar13 != 0) {
        uVar7 = 0;
        do {
          if (uVar7 == 0x400000) goto LAB_71019e28d8;
          if (puVar13[uVar7 + 1] == 0) {
            uVar7 = uVar7 + 1;
            break;
          }
          lVar12 = uVar7 + 2;
          uVar7 = uVar7 + 2;
        } while (puVar13[lVar12] != 0);
      }
    }
  }
  else {
    lVar12 = 0;
    do {
      if (lVar12 == 0x400000) {
        lVar12 = 0;
        cVar2 = (char)param_3[1];
        goto joined_r0x0071019e297c;
      }
      if (psVar15[lVar12 + 1] == 0) {
        lVar12 = lVar12 + 1;
        cVar2 = (char)param_3[1];
        goto joined_r0x0071019e297c;
      }
      lVar5 = lVar12 + 2;
      lVar12 = lVar12 + 2;
    } while (psVar15[lVar5] != 0);
    if ((char)param_3[1] == '\0') goto LAB_71019e28a0;
LAB_71019e288c:
    iVar11 = (int)lVar12;
    uVar7 = (ulong)*param_3;
  }
  uVar6 = (uint)uVar7;
  iVar1 = (int)param_1[1];
  iVar3 = iVar1 + -1;
  uVar4 = iVar3 - iVar11;
  uVar7 = (ulong)uVar4;
  if (uVar4 == 0 || iVar3 < iVar11) {
LAB_71019e2adc:
    bVar14 = false;
  }
  else {
    bVar14 = (int)(uVar6 + iVar11) < iVar1;
    if ((int)(uVar6 + iVar11) < iVar1) {
      psVar15[iVar3] = 0;
      puVar13 = (ushort *)*param_1;
      if (puVar13 == (ushort *)0x0) {
        uVar10 = 0;
      }
      else {
        uVar7 = (ulong)*puVar13;
        if (*puVar13 != 0) {
          uVar7 = 0;
          do {
            if (uVar7 == 0x400000) {
              uVar7 = 0;
              break;
            }
            if (puVar13[uVar7 + 1] == 0) {
              uVar10 = (int)uVar7 + 1;
              uVar10 = uVar10 & ((int)uVar10 >> 0x1f ^ 0xffffffffU);
              goto joined_r0x0071019e299c;
            }
            lVar12 = uVar7 + 2;
            uVar7 = uVar7 + 2;
          } while (puVar13[lVar12] != 0);
        }
        uVar10 = (uint)uVar7 & ((int)(uint)uVar7 >> 0x1f ^ 0xffffffffU);
      }
joined_r0x0071019e299c:
      if ((int)uVar6 < 0) {
        psVar9 = (short *)*param_2;
        uVar6 = 0;
        if (psVar9 != (short *)0x0) {
          if (*psVar9 == 0) {
LAB_71019e2a84:
            uVar6 = 0;
          }
          else {
            lVar12 = 0;
            do {
              if (lVar12 == 0x400000) goto LAB_71019e2a84;
              if (psVar9[lVar12 + 1] == 0) {
                lVar12 = lVar12 + 1;
                break;
              }
              lVar5 = lVar12 + 2;
              lVar12 = lVar12 + 2;
            } while (psVar9[lVar5] != 0);
            uVar6 = (uint)lVar12;
          }
        }
      }
      if ((int)((int)param_1[1] - uVar10) <= (int)uVar6) {
        uVar6 = (int)param_1[1] + ~uVar10;
      }
      if ((int)uVar6 < 1) {
        return true;
      }
    }
    else {
      psVar15[iVar3] = 0;
      puVar13 = (ushort *)*param_1;
      if (puVar13 == (ushort *)0x0) {
        uVar10 = 0;
      }
      else {
        uVar8 = (ulong)*puVar13;
        if (*puVar13 != 0) {
          uVar8 = 0;
          do {
            if (uVar8 == 0x400000) {
              uVar8 = 0;
              break;
            }
            if (puVar13[uVar8 + 1] == 0) {
              uVar10 = (int)uVar8 + 1;
              uVar10 = uVar10 & ((int)uVar10 >> 0x1f ^ 0xffffffffU);
              goto joined_r0x0071019e2a94;
            }
            lVar12 = uVar8 + 2;
            uVar8 = uVar8 + 2;
          } while (puVar13[lVar12] != 0);
        }
        uVar10 = (uint)uVar8 & ((int)(uint)uVar8 >> 0x1f ^ 0xffffffffU);
      }
joined_r0x0071019e2a94:
      if ((int)uVar4 < 0) {
        puVar13 = (ushort *)*param_2;
        if (puVar13 == (ushort *)0x0) {
LAB_71019e2a34:
          uVar7 = 0;
        }
        else {
          uVar7 = (ulong)*puVar13;
          if (*puVar13 != 0) {
            uVar7 = 0;
            do {
              if (uVar7 == 0x400000) goto LAB_71019e2a34;
              if (puVar13[uVar7 + 1] == 0) {
                uVar7 = uVar7 + 1;
                break;
              }
              lVar12 = uVar7 + 2;
              uVar7 = uVar7 + 2;
            } while (puVar13[lVar12] != 0);
          }
        }
      }
      uVar6 = (uint)uVar7;
      if ((int)((int)param_1[1] - uVar10) <= (int)(uint)uVar7) {
        uVar6 = (int)param_1[1] + ~uVar10;
      }
      if ((int)uVar6 < 1) goto LAB_71019e2adc;
    }
    thunk_EXT_FUN_02e95df0(psVar15 + uVar10,*param_2,(ulong)uVar6 << 1);
    psVar15[(int)(uVar6 + uVar10)] = 0;
  }
  return bVar14;
}



void FUN_71019e2b00(int *param_1)

{
  int iVar1;
  int iVar2;
  long lVar3;
  int *piVar4;
  undefined8 *puVar5;
  uint uVar6;
  long lVar7;
  int iVar8;
  
  uVar6 = param_1[1];
  if (-1 < (int)uVar6) {
    if (*DAT_71040e7d48 <= uVar6) {
      uVar6 = 0;
    }
    if (((*(long *)(DAT_71040e7d48 + 2) != 0) &&
        (lVar3 = *(long *)(DAT_71040e7d48 + 2) + (ulong)uVar6 * 0x10,
        *(int *)(lVar3 + 4) == *param_1)) && (lVar3 = *(long *)(lVar3 + 8), lVar3 != 0)) {
      piVar4 = (int *)(lVar3 + 0x48);
      iVar2 = *piVar4;
      goto joined_r0x0071019e2b70;
    }
  }
  puVar5 = FUN_7100baff84();
  piVar4 = (int *)(puVar5 + 9);
  iVar2 = *piVar4;
joined_r0x0071019e2b70:
  if (((iVar2 != 0) && ((long)iVar2 + (long)piVar4 != 0)) &&
     (lVar3 = *(long *)((long)iVar2 + (long)piVar4 + 0x30), lVar3 != 0)) {
    FUN_7100f09f60(lVar3 + 0x4c08);
    lVar7 = *(long *)(lVar3 + 0x330);
    if (lVar7 != 0) {
      *(ulong *)(lVar7 + 0x10) = *(ulong *)(lVar7 + 0x10) | 0x8000;
    }
    iVar2 = *(int *)(lVar3 + 0x348);
    if (iVar2 != 0) {
      iVar8 = 0;
      do {
        iVar1 = 0;
        if (*(int *)(lVar3 + 0x340) <= iVar8 + *(int *)(lVar3 + 0x344)) {
          iVar1 = *(int *)(lVar3 + 0x340);
        }
        iVar1 = iVar8 + (*(int *)(lVar3 + 0x344) - iVar1);
        iVar8 = iVar8 + 1;
        lVar7 = *(long *)(*(long *)(lVar3 + 0x338) + (long)iVar1 * 8);
        *(ulong *)(lVar7 + 0x10) = *(ulong *)(lVar7 + 0x10) | 0x8000;
      } while (iVar2 != iVar8);
    }
  }
  return;
}



undefined8 FUN_71019e2d90(int *param_1)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  undefined8 *puVar5;
  long lVar6;
  ulong uVar7;
  
  uVar1 = param_1[1];
  if ((int)uVar1 < 0) {
    return 0;
  }
  lVar6 = *(long *)(DAT_71040e7d48 + 2);
  if (lVar6 != 0) {
    if (*DAT_71040e7d48 <= uVar1) {
      uVar1 = 0;
    }
    if (*(int *)(lVar6 + (ulong)uVar1 * 0x10 + 4) == *param_1) {
      puVar5 = *(undefined8 **)(lVar6 + (ulong)uVar1 * 0x10 + 8);
      if (puVar5 == (undefined8 *)0x0) {
        puVar5 = FUN_7100baff84();
      }
      lVar6 = (long)puVar5 + (long)*(int *)(puVar5 + 0x28) + 0x140;
      if ((*(int *)(puVar5 + 0x28) != 0 && lVar6 != 0) &&
         (uVar1 = *(uint *)(lVar6 + 0x28), uVar1 != 0)) {
        lVar6 = FUN_7100cb5110(DAT_710407a3f8);
        uVar2 = *(uint *)(lVar6 + 0x2c);
        uVar4 = 0;
        if (uVar2 != 0) {
          uVar4 = uVar1 / uVar2;
        }
        uVar4 = uVar1 - uVar4 * uVar2;
        uVar7 = (ulong)uVar4;
        lVar6 = *(long *)(lVar6 + 0x20);
        uVar3 = *(uint *)(lVar6 + (-(ulong)(uVar4 >> 0x1f) & 0xfffffff000000000 | uVar7 << 4));
        while (uVar3 != uVar1) {
          uVar4 = 0;
          if ((int)uVar7 + 1 < (int)uVar2) {
            uVar4 = (int)uVar7 + 1;
          }
          uVar7 = (ulong)uVar4;
          uVar3 = *(uint *)(lVar6 + (-(ulong)(uVar4 >> 0x1f) & 0xfffffff000000000 | uVar7 << 4));
        }
        if (*(char *)(*(long *)(lVar6 + (long)(int)uVar4 * 0x10 + 8) + 0x6c) != '\0') {
          return 1;
        }
      }
    }
  }
  return 0;
}



bool FUN_71019e2e90(int *param_1)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  long lVar6;
  uint uVar7;
  undefined8 *puVar8;
  
  uVar7 = param_1[1];
  if (-1 < (int)uVar7) {
    if (*DAT_71040e7d48 <= uVar7) {
      uVar7 = 0;
    }
    if (((*(long *)(DAT_71040e7d48 + 2) != 0) &&
        (lVar6 = *(long *)(DAT_71040e7d48 + 2) + (ulong)uVar7 * 0x10,
        *(int *)(lVar6 + 4) == *param_1)) &&
       (puVar8 = *(undefined8 **)(lVar6 + 8), puVar8 != (undefined8 *)0x0)) goto LAB_71019e2ef8;
  }
  puVar8 = FUN_7100baff84();
LAB_71019e2ef8:
  iVar3 = *(int *)(puVar8 + 0x10);
  if ((iVar3 != 0) && (lVar6 = (long)iVar3 + (long)(puVar8 + 0x10), lVar6 != 0)) {
    uVar7 = *(uint *)(lVar6 + 0x38);
    if (uVar7 == 0xb6eede09 || uVar7 == 0) {
      FUN_7100df0120(DAT_710407a3f8);
    }
    else {
      lVar6 = FUN_7100df0120(DAT_710407a3f8);
      uVar1 = *(uint *)(lVar6 + 0x2c);
      if (uVar1 != 0) {
        uVar4 = 0;
        if (uVar1 != 0) {
          uVar4 = uVar7 / uVar1;
        }
        uVar4 = uVar7 - uVar4 * uVar1;
        uVar5 = uVar4;
        do {
          uVar2 = *(uint *)(*(long *)(lVar6 + 0x20) +
                           (-(ulong)(uVar5 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar5 << 4));
          if (uVar2 == uVar7) {
            lVar6 = *(long *)(*(long *)(lVar6 + 0x20) + (long)(int)uVar5 * 0x10 + 8);
            if (lVar6 == 0) {
              return false;
            }
            return *(char *)(lVar6 + 0x13b) == '\0';
          }
          if (uVar2 == 0) {
            return false;
          }
          uVar2 = 0;
          if ((int)(uVar5 + 1) < (int)uVar1) {
            uVar2 = uVar5 + 1;
          }
          uVar5 = uVar2;
        } while (uVar2 != uVar4);
      }
    }
  }
  return false;
}



uint FUN_71019e3100(void)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  long *plVar5;
  uint uVar6;
  long lVar7;
  ulong uVar8;
  int *piVar9;
  ulong uVar10;
  ulong uVar11;
  ulong uVar12;
  int *piVar13;
  uint uVar14;
  uint *puVar15;
  uint uVar16;
  uint uVar17;
  uint uVar18;
  float fVar19;
  float fVar20;
  float fVar21;
  
  thunk_EXT_FUN_02e95df0();
  uVar6 = thunk_EXT_FUN_02e95df0();
  plVar5 = DAT_7103a59ec8;
  lVar7 = FUN_71018001e0(*DAT_7103a59ec8);
  uVar8 = (ulong)*(uint *)(lVar7 + 0x2c);
  if (0 < (int)*(uint *)(lVar7 + 0x2c)) {
    piVar9 = *(int **)(lVar7 + 0x20);
    if (*piVar9 == 0) {
      uVar12 = 0;
      piVar13 = piVar9;
      do {
        piVar13 = piVar13 + 4;
        uVar11 = uVar8;
        uVar10 = uVar8 - 1;
        if (uVar8 - 1 == uVar12) break;
        uVar11 = uVar12 + 1;
        uVar12 = uVar11;
        uVar10 = uVar11;
      } while (*piVar13 == 0);
      if (uVar8 <= uVar11) {
        uVar10 = uVar8;
      }
      if (uVar10 != uVar8) goto LAB_71019e31dc;
    }
    else {
      uVar10 = 0;
      if (uVar8 != 0) {
LAB_71019e31dc:
        uVar6 = (uVar6 ^ uVar6 >> 0x1e) * 0x6c078965 + 1;
        fVar21 = 0.0;
        puVar15 = (uint *)(piVar9 + uVar10 * 4);
        uVar14 = 0;
        uVar16 = (uVar6 ^ uVar6 >> 0x1e) * 0x6c078965 + 2;
        uVar17 = (uVar16 ^ uVar16 >> 0x1e) * 0x6c078965 + 3;
        uVar18 = (uVar17 ^ uVar17 >> 0x1e) * 0x6c078965 + 4;
        do {
          uVar1 = *puVar15;
          lVar7 = FUN_71018001e0(*plVar5);
          uVar2 = *(uint *)(lVar7 + 0x2c);
          uVar4 = 0;
          if (uVar2 != 0) {
            uVar4 = uVar1 / uVar2;
          }
          uVar4 = uVar1 - uVar4 * uVar2;
          uVar12 = (ulong)uVar4;
          lVar7 = *(long *)(lVar7 + 0x20);
          uVar3 = *(uint *)(lVar7 + (-(ulong)(uVar4 >> 0x1f) & 0xfffffff000000000 | uVar12 << 4));
          while (uVar3 != uVar1) {
            uVar4 = 0;
            if ((int)uVar12 + 1 < (int)uVar2) {
              uVar4 = (int)uVar12 + 1;
            }
            uVar12 = (ulong)uVar4;
            uVar3 = *(uint *)(lVar7 + (-(ulong)(uVar4 >> 0x1f) & 0xfffffff000000000 | uVar12 << 4));
          }
          fVar19 = (float)*(int *)(*(long *)(lVar7 + (long)(int)uVar4 * 0x10 + 8) + 0x10);
          fVar21 = fVar21 + fVar19;
          if (ABS(fVar21) != INFINITY) {
            if (fVar21 < 0.0) {
              fVar20 = 0.0;
              uVar2 = uVar18;
              uVar18 = uVar17;
            }
            else {
              uVar6 = uVar6 ^ uVar6 << 0xb;
              uVar2 = uVar18 >> 0x13 ^ uVar6 >> 8 ^ uVar18 ^ uVar6;
              fVar20 = ((float)(uVar2 >> 9 | 0x3f800000) + -1.0) * fVar21 + 0.0;
              uVar6 = uVar16;
              uVar16 = uVar17;
            }
            uVar17 = uVar18;
            uVar18 = uVar2;
            if (fVar20 < fVar19) {
              uVar14 = uVar1;
            }
          }
          do {
            if (piVar9 + uVar8 * 4 <= puVar15) break;
            puVar15 = puVar15 + 4;
          } while (*puVar15 == 0);
          if (puVar15 == (uint *)(piVar9 + uVar8 * 4)) {
            return uVar14;
          }
        } while( true );
      }
    }
  }
  return 0;
}



// WARNING: Type propagation algorithm not settling

uint FUN_71019e3340(uint param_1)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  byte bVar4;
  uint uVar5;
  uint uVar6;
  long *plVar7;
  uint uVar8;
  uint uVar9;
  ulong uVar10;
  undefined1 *puVar11;
  int *piVar12;
  ulong uVar13;
  ulong uVar14;
  uint uVar15;
  uint uVar16;
  uint uVar17;
  ulong uVar18;
  int *piVar19;
  long lVar20;
  uint uVar21;
  uint uVar22;
  uint uVar23;
  uint *puVar24;
  float fVar25;
  float fVar26;
  undefined1 auVar27 [16];
  undefined8 uStack_90;
  undefined4 uStack_88;
  byte bStack_84;
  uint local_74;
  
  if (*DAT_7103a5d850 == 0) {
    uVar17 = 4;
    uVar16 = 4;
    uVar15 = 4;
  }
  else {
    bVar4 = *(byte *)(*DAT_7103a5d850 + 0x4172a0);
    if (((bVar4 >> 1 & 1) == 0) && (*DAT_7103a5c098 != 0)) {
      lVar20 = 0;
      if (DAT_71040e5cd8 != 0) {
        lVar20 = *(long *)(DAT_71040e5cd8 + 0xf0);
      }
      uVar18 = lVar20 - *(long *)(*(long *)(*DAT_7103a5c098 + 0x80) + 0x243558);
      if ((long)uVar18 < 0x15180) {
        uVar16 = 0;
      }
      else {
        uVar18 = uVar18 >> 7;
        if (uVar18 < 0x7e9) {
          uVar16 = 1;
        }
        else {
          uVar16 = 2;
          if (0xd2e < uVar18) {
            uVar16 = 3;
          }
        }
      }
    }
    else {
      uVar16 = 4;
    }
    if (((bVar4 & 1) == 0) && (*DAT_7103a5c098 != 0)) {
      lVar20 = 0;
      if (DAT_71040e5cd8 != 0) {
        lVar20 = *(long *)(DAT_71040e5cd8 + 0xf0);
      }
      uVar18 = lVar20 - *(long *)(*(long *)(*DAT_7103a5c098 + 0x80) + 0x243558);
      if ((long)uVar18 < 0x15180) {
        uVar17 = 0;
      }
      else {
        uVar18 = uVar18 >> 7;
        if (uVar18 < 0x7e9) {
          uVar17 = 1;
        }
        else {
          uVar17 = 2;
          if (0xd2e < uVar18) {
            uVar17 = 3;
          }
        }
      }
    }
    else {
      uVar17 = 4;
    }
    if ((((bVar4 ^ 0xff) & 3) == 0) || (*DAT_7103a5c098 == 0)) {
      uVar15 = 4;
    }
    else {
      lVar20 = 0;
      if (DAT_71040e5cd8 != 0) {
        lVar20 = *(long *)(DAT_71040e5cd8 + 0xf0);
      }
      uVar18 = lVar20 - *(long *)(*(long *)(*DAT_7103a5c098 + 0x80) + 0x243558);
      uVar10 = uVar18 >> 7;
      uVar15 = 2;
      if (0xd2e < uVar10) {
        uVar15 = 3;
      }
      uVar8 = 1;
      if (0x7e8 < uVar10) {
        uVar8 = uVar15;
      }
      uVar15 = 0;
      if (0x1517f < (long)uVar18) {
        uVar15 = uVar8;
      }
    }
  }
  thunk_EXT_FUN_02e95df0();
  uVar8 = thunk_EXT_FUN_02e95df0();
  plVar7 = DAT_7103a59ec8;
  lVar20 = FUN_7100df0120(*DAT_7103a59ec8);
  uVar18 = (ulong)*(uint *)(lVar20 + 0x2c);
  if (0 < (int)*(uint *)(lVar20 + 0x2c)) {
    piVar12 = *(int **)(lVar20 + 0x20);
    if (*piVar12 == 0) {
      uVar10 = 0;
      piVar19 = piVar12;
      do {
        piVar19 = piVar19 + 4;
        uVar14 = uVar18;
        uVar13 = uVar18 - 1;
        if (uVar18 - 1 == uVar10) break;
        uVar14 = uVar10 + 1;
        uVar10 = uVar14;
        uVar13 = uVar14;
      } while (*piVar19 == 0);
      if (uVar18 <= uVar14) {
        uVar13 = uVar18;
      }
      if (uVar13 != uVar18) goto LAB_71019e3580;
    }
    else {
      uVar13 = 0;
      if (uVar18 != 0) {
LAB_71019e3580:
        uVar8 = (uVar8 ^ uVar8 >> 0x1e) * 0x6c078965 + 1;
        puVar24 = (uint *)(piVar12 + uVar13 * 4);
        fVar26 = 0.0;
        local_74 = 0;
        uVar21 = (uVar8 ^ uVar8 >> 0x1e) * 0x6c078965 + 2;
        uVar22 = (uVar21 ^ uVar21 >> 0x1e) * 0x6c078965 + 3;
        uVar23 = (uVar22 ^ uVar22 >> 0x1e) * 0x6c078965 + 4;
        do {
          uVar1 = *puVar24;
          lVar20 = FUN_7100df0120(*plVar7);
          if ((uVar1 != 0) && (uVar9 = *(uint *)(lVar20 + 0x2c), uVar9 != 0)) {
            uVar5 = 0;
            if (uVar9 != 0) {
              uVar5 = uVar1 / uVar9;
            }
            uVar5 = uVar1 - uVar5 * uVar9;
            uVar6 = uVar5;
            do {
              uVar3 = *(uint *)(*(long *)(lVar20 + 0x20) +
                               (-(ulong)(uVar6 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar6 << 4));
              if (uVar3 == uVar1) {
                lVar20 = *(long *)(*(long *)(lVar20 + 0x20) + (long)(int)uVar6 * 0x10 + 8);
                goto LAB_71019e3644;
              }
              if (uVar3 == 0) break;
              uVar3 = 0;
              if ((int)(uVar6 + 1) < (int)uVar9) {
                uVar3 = uVar6 + 1;
              }
              uVar6 = uVar3;
            } while (uVar3 != uVar5);
          }
          lVar20 = 0;
LAB_71019e3644:
          uVar9 = FUN_7100bb2120(*(byte **)(lVar20 + 0x28),0);
          if (uVar9 == param_1) {
            iVar2 = *(int *)(lVar20 + 0xd0);
            uVar10 = (ulong)*(uint *)(lVar20 + 0x108);
            if (iVar2 == 2) {
              if (uVar15 != 4) {
                bVar4 = *(byte *)(lVar20 + 0x24);
                if (((bVar4 != 0xc1) && (bVar4 != 0xc4)) && ((bVar4 & 0xef) != 0x20))
                goto LAB_71019e38e0;
                uStack_88 = (undefined4)((ulong)*(undefined8 *)(lVar20 + 0x1d) >> 0x18);
                bStack_84 = (byte)((ulong)*(undefined8 *)(lVar20 + 0x1d) >> 0x38);
                uStack_90._0_5_ = (undefined5)*(undefined8 *)(lVar20 + 0x18);
                uStack_90._5_3_ = (undefined3)((ulong)*(undefined8 *)(lVar20 + 0x18) >> 0x28);
                uVar9 = uVar15;
                if ((bStack_84 == 0xc4) || (bStack_84 == 0xc1)) {
                  puVar11 = &DAT_71030e70e0;
                  if (uVar15 < 4) {
                    puVar11 = *(undefined1 **)(DAT_7103a5c0e0 + (ulong)uVar15 * 8 + 0x20);
                  }
                  auVar27 = FUN_7102813520(&uStack_90,puVar11);
                  uVar10 = auVar27._8_8_;
joined_r0x0071019e37e8:
                  if ((uVar10 & 0xff00000000) == 0xd100000000) goto LAB_71019e38e4;
                }
joined_r0x0071019e37f8:
                if ((bStack_84 & 0xef) != 0x20) goto LAB_71019e38e0;
                if (uVar9 < 4) {
LAB_71019e3808:
                  uVar9 = (&DAT_71032aa51c)[uVar9];
                }
                else {
LAB_71019e38c0:
                  uVar9 = 0;
                }
                auVar27 = FUN_71028136c0(&uStack_90,uVar9);
                uVar9 = auVar27._8_4_;
                if ((auVar27._8_8_ & 0xff00000000) != 0xd100000000) {
                  uVar9 = 0;
                }
                uVar10 = (ulong)uVar9;
              }
            }
            else if (iVar2 == 1) {
              if (uVar17 != 4) {
                bVar4 = *(byte *)(lVar20 + 0x24);
                if (((bVar4 == 0xc1) || (bVar4 == 0xc4)) || ((bVar4 & 0xef) == 0x20)) {
                  uStack_88 = (undefined4)((ulong)*(undefined8 *)(lVar20 + 0x1d) >> 0x18);
                  bStack_84 = (byte)((ulong)*(undefined8 *)(lVar20 + 0x1d) >> 0x38);
                  uStack_90._0_5_ = (undefined5)*(undefined8 *)(lVar20 + 0x18);
                  uStack_90._5_3_ = (undefined3)((ulong)*(undefined8 *)(lVar20 + 0x18) >> 0x28);
                  uVar9 = uVar17;
                  if ((bStack_84 == 0xc4) || (bStack_84 == 0xc1)) {
                    puVar11 = &DAT_71030e70e0;
                    if (uVar17 < 4) {
                      puVar11 = *(undefined1 **)(DAT_7103a5c0e0 + (ulong)uVar17 * 8 + 0x20);
                    }
                    auVar27 = FUN_7102813520(&uStack_90,puVar11);
                    uVar10 = auVar27._8_8_;
                    goto joined_r0x0071019e37e8;
                  }
                  goto joined_r0x0071019e37f8;
                }
                goto LAB_71019e38e0;
              }
            }
            else if ((iVar2 == 0) && (uVar16 != 4)) {
              bVar4 = *(byte *)(lVar20 + 0x24);
              if ((bVar4 == 0xc1) || ((bVar4 == 0xc4 || ((bVar4 & 0xef) == 0x20)))) {
                uStack_88 = (undefined4)((ulong)*(undefined8 *)(lVar20 + 0x1d) >> 0x18);
                bStack_84 = (byte)((ulong)*(undefined8 *)(lVar20 + 0x1d) >> 0x38);
                uStack_90._0_5_ = (undefined5)*(undefined8 *)(lVar20 + 0x18);
                uStack_90._5_3_ = (undefined3)((ulong)*(undefined8 *)(lVar20 + 0x18) >> 0x28);
                if ((bStack_84 == 0xc4) || (bStack_84 == 0xc1)) {
                  puVar11 = &DAT_71030e70e0;
                  if (uVar16 < 4) {
                    puVar11 = *(undefined1 **)(DAT_7103a5c0e0 + (ulong)uVar16 * 8 + 0x20);
                  }
                  auVar27 = FUN_7102813520(&uStack_90,puVar11);
                  uVar10 = auVar27._8_8_;
                  if ((uVar10 & 0xff00000000) == 0xd100000000) goto LAB_71019e38e4;
                }
                if ((bStack_84 & 0xef) == 0x20) {
                  uVar9 = uVar16;
                  if (3 < uVar16) goto LAB_71019e38c0;
                  goto LAB_71019e3808;
                }
              }
LAB_71019e38e0:
              uVar10 = 0;
            }
LAB_71019e38e4:
            fVar26 = fVar26 + (float)(int)uVar10;
            if (ABS(fVar26) != INFINITY) {
              if (fVar26 < 0.0) {
                fVar25 = 0.0;
                uVar9 = uVar23;
                uVar23 = uVar22;
              }
              else {
                uVar8 = uVar8 ^ uVar8 << 0xb;
                uVar9 = uVar23 >> 0x13 ^ uVar8 >> 8 ^ uVar23 ^ uVar8;
                fVar25 = ((float)(uVar9 >> 9 | 0x3f800000) + -1.0) * fVar26 + 0.0;
                uVar8 = uVar21;
                uVar21 = uVar22;
              }
              uVar22 = uVar23;
              uVar23 = uVar9;
              if (fVar25 < (float)(int)uVar10) {
                local_74 = uVar1;
              }
            }
          }
          do {
            if (piVar12 + uVar18 * 4 <= puVar24) break;
            puVar24 = puVar24 + 4;
          } while (*puVar24 == 0);
          if (puVar24 == (uint *)(piVar12 + uVar18 * 4)) {
            return local_74;
          }
        } while( true );
      }
    }
  }
  return 0;
}



undefined8 FUN_71019e39a0(int *param_1,uint param_2)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  long *plVar4;
  bool bVar5;
  int iVar6;
  long lVar7;
  undefined8 *puVar8;
  uint uVar9;
  ulong uVar10;
  long *plVar11;
  
  plVar4 = DAT_7103a59ec8;
  lVar7 = FUN_7100df0120(*DAT_7103a59ec8);
  if ((param_2 != 0) && (uVar9 = *(uint *)(lVar7 + 0x2c), uVar9 != 0)) {
    uVar2 = 0;
    if (uVar9 != 0) {
      uVar2 = param_2 / uVar9;
    }
    uVar2 = param_2 - uVar2 * uVar9;
    uVar3 = uVar2;
    do {
      uVar1 = *(uint *)(*(long *)(lVar7 + 0x20) +
                       (-(ulong)(uVar3 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar3 << 4));
      if (uVar1 == param_2 || uVar1 == 0) break;
      uVar1 = 0;
      if ((int)(uVar3 + 1) < (int)uVar9) {
        uVar1 = uVar3 + 1;
      }
      uVar3 = uVar1;
    } while (uVar1 != uVar2);
  }
  puVar8 = *(undefined8 **)(*plVar4 + 0x70);
  lVar7 = 0;
  if (puVar8 != (undefined8 *)0x0) {
    if (((*DAT_7103a5d838 & 1) == 0) && (iVar6 = thunk_EXT_FUN_02e95df0(DAT_7103a5d838), iVar6 != 0)
       ) {
      *DAT_7103a5d830 = DAT_7103a59e80 + 0x10;
      thunk_EXT_FUN_02e95df0(DAT_7103a5d838);
    }
    lVar7 = (**(code **)*puVar8)(puVar8,DAT_7103a5d830);
  }
  if ((param_2 != 0) && (uVar9 = *(uint *)(lVar7 + 0xa4), uVar9 != 0)) {
    uVar2 = 0;
    if (uVar9 != 0) {
      uVar2 = param_2 / uVar9;
    }
    uVar2 = param_2 - uVar2 * uVar9;
    uVar3 = uVar2;
    do {
      uVar1 = *(uint *)(*(long *)(lVar7 + 0x98) +
                       (-(ulong)(uVar3 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar3 << 4));
      if (uVar1 == param_2) {
        plVar11 = *(long **)(*(long *)(lVar7 + 0x98) + (long)(int)uVar3 * 0x10 + 8);
        if (plVar11 == (long *)0x0) {
          return 0;
        }
        uVar9 = param_1[1];
        if (-1 < (int)uVar9) {
          lVar7 = *(long *)((uint *)*DAT_7103a59c40 + 2);
          if (*(uint *)*DAT_7103a59c40 <= uVar9) {
            uVar9 = 0;
          }
          if (((lVar7 != 0) &&
              (lVar7 = lVar7 + (ulong)uVar9 * 0x10, *(int *)(lVar7 + 4) == *param_1)) &&
             (puVar8 = *(undefined8 **)(lVar7 + 8), puVar8 != (undefined8 *)0x0))
          goto LAB_71019e3af4;
        }
        puVar8 = FUN_7100baff84();
LAB_71019e3af4:
        iVar6 = *(int *)(puVar8 + 0x10);
        if ((iVar6 == 0) ||
           (puVar8 = (undefined8 *)((long)iVar6 + (long)(puVar8 + 0x10)),
           puVar8 == (undefined8 *)0x0)) {
          puVar8 = FUN_7100bb5984();
        }
        uVar9 = *(uint *)(plVar11 + 1);
        lVar7 = FUN_7100df0120(*plVar4);
        uVar2 = *(uint *)(lVar7 + 0x2c);
        uVar3 = 0;
        if (uVar2 != 0) {
          uVar3 = uVar9 / uVar2;
        }
        uVar3 = uVar9 - uVar3 * uVar2;
        uVar10 = (ulong)uVar3;
        lVar7 = *(long *)(lVar7 + 0x20);
        uVar1 = *(uint *)(lVar7 + (-(ulong)(uVar3 >> 0x1f) & 0xfffffff000000000 | uVar10 << 4));
        while (uVar1 != uVar9) {
          uVar3 = 0;
          if ((int)uVar10 + 1 < (int)uVar2) {
            uVar3 = (int)uVar10 + 1;
          }
          uVar10 = (ulong)uVar3;
          uVar1 = *(uint *)(lVar7 + (-(ulong)(uVar3 >> 0x1f) & 0xfffffff000000000 | uVar10 << 4));
        }
        lVar7 = *(long *)(lVar7 + (long)(int)uVar3 * 0x10 + 8);
        if (*(int *)(lVar7 + 0x108) == 0) {
          return 0;
        }
        if (((*DAT_7103a59d08 != 0) && (uVar9 = *(uint *)(lVar7 + 0xf4), uVar9 != 0)) &&
           (bVar5 = FUN_710193a3f0(*DAT_7103a59d08,uVar9), !bVar5)) {
          return 0;
        }
        uVar10 = (**(code **)(*plVar11 + 0x20))(plVar11,puVar8 + 5);
        if ((uVar10 & 1) == 0) {
          return 0;
        }
        return 1;
      }
      if (uVar1 == 0) {
        return 0;
      }
      uVar1 = 0;
      if ((int)(uVar3 + 1) < (int)uVar9) {
        uVar1 = uVar3 + 1;
      }
      uVar3 = uVar1;
    } while (uVar1 != uVar2);
  }
  return 0;
}



undefined8 FUN_71019e4490(int *param_1)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  long lVar6;
  uint uVar7;
  undefined8 *puVar8;
  
  uVar7 = param_1[1];
  if (-1 < (int)uVar7) {
    if (*DAT_71040e7d48 <= uVar7) {
      uVar7 = 0;
    }
    if (((*(long *)(DAT_71040e7d48 + 2) != 0) &&
        (lVar6 = *(long *)(DAT_71040e7d48 + 2) + (ulong)uVar7 * 0x10,
        *(int *)(lVar6 + 4) == *param_1)) &&
       (puVar8 = *(undefined8 **)(lVar6 + 8), puVar8 != (undefined8 *)0x0)) goto LAB_71019e44f8;
  }
  puVar8 = FUN_7100baff84();
LAB_71019e44f8:
  iVar3 = *(int *)(puVar8 + 0x10);
  if ((iVar3 != 0) && (lVar6 = (long)iVar3 + (long)(puVar8 + 0x10), lVar6 != 0)) {
    uVar7 = *(uint *)(lVar6 + 0x38);
    if (uVar7 == 0xb6eede09 || uVar7 == 0) {
      FUN_7100df0120(DAT_710407a3f8);
    }
    else {
      lVar6 = FUN_7100df0120(DAT_710407a3f8);
      uVar1 = *(uint *)(lVar6 + 0x2c);
      if (uVar1 != 0) {
        uVar4 = 0;
        if (uVar1 != 0) {
          uVar4 = uVar7 / uVar1;
        }
        uVar4 = uVar7 - uVar4 * uVar1;
        uVar5 = uVar4;
        do {
          uVar2 = *(uint *)(*(long *)(lVar6 + 0x20) +
                           (-(ulong)(uVar5 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar5 << 4));
          if (uVar2 == uVar7) {
            lVar6 = *(long *)(*(long *)(lVar6 + 0x20) + (long)(int)uVar5 * 0x10 + 8);
            if (lVar6 == 0) {
              return 0;
            }
            if (*(int *)(lVar6 + 0x100) == 0) {
              return 0;
            }
            if (*(char *)(lVar6 + 0x140) == '\0') {
              return 0;
            }
            return 1;
          }
          if (uVar2 == 0) {
            return 0;
          }
          uVar2 = 0;
          if ((int)(uVar5 + 1) < (int)uVar1) {
            uVar2 = uVar5 + 1;
          }
          uVar5 = uVar2;
        } while (uVar2 != uVar4);
      }
    }
  }
  return 0;
}



undefined8 FUN_71019e45c0(int *param_1,int *param_2)

{
  long lVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  long lVar7;
  uint uVar8;
  undefined8 *puVar9;
  
  uVar8 = param_1[1];
  if (-1 < (int)uVar8) {
    if (*DAT_71040e7d48 <= uVar8) {
      uVar8 = 0;
    }
    if (((*(long *)(DAT_71040e7d48 + 2) != 0) &&
        (lVar1 = *(long *)(DAT_71040e7d48 + 2) + (ulong)uVar8 * 0x10,
        *(int *)(lVar1 + 4) == *param_1)) &&
       (puVar9 = *(undefined8 **)(lVar1 + 8), puVar9 != (undefined8 *)0x0)) goto LAB_71019e4630;
  }
  puVar9 = FUN_7100baff84();
LAB_71019e4630:
  iVar4 = *(int *)(puVar9 + 0x10);
  if ((iVar4 != 0) && (lVar1 = (long)iVar4 + (long)(puVar9 + 0x10), lVar1 != 0)) {
    uVar8 = *(uint *)(lVar1 + 0x38);
    if (uVar8 == 0xb6eede09 || uVar8 == 0) {
      FUN_7100df0120(DAT_710407a3f8);
    }
    else {
      lVar7 = FUN_7100df0120(DAT_710407a3f8);
      uVar2 = *(uint *)(lVar7 + 0x2c);
      if (uVar2 != 0) {
        uVar5 = 0;
        if (uVar2 != 0) {
          uVar5 = uVar8 / uVar2;
        }
        uVar5 = uVar8 - uVar5 * uVar2;
        uVar6 = uVar5;
        do {
          uVar3 = *(uint *)(*(long *)(lVar7 + 0x20) +
                           (-(ulong)(uVar6 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar6 << 4));
          if (uVar3 == uVar8) {
            if (uVar8 != 0xf445d631) {
              return 0;
            }
            if (*(long *)(*(long *)(lVar7 + 0x20) + (long)(int)uVar6 * 0x10 + 8) == 0) {
              return 0;
            }
            if (*(int *)(lVar1 + 0x3c) != *param_2) {
              return 0;
            }
            return 1;
          }
          if (uVar3 == 0) {
            return 0;
          }
          uVar3 = 0;
          if ((int)(uVar6 + 1) < (int)uVar2) {
            uVar3 = uVar6 + 1;
          }
          uVar6 = uVar3;
        } while (uVar3 != uVar5);
      }
    }
  }
  return 0;
}



bool FUN_71019e4710(int *param_1)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  long lVar6;
  uint uVar7;
  undefined8 *puVar8;
  
  uVar7 = param_1[1];
  if (-1 < (int)uVar7) {
    if (*DAT_71040e7d48 <= uVar7) {
      uVar7 = 0;
    }
    if (((*(long *)(DAT_71040e7d48 + 2) != 0) &&
        (lVar6 = *(long *)(DAT_71040e7d48 + 2) + (ulong)uVar7 * 0x10,
        *(int *)(lVar6 + 4) == *param_1)) &&
       (puVar8 = *(undefined8 **)(lVar6 + 8), puVar8 != (undefined8 *)0x0)) goto LAB_71019e4778;
  }
  puVar8 = FUN_7100baff84();
LAB_71019e4778:
  iVar3 = *(int *)(puVar8 + 0x10);
  if ((iVar3 != 0) && (lVar6 = (long)iVar3 + (long)(puVar8 + 0x10), lVar6 != 0)) {
    uVar7 = *(uint *)(lVar6 + 0x38);
    if (uVar7 == 0xb6eede09 || uVar7 == 0) {
      FUN_7100df0120(DAT_710407a3f8);
    }
    else {
      lVar6 = FUN_7100df0120(DAT_710407a3f8);
      uVar1 = *(uint *)(lVar6 + 0x2c);
      if (uVar1 != 0) {
        uVar4 = 0;
        if (uVar1 != 0) {
          uVar4 = uVar7 / uVar1;
        }
        uVar4 = uVar7 - uVar4 * uVar1;
        uVar5 = uVar4;
        do {
          uVar2 = *(uint *)(*(long *)(lVar6 + 0x20) +
                           (-(ulong)(uVar5 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar5 << 4));
          if (uVar2 == uVar7) {
            if (*(long *)(*(long *)(lVar6 + 0x20) + (long)(int)uVar5 * 0x10 + 8) == 0) {
              return false;
            }
            return uVar7 == 0xb24335f4 || uVar7 == 0xfe59f825;
          }
          if (uVar2 == 0) {
            return false;
          }
          uVar2 = 0;
          if ((int)(uVar5 + 1) < (int)uVar1) {
            uVar2 = uVar5 + 1;
          }
          uVar5 = uVar2;
        } while (uVar2 != uVar4);
      }
    }
  }
  return false;
}



void FUN_71019e78a4(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071019e78e4. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



void FUN_71019e7ae0(int *param_1)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  int *piVar4;
  long lVar5;
  uint uVar6;
  uint uVar7;
  int iVar8;
  long lVar9;
  float fVar10;
  
  lVar9 = *(long *)(DAT_71040e86a0 + 0x88);
  thunk_EXT_FUN_02e95df0();
  iVar8 = DAT_7104010530;
  uVar2 = thunk_EXT_FUN_02e95df0();
  uVar2 = (uVar2 ^ uVar2 >> 0x1e) * 0x6c078965 + 1;
  fVar10 = 0.0;
  uVar3 = (uVar2 ^ uVar2 >> 0x1e) * 0x6c078965 + 2;
  uVar7 = (uVar3 ^ uVar3 >> 0x1e) * 0x6c078965 + 3;
  uVar6 = (uVar7 ^ uVar7 >> 0x1e) * 0x6c078965 + 4;
  lVar5 = 0x17798;
  piVar4 = (int *)(lVar9 + 0x2144c);
  do {
    if (((*piVar4 != 0) && (fVar10 = fVar10 + 1.0, ABS(fVar10) != INFINITY)) &&
       ((fVar10 < 0.0 ||
        (uVar2 = uVar2 ^ uVar2 << 0xb, uVar1 = uVar6 >> 0x13 ^ uVar2 >> 8 ^ uVar6 ^ uVar2,
        uVar2 = uVar3, uVar3 = uVar7, uVar7 = uVar6, uVar6 = uVar1,
        fVar10 * ((float)(uVar1 >> 9 | 0x3f800000) + -1.0) + 0.0 < 1.0)))) {
      iVar8 = piVar4[0x4c];
    }
    lVar5 = lVar5 + -0x3b8;
    piVar4 = piVar4 + 0xee;
  } while (lVar5 != 0);
  *param_1 = iVar8;
  return;
}



bool FUN_71019e7dd0(uint *param_1,uint param_2,int *param_3,uint param_4,int *param_5,uint param_6,
                   uint param_7)

{
  bool bVar1;
  bool bVar2;
  undefined8 *puVar3;
  long *plVar4;
  long lVar5;
  int iVar6;
  long lVar7;
  uint uVar8;
  uint uVar9;
  ulong uVar10;
  ulong uVar11;
  uint uVar12;
  undefined4 *puVar13;
  uint uVar14;
  ulong uVar15;
  ulong uVar16;
  undefined8 uVar17;
  long lVar18;
  long *plVar19;
  undefined8 *puVar20;
  undefined8 local_1348;
  undefined8 *local_1340;
  long *local_1338;
  long local_1328 [2];
  long local_1318;
  long local_1310;
  undefined1 auStack_1308 [2360];
  undefined8 local_9d0;
  undefined8 local_9c8 [301];
  
  if (param_1 != (uint *)0x0) {
    if ((int)param_1[1] < (int)param_2) {
      param_2 = *param_1;
    }
    lVar7 = *(long *)(DAT_71040e86a0 + 0x88);
    if (lVar7 != 0) {
      local_1338 = local_1328;
      local_1348 = 0;
      local_1340 = (undefined8 *)0x0;
      lVar18 = 0;
      while( true ) {
        plVar19 = (long *)((long)local_1328 + lVar18 + 8);
        *plVar19 = (long)&local_1318 + lVar18;
        *(long **)((long)local_1328 + lVar18) = plVar19;
        *(undefined1 **)((long)&local_1318 + lVar18) = auStack_1308 + lVar18 + -8;
        if (lVar18 == 0x940) break;
        *(undefined1 **)(auStack_1308 + lVar18 + -8) = auStack_1308 + lVar18;
        lVar18 = lVar18 + 0x20;
      }
      local_9d0 = 0;
      if (local_9c8 != (undefined8 *)0x0) {
        local_1348 = 0x12c00000000;
        local_1340 = local_9c8;
      }
      if (*param_3 != 0) {
        puVar20 = *(undefined8 **)(param_3 + 2);
        puVar3 = puVar20 + *param_3;
        do {
          lVar18 = 0;
          plVar19 = *(long **)(lVar7 + 0x154c68);
          iVar6 = *(int *)*puVar20;
          do {
            plVar4 = local_1338;
            lVar5 = (**(code **)(*plVar19 + 0x20))(plVar19);
            if (((*(int *)(lVar5 + 0xe0) == iVar6) && ((int)lVar18 != *param_5)) &&
               ((1 << (ulong)(*(uint *)(lVar5 + 0xe4) & 0x1f) & param_4 & 0xff) != 0)) {
              if ((int)(uint)local_1348 < local_1348._4_4_) {
                if (local_1338 != (long *)0x0) {
                  local_1338 = (long *)*local_1338;
                }
                *(int *)plVar4 = (int)lVar18;
                if ((int)(uint)local_1348 < local_1348._4_4_) {
                  local_1340[(int)(uint)local_1348] = plVar4;
                  local_1348 = CONCAT44(local_1348._4_4_,(uint)local_1348 + 1);
                }
              }
            }
            lVar18 = lVar18 + 1;
            plVar19 = plVar19 + 0x48;
          } while (lVar18 != 300);
          puVar20 = puVar20 + 1;
        } while (puVar20 != puVar3);
        bVar2 = 0 < (int)(uint)local_1348;
        if (0 < (int)(uint)local_1348) {
          if ((uint)local_1348 != 1) {
            uVar12 = (param_7 ^ param_7 >> 0x1e) * 0x6c078965 + 1;
            uVar14 = (uVar12 ^ uVar12 >> 0x1e) * 0x6c078965 + 2;
            uVar8 = (uVar14 ^ uVar14 >> 0x1e) * 0x6c078965 + 3;
            uVar10 = (ulong)((uVar8 ^ uVar8 >> 0x1e) * 0x6c078965 + 4);
            uVar11 = local_1348 & 0xffffffff;
            do {
              uVar12 = uVar12 ^ uVar12 << 0xb;
              uVar9 = (uint)uVar10;
              uVar10 = (ulong)(uVar9 >> 0x13 ^ uVar12 >> 8 ^ uVar9 ^ uVar12);
              uVar16 = uVar11 - 1 & 0xffffffff;
              uVar17 = local_1340[uVar16];
              uVar15 = uVar11 * uVar10 >> 0x1d & 0x7fffffff8;
              local_1340[uVar16] = *(undefined8 *)((long)local_1340 + uVar15);
              *(undefined8 *)((long)local_1340 + uVar15) = uVar17;
              bVar1 = 2 < uVar11;
              uVar11 = uVar11 - 1;
              uVar12 = uVar14;
              uVar14 = uVar8;
              uVar8 = uVar9;
            } while (bVar1);
          }
          uVar12 = (uint)local_1348;
          if ((int)param_2 <= (int)(uint)local_1348) {
            uVar12 = param_2;
          }
          if (0 < (int)uVar12) {
            uVar11 = 0;
            do {
              if (uVar11 < (local_1348 & 0xffffffff)) {
                puVar13 = (undefined4 *)local_1340[uVar11];
              }
              else {
                puVar13 = (undefined4 *)0x0;
              }
              if ((int)*param_1 < (int)param_1[1]) {
                puVar20 = *(undefined8 **)(param_1 + 4);
                if (puVar20 != (undefined8 *)0x0) {
                  *(undefined8 *)(param_1 + 4) = *puVar20;
                }
                *(undefined4 *)puVar20 = *puVar13;
                if ((int)*param_1 < (int)param_1[1]) {
                  *(undefined8 **)(*(long *)(param_1 + 2) + (long)(int)*param_1 * 8) = puVar20;
                  *param_1 = *param_1 + 1;
                }
              }
              uVar11 = uVar11 + 1;
            } while (uVar12 != uVar11);
          }
          if ((param_6 & 1) != 0) {
            if ((int)(uint)local_1348 < (int)param_2) {
              iVar6 = param_2 - uVar12;
              do {
                if ((uint)local_1348 == 0) {
                  puVar13 = (undefined4 *)0x0;
                }
                else {
                  puVar13 = (undefined4 *)*local_1340;
                }
                if ((int)*param_1 < (int)param_1[1]) {
                  puVar20 = *(undefined8 **)(param_1 + 4);
                  if (puVar20 != (undefined8 *)0x0) {
                    *(undefined8 *)(param_1 + 4) = *puVar20;
                  }
                  *(undefined4 *)puVar20 = *puVar13;
                  if ((int)*param_1 < (int)param_1[1]) {
                    *(undefined8 **)(*(long *)(param_1 + 2) + (long)(int)*param_1 * 8) = puVar20;
                    *param_1 = *param_1 + 1;
                  }
                }
                iVar6 = iVar6 + -1;
              } while (iVar6 != 0);
              return bVar2;
            }
            return bVar2;
          }
          return bVar2;
        }
      }
    }
  }
  return false;
}



int FUN_71019e82b0(int param_1,uint param_2)

{
  long lVar1;
  int iVar2;
  long *plVar3;
  long lVar4;
  
  if (*(long *)(DAT_71040e86a0 + 0x88) == 0) {
    iVar2 = 0;
  }
  else {
    plVar3 = *(long **)(*(long *)(DAT_71040e86a0 + 0x88) + 0x154c68);
    iVar2 = 0;
    lVar4 = 300;
    do {
      lVar1 = (**(code **)(*plVar3 + 0x20))(plVar3);
      if (*(int *)(lVar1 + 0xe0) == param_1) {
        iVar2 = iVar2 + ((param_2 & 0xff) >> (ulong)(*(uint *)(lVar1 + 0xe4) & 0x1f) & 1);
      }
      lVar4 = lVar4 + -1;
      plVar3 = plVar3 + 0x48;
    } while (lVar4 != 0);
  }
  return iVar2;
}



void FUN_71019e8360(int *param_1)

{
  int iVar1;
  long lVar2;
  int iVar3;
  undefined8 *puVar4;
  undefined8 *puVar5;
  
  if (0 < *param_1) {
    lVar2 = 0;
    puVar5 = *(undefined8 **)(param_1 + 4);
    do {
      puVar4 = *(undefined8 **)(*(long *)(param_1 + 2) + lVar2 * 8);
      lVar2 = lVar2 + 1;
      *puVar4 = puVar5;
      *(undefined8 **)(param_1 + 4) = puVar4;
      puVar5 = puVar4;
    } while (lVar2 < *param_1);
  }
  iVar1 = param_1[1];
  *param_1 = 0;
  if (iVar1 < 1) {
    iVar3 = 0;
    if (0 < iVar1) goto LAB_71019e83e8;
  }
  else {
    puVar5 = *(undefined8 **)(param_1 + 4);
    if (puVar5 != (undefined8 *)0x0) {
      *(undefined8 *)(param_1 + 4) = *puVar5;
    }
    *(undefined4 *)puVar5 = 0;
    iVar3 = *param_1;
    iVar1 = param_1[1];
    if (iVar3 < iVar1) {
      *(undefined8 **)(*(long *)(param_1 + 2) + (long)iVar3 * 8) = puVar5;
      iVar1 = param_1[1];
      iVar3 = *param_1 + 1;
      *param_1 = iVar3;
    }
    if (iVar3 < iVar1) {
LAB_71019e83e8:
      puVar5 = *(undefined8 **)(param_1 + 4);
      if (puVar5 != (undefined8 *)0x0) {
        *(undefined8 *)(param_1 + 4) = *puVar5;
      }
      *(undefined4 *)puVar5 = 1;
      iVar3 = *param_1;
      iVar1 = param_1[1];
      if (iVar3 < iVar1) {
        *(undefined8 **)(*(long *)(param_1 + 2) + (long)iVar3 * 8) = puVar5;
        iVar1 = param_1[1];
        iVar3 = *param_1 + 1;
        *param_1 = iVar3;
      }
    }
  }
  if (iVar3 < iVar1) {
    puVar5 = *(undefined8 **)(param_1 + 4);
    if (puVar5 != (undefined8 *)0x0) {
      *(undefined8 *)(param_1 + 4) = *puVar5;
    }
    *(undefined4 *)puVar5 = 2;
    iVar1 = *param_1;
    if (param_1[1] <= iVar1) {
      if (param_1[1] <= iVar1) {
        return;
      }
      goto LAB_71019e8470;
    }
    *(undefined8 **)(*(long *)(param_1 + 2) + (long)iVar1 * 8) = puVar5;
    iVar1 = param_1[1];
    iVar3 = *param_1 + 1;
    *param_1 = iVar3;
  }
  if (iVar1 <= iVar3) {
    return;
  }
LAB_71019e8470:
  puVar5 = *(undefined8 **)(param_1 + 4);
  if (puVar5 != (undefined8 *)0x0) {
    *(undefined8 *)(param_1 + 4) = *puVar5;
  }
  *(undefined4 *)puVar5 = 4;
  if (*param_1 < param_1[1]) {
    *(undefined8 **)(*(long *)(param_1 + 2) + (long)*param_1 * 8) = puVar5;
    *param_1 = *param_1 + 1;
  }
  return;
}



void FUN_71019e84e0(int *param_1)

{
  int iVar1;
  long lVar2;
  int iVar3;
  undefined8 *puVar4;
  undefined8 *puVar5;
  
  if (0 < *param_1) {
    lVar2 = 0;
    puVar5 = *(undefined8 **)(param_1 + 4);
    do {
      puVar4 = *(undefined8 **)(*(long *)(param_1 + 2) + lVar2 * 8);
      lVar2 = lVar2 + 1;
      *puVar4 = puVar5;
      *(undefined8 **)(param_1 + 4) = puVar4;
      puVar5 = puVar4;
    } while (lVar2 < *param_1);
  }
  iVar1 = param_1[1];
  *param_1 = 0;
  if (iVar1 < 1) {
    iVar3 = 0;
    if (0 < iVar1) goto LAB_71019e8568;
  }
  else {
    puVar5 = *(undefined8 **)(param_1 + 4);
    if (puVar5 != (undefined8 *)0x0) {
      *(undefined8 *)(param_1 + 4) = *puVar5;
    }
    *(undefined4 *)puVar5 = 0;
    iVar3 = *param_1;
    iVar1 = param_1[1];
    if (iVar3 < iVar1) {
      *(undefined8 **)(*(long *)(param_1 + 2) + (long)iVar3 * 8) = puVar5;
      iVar1 = param_1[1];
      iVar3 = *param_1 + 1;
      *param_1 = iVar3;
    }
    if (iVar3 < iVar1) {
LAB_71019e8568:
      puVar5 = *(undefined8 **)(param_1 + 4);
      if (puVar5 != (undefined8 *)0x0) {
        *(undefined8 *)(param_1 + 4) = *puVar5;
      }
      *(undefined4 *)puVar5 = 1;
      iVar3 = *param_1;
      iVar1 = param_1[1];
      if (iVar3 < iVar1) {
        *(undefined8 **)(*(long *)(param_1 + 2) + (long)iVar3 * 8) = puVar5;
        iVar1 = param_1[1];
        iVar3 = *param_1 + 1;
        *param_1 = iVar3;
      }
    }
  }
  if (iVar3 < iVar1) {
    puVar5 = *(undefined8 **)(param_1 + 4);
    if (puVar5 != (undefined8 *)0x0) {
      *(undefined8 *)(param_1 + 4) = *puVar5;
    }
    *(undefined4 *)puVar5 = 2;
    iVar3 = *param_1;
    iVar1 = param_1[1];
    if (iVar3 < iVar1) {
      *(undefined8 **)(*(long *)(param_1 + 2) + (long)iVar3 * 8) = puVar5;
      iVar1 = param_1[1];
      iVar3 = *param_1 + 1;
      *param_1 = iVar3;
      goto LAB_71019e85e8;
    }
    if (iVar1 <= iVar3) goto LAB_71019e862c;
  }
  else {
LAB_71019e85e8:
    if (iVar1 <= iVar3) goto LAB_71019e862c;
  }
  puVar5 = *(undefined8 **)(param_1 + 4);
  if (puVar5 != (undefined8 *)0x0) {
    *(undefined8 *)(param_1 + 4) = *puVar5;
  }
  *(undefined4 *)puVar5 = 3;
  iVar3 = *param_1;
  iVar1 = param_1[1];
  if (iVar3 < iVar1) {
    *(undefined8 **)(*(long *)(param_1 + 2) + (long)iVar3 * 8) = puVar5;
    iVar1 = param_1[1];
    iVar3 = *param_1 + 1;
    *param_1 = iVar3;
  }
LAB_71019e862c:
  if (iVar3 < iVar1) {
    puVar5 = *(undefined8 **)(param_1 + 4);
    if (puVar5 != (undefined8 *)0x0) {
      *(undefined8 *)(param_1 + 4) = *puVar5;
    }
    *(undefined4 *)puVar5 = 4;
    if (*param_1 < param_1[1]) {
      *(undefined8 **)(*(long *)(param_1 + 2) + (long)*param_1 * 8) = puVar5;
      *param_1 = *param_1 + 1;
    }
  }
  return;
}



bool FUN_71019e86b0(uint param_1)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  bool bVar5;
  int iVar6;
  undefined8 *puVar7;
  long lVar8;
  long *plVar9;
  long lVar10;
  
  lVar10 = *(long *)(*DAT_7103a5c098 + 0x80);
  if (lVar10 == 0) {
    bVar5 = false;
  }
  else {
    if (param_1 != 0) {
      puVar7 = *(undefined8 **)(*DAT_7103a59ec8 + 0x58);
      lVar8 = 0;
      if (puVar7 != (undefined8 *)0x0) {
        if (((*DAT_7103a62bc8 & 1) == 0) &&
           (iVar6 = thunk_EXT_FUN_02e95df0(DAT_7103a62bc8), iVar6 != 0)) {
          *DAT_7103a62bc0 = DAT_7103a59e80 + 0x10;
          thunk_EXT_FUN_02e95df0(DAT_7103a62bc8);
        }
        lVar8 = (**(code **)*puVar7)(puVar7,DAT_7103a62bc0);
      }
      uVar1 = *(uint *)(lVar8 + 0x24);
      if (uVar1 != 0) {
        uVar3 = 0;
        if (uVar1 != 0) {
          uVar3 = param_1 / uVar1;
        }
        uVar3 = param_1 - uVar3 * uVar1;
        uVar4 = uVar3;
        do {
          uVar2 = *(uint *)(*(long *)(lVar8 + 0x18) +
                           (-(ulong)(uVar4 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar4 << 4));
          if (uVar2 == param_1 || uVar2 == 0) break;
          uVar2 = 0;
          if ((int)(uVar4 + 1) < (int)uVar1) {
            uVar2 = uVar4 + 1;
          }
          uVar4 = uVar2;
        } while (uVar2 != uVar3);
      }
    }
    plVar9 = (long *)FUN_7101a72200(lVar10 + 0x12e10);
    for (plVar9 = (long *)*plVar9; plVar9 != (long *)0x0; plVar9 = (long *)*plVar9) {
      if (*(uint *)(plVar9 + 3) <= param_1) {
        if (param_1 <= *(uint *)(plVar9 + 3)) {
          return *(int *)(plVar9 + 7) == 0;
        }
        plVar9 = plVar9 + 1;
      }
    }
    bVar5 = true;
  }
  return bVar5;
}



undefined4 * FUN_71019e8800(int *param_1)

{
  undefined4 *puVar1;
  int iVar2;
  int iVar3;
  
  iVar2 = *param_1;
  iVar3 = param_1[1];
  if (iVar2 == 0 && iVar3 == -1) {
    return &DAT_71032b474c;
  }
  if ((iVar2 == 1) && (iVar3 == 0)) {
    return &DAT_71032b4764;
  }
  if ((iVar2 == 0) && (iVar3 == 1)) {
    return &DAT_71032b475c;
  }
  if ((iVar2 == -1) && (iVar3 == 0)) {
    return &DAT_71032b4754;
  }
  if ((iVar2 == 1) && (iVar3 == -1)) {
    return &DAT_71032b4774;
  }
  if ((iVar2 == -1) && (iVar3 == -1)) {
    return &DAT_71032b4784;
  }
  if ((iVar2 == 1) && (iVar3 == 1)) {
    return &DAT_71032b477c;
  }
  puVar1 = &DAT_71032b476c;
  if (iVar3 != 1 || iVar2 != -1) {
    puVar1 = &DAT_71032b478c;
  }
  return puVar1;
}



undefined4 * FUN_71019e88e0(int *param_1,int *param_2)

{
  uint uVar1;
  uint uVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  uint uVar9;
  uint uVar10;
  
  iVar5 = *param_2;
  iVar7 = param_2[1];
  iVar6 = *param_1;
  iVar8 = param_1[1];
  uVar9 = iVar5 - iVar6;
  uVar10 = iVar7 - iVar8;
  uVar1 = -uVar9;
  if (-1 < (int)uVar9) {
    uVar1 = uVar9;
  }
  uVar2 = -uVar10;
  if (-1 < (int)uVar10) {
    uVar2 = uVar10;
  }
  if ((iVar7 != iVar8 && iVar5 != iVar6 || 1 < uVar1) || 1 < uVar2) {
    return &DAT_71032b478c;
  }
  if ((iVar5 == iVar6) && (iVar7 == iVar8)) {
    return &DAT_71032b478c;
  }
  if (0 < (int)uVar9) {
    return &DAT_71032b4754;
  }
  if (-1 < (int)uVar9) {
    puVar3 = &DAT_71032b478c;
    if (iVar7 != iVar8) {
      puVar3 = &DAT_71032b475c;
    }
    puVar4 = &DAT_71032b474c;
    if (iVar7 - iVar8 < 1) {
      puVar4 = puVar3;
    }
    return puVar4;
  }
  return &DAT_71032b4764;
}



float FUN_71019e8984(float *param_1,uint *param_2)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  float fVar5;
  float fVar6;
  
  switch(param_1[3]) {
  case 0.0:
    uVar4 = *param_2;
    if (8 < uVar4) {
      fVar5 = *param_1;
      goto LAB_71019e8acc;
    }
    uVar1 = 1 << (ulong)(uVar4 & 0x1f);
    uVar3 = uVar4;
    if ((uVar1 & 0x49) != 0) goto switchD_71019e8a70_caseD_7;
    uVar2 = uVar4;
    if ((uVar1 & 0x92) == 0) goto switchD_71019e8a70_caseD_1;
    break;
  case 1.4013e-45:
    uVar4 = 5;
    uVar2 = 4;
    uVar3 = 3;
    switch(*param_2) {
    case 0:
switchD_71019e8a70_caseD_8:
      uVar3 = 6;
    case 1:
      goto switchD_71019e8a70_caseD_7;
    case 2:
switchD_71019e8a70_caseD_6:
      uVar3 = 0;
switchD_71019e8a70_caseD_7:
      uVar4 = uVar3;
      fVar5 = *param_1;
      fVar6 = -0.5;
      goto LAB_71019e8ac4;
    case 3:
switchD_71019e8a70_caseD_5:
      uVar2 = 7;
      break;
    case 5:
switchD_71019e8a70_caseD_3:
      uVar2 = 1;
      break;
    case 6:
switchD_71019e8a70_caseD_2:
      uVar4 = 8;
    case 7:
      goto switchD_71019e8a70_caseD_1;
    case 8:
switchD_71019e8a70_caseD_0:
      uVar4 = 2;
      goto switchD_71019e8a70_caseD_1;
    }
    break;
  case 2.8026e-45:
    uVar4 = 5;
    uVar2 = 4;
    uVar3 = 3;
    switch(*param_2) {
    case 0:
      goto switchD_71019e8a70_caseD_2;
    case 1:
      goto switchD_71019e8a70_caseD_5;
    case 2:
      goto switchD_71019e8a70_caseD_8;
    case 3:
      goto switchD_71019e8a70_caseD_1;
    case 5:
      goto switchD_71019e8a70_caseD_7;
    case 6:
      goto switchD_71019e8a70_caseD_0;
    case 7:
      goto switchD_71019e8a70_caseD_3;
    case 8:
      goto switchD_71019e8a70_caseD_6;
    }
    break;
  case 4.2039e-45:
    uVar4 = 5;
    uVar2 = 4;
    uVar3 = 3;
    switch(*param_2) {
    case 0:
      goto switchD_71019e8a70_caseD_0;
    case 1:
      goto switchD_71019e8a70_caseD_1;
    case 2:
      goto switchD_71019e8a70_caseD_2;
    case 3:
      goto switchD_71019e8a70_caseD_3;
    case 5:
      goto switchD_71019e8a70_caseD_5;
    case 6:
      goto switchD_71019e8a70_caseD_6;
    case 7:
      goto switchD_71019e8a70_caseD_7;
    case 8:
      goto switchD_71019e8a70_caseD_8;
    }
    break;
  default:
    uVar2 = 4;
  }
  uVar4 = uVar2;
  fVar5 = *param_1;
LAB_71019e8acc:
  if ((uVar4 < 9) &&
     ((uVar2 = 1 << (ulong)(uVar4 & 0x1f), (uVar2 & 7) != 0 || ((uVar2 & 0x38) == 0)))) {
    return fVar5;
  }
  return fVar5;
switchD_71019e8a70_caseD_1:
  fVar5 = *param_1;
  fVar6 = 0.5;
LAB_71019e8ac4:
  fVar5 = fVar5 + fVar6 * param_1[4];
  goto LAB_71019e8acc;
}



void FUN_71019e8b20(long *param_1,long param_2,undefined4 *param_3,undefined4 *param_4)

{
  byte bVar1;
  byte bVar2;
  long lVar3;
  int *piVar4;
  uint uVar5;
  long lVar6;
  char cVar7;
  char cVar8;
  
  lVar3 = DAT_7103a5a2a8;
  bVar1 = *(byte *)(param_2 + 10);
  if ((ulong)bVar1 != 0xff) {
    piVar4 = &DAT_7104046478;
    if ((DAT_71041fd400 != 0) &&
       (lVar6 = *(long *)(DAT_71041fd400 + (ulong)bVar1 * 8 + 8), lVar6 != 0)) {
      piVar4 = (int *)(lVar6 + 0x150);
    }
    uVar5 = piVar4[1];
    if (-1 < (int)uVar5) {
      if (*DAT_71040e7d48 <= uVar5) {
        uVar5 = 0;
      }
      if ((((*(long *)(DAT_71040e7d48 + 2) != 0) &&
           (lVar6 = *(long *)(DAT_71040e7d48 + 2) + (ulong)uVar5 * 0x10,
           *(int *)(lVar6 + 4) == *piVar4)) && (lVar6 = *(long *)(lVar6 + 8), lVar6 != 0)) &&
         ((*(byte *)(param_2 + 8) < *(byte *)(lVar6 + 0x24) &&
          (bVar2 = *(byte *)(param_2 + 9), bVar2 < *(byte *)(lVar6 + 0x25))))) {
        switch(*param_4) {
        default:
          cVar7 = (char)*param_3;
          cVar8 = (char)param_3[1];
          break;
        case 1:
          cVar7 = (char)param_3[1];
          cVar8 = -(char)*param_3;
          break;
        case 2:
          cVar7 = -(char)*param_3;
          cVar8 = -(char)param_3[1];
          break;
        case 3:
          cVar8 = (char)*param_3;
          cVar7 = -(char)param_3[1];
        }
        *(byte *)(param_1 + 1) = *(byte *)(param_2 + 8) + cVar7;
        *(byte *)((long)param_1 + 10) = bVar1;
        *param_1 = lVar3 + 0x10;
        *(byte *)((long)param_1 + 9) = bVar2 + cVar8;
        return;
      }
    }
  }
  *(undefined2 *)(param_1 + 1) = 0;
  *param_1 = (long)&DAT_710386bbc8;
  *(undefined1 *)((long)param_1 + 10) = 0xff;
  return;
}



uint FUN_71019e8c60(int *param_1,undefined8 *param_2)

{
  uint uVar1;
  ulong uVar2;
  undefined4 local_18;
  undefined4 local_14;
  
  uVar2 = (**(code **)*param_2)(param_2,param_1);
  if ((uVar2 & 1) == 0) {
    uVar2 = (**(code **)*param_2)(param_2,param_1 + 1);
    if ((uVar2 & 1) == 0) {
      uVar1 = param_1[1] - 1;
      if (uVar1 < 3) {
        local_14 = *(undefined4 *)((long)&DAT_71032b47e8 + (long)(int)uVar1 * 4);
      }
      else {
        local_14 = 2;
      }
      uVar2 = (**(code **)*param_2)(param_2,&local_14);
      if ((uVar2 & 1) == 0) {
        if (*param_1 - 1U < 3) {
          local_18 = *(undefined4 *)((long)&DAT_71032b47e8 + (long)(int)(*param_1 - 1U) * 4);
        }
        else {
          local_18 = 2;
        }
        uVar1 = (**(code **)*param_2)(param_2,&local_18);
        goto LAB_71019e8cf0;
      }
    }
  }
  uVar1 = 1;
LAB_71019e8cf0:
  return uVar1 & 1;
}



void FUN_71019e8d50(long param_1,ulong param_2,undefined4 param_3,long *param_4)

{
  undefined8 *puVar1;
  undefined8 uVar2;
  long *plVar3;
  long lVar4;
  long *plVar5;
  long lVar6;
  int iVar7;
  ulong uVar8;
  long lVar9;
  
  iVar7 = (int)param_2;
  *(undefined4 *)(param_1 + 0x14) = param_3;
  *(int *)(param_1 + 0x18) = iVar7;
  plVar3 = DAT_7103a65db8;
  if (iVar7 < 1) {
LAB_71019e8dfc:
    uVar8 = (ulong)*(uint *)(param_1 + 0x28);
    if (*(uint *)(param_1 + 0x28) == 0) goto LAB_71019e8e14;
    lVar6 = *(long *)(param_1 + 0x30);
  }
  else {
    lVar9 = *DAT_7103a65db8;
    lVar6 = (param_2 & 0xffffffff) << 6;
    if (lVar9 == 0) {
      lVar6 = FUN_71005fbcb0(8,lVar6);
    }
    else {
      plVar5 = param_4;
      if (param_4 == (long *)0x0) {
        lVar4 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
        plVar5 = (long *)(lVar9 + 8);
        if (lVar4 != 0) {
          plVar5 = (long *)(lVar4 + 0x88);
        }
        plVar5 = (long *)*plVar5;
        if (plVar5 == (long *)0x0) goto LAB_71019e8dfc;
      }
      lVar6 = (**(code **)(*plVar5 + 0x30))(plVar5,lVar6,8);
    }
    if (lVar6 == 0) goto LAB_71019e8dfc;
    *(int *)(param_1 + 0x28) = iVar7;
    uVar8 = param_2 & 0xffffffff;
    *(long *)(param_1 + 0x30) = lVar6;
  }
  thunk_EXT_FUN_02e95df0(lVar6,0,-(uVar8 >> 0x1f) & 0xffffffc000000000 | uVar8 << 6);
LAB_71019e8e14:
  if (0 < iVar7) {
    lVar9 = *plVar3;
    lVar6 = (param_2 & 0xffffffff) << 3;
    if (lVar9 == 0) {
      lVar6 = FUN_71005fbcb0(8,lVar6);
      uVar2 = DAT_7103a59fe0;
    }
    else {
      if (param_4 == (long *)0x0) {
        lVar4 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
        puVar1 = (undefined8 *)(lVar9 + 8);
        if (lVar4 != 0) {
          puVar1 = (undefined8 *)(lVar4 + 0x88);
        }
        param_4 = (long *)*puVar1;
        if (param_4 == (long *)0x0) {
          return;
        }
      }
      lVar6 = (**(code **)(*param_4 + 0x30))(param_4,lVar6,8);
      uVar2 = DAT_7103a59fe0;
    }
    DAT_7103a59fe0 = uVar2;
    if (lVar6 != 0) {
      if (iVar7 == 1) {
        lVar9 = 0;
      }
      else {
        lVar9 = 0;
        do {
          puVar1 = (undefined8 *)(lVar6 + lVar9);
          lVar9 = lVar9 + 0x10;
          *puVar1 = uVar2;
          puVar1[1] = uVar2;
        } while ((param_2 & 0xfffffffe) * 8 - lVar9 != 0);
      }
      if ((param_2 & 1) != 0) {
        *(undefined1 **)(lVar9 + lVar6) = &DAT_71032a8da0;
      }
      *(int *)(param_1 + 0x38) = iVar7;
      *(long *)(param_1 + 0x40) = lVar6;
    }
  }
  return;
}



void FUN_71019e8ef4(uint *param_1)

{
  uint uVar1;
  long lVar2;
  
  param_1[7] = 0;
  uVar1 = param_1[5];
  param_1[3] = *param_1;
  param_1[4] = param_1[1];
  *param_1 = uVar1;
  param_1[1] = 0;
  param_1[2] = 0xffffffff;
  *(undefined1 *)((long)param_1 + 0x21) = 1;
  *(undefined1 *)((long)param_1 + 0x23) = 1;
  if (param_1[10] <= uVar1) {
    uVar1 = 0;
  }
  lVar2 = *(long *)(*(long *)(param_1 + 0xc) + (long)(int)uVar1 * 0x40);
  if (lVar2 != 0) {
                    // WARNING: Could not recover jumptable at 0x0071019e8f40. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(lVar2 + 0x10))();
    return;
  }
  return;
}



void FUN_71019e8f48(uint *param_1,uint param_2)

{
  long *plVar1;
  uint uVar2;
  long lVar3;
  uint uVar4;
  uint uVar5;
  long lVar6;
  
  uVar2 = *param_1;
  if (uVar2 == 0xffffffff) {
    uVar5 = param_1[1];
    param_1[1] = 0;
    param_1[2] = 0xffffffff;
    uVar2 = param_1[5];
    *(undefined1 *)((long)param_1 + 0x21) = 1;
    *(undefined1 *)((long)param_1 + 0x23) = 1;
    param_1[7] = 0;
    param_1[3] = 0xffffffff;
    param_1[4] = uVar5;
    *param_1 = uVar2;
    uVar5 = uVar2;
    if (param_1[10] <= uVar2) {
      uVar5 = 0;
    }
    lVar3 = *(long *)(*(long *)(param_1 + 0xc) + (long)(int)uVar5 * 0x40);
    if (lVar3 != 0) {
      (**(code **)(lVar3 + 0x10))();
      uVar2 = *param_1;
    }
  }
  uVar4 = param_1[10];
  lVar3 = *(long *)(param_1 + 0xc);
  uVar5 = uVar2;
  if (uVar4 <= uVar2) {
    uVar5 = 0;
  }
  plVar1 = (long *)(lVar3 + (long)(int)uVar5 * 0x40);
  lVar6 = *plVar1;
  if (lVar6 != 0) {
    (**(code **)(lVar6 + 0x20))(plVar1,param_2);
    uVar2 = *param_1;
    uVar4 = param_1[10];
    lVar3 = *(long *)(param_1 + 0xc);
  }
  *param_1 = param_2;
  if (uVar4 <= param_2) {
    param_2 = 0;
  }
  param_1[7] = 0;
  param_1[3] = uVar2;
  param_1[4] = param_1[1];
  param_1[1] = 0;
  param_1[2] = 0xffffffff;
  *(undefined1 *)((long)param_1 + 0x21) = 1;
  *(undefined1 *)((long)param_1 + 0x23) = 1;
  lVar3 = *(long *)(lVar3 + (long)(int)param_2 * 0x40);
  if (lVar3 != 0) {
                    // WARNING: Could not recover jumptable at 0x0071019e9044. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(lVar3 + 0x10))();
    return;
  }
  return;
}



void FUN_71019e905c(uint *param_1,uint param_2,undefined8 *param_3,undefined8 *param_4)

{
  long *plVar1;
  uint uVar2;
  long lVar3;
  uint uVar4;
  
  uVar2 = *param_1;
  if (uVar2 == 0xffffffff) {
    uVar4 = param_1[1];
    param_1[1] = 0;
    param_1[2] = 0xffffffff;
    uVar2 = param_1[5];
    *(undefined1 *)((long)param_1 + 0x21) = 1;
    *(undefined1 *)((long)param_1 + 0x23) = 1;
    param_1[7] = 0;
    param_1[3] = 0xffffffff;
    param_1[4] = uVar4;
    *param_1 = uVar2;
    uVar4 = uVar2;
    if (param_1[10] <= uVar2) {
      uVar4 = 0;
    }
    lVar3 = *(long *)(*(long *)(param_1 + 0xc) + (long)(int)uVar4 * 0x40);
    if (lVar3 != 0) {
      (**(code **)(lVar3 + 0x10))();
      uVar2 = *param_1;
    }
  }
  (**(code **)*param_3)(param_3,uVar2);
  uVar2 = *param_1;
  uVar4 = uVar2;
  if (param_1[10] <= uVar2) {
    uVar4 = 0;
  }
  plVar1 = (long *)(*(long *)(param_1 + 0xc) + (long)(int)uVar4 * 0x40);
  lVar3 = *plVar1;
  if (lVar3 != 0) {
    (**(code **)(lVar3 + 0x20))(plVar1,param_2);
    uVar2 = *param_1;
  }
  *param_1 = param_2;
  param_1[7] = 0;
  param_1[3] = uVar2;
  param_1[4] = param_1[1];
  param_1[1] = 0;
  param_1[2] = 0xffffffff;
  *(undefined1 *)((long)param_1 + 0x21) = 1;
  *(undefined1 *)((long)param_1 + 0x23) = 1;
  (**(code **)*param_4)(param_4,param_2);
  uVar2 = *param_1;
  if (param_1[10] <= uVar2) {
    uVar2 = 0;
  }
  lVar3 = *(long *)(*(long *)(param_1 + 0xc) + (long)(int)uVar2 * 0x40);
  if (lVar3 != 0) {
                    // WARNING: Could not recover jumptable at 0x0071019e9198. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(lVar3 + 0x10))();
    return;
  }
  return;
}



void FUN_71019e91c4(uint *param_1)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  long lVar4;
  long lVar5;
  
  uVar2 = *param_1;
  *(undefined1 *)((long)param_1 + 0x21) = 0;
  if (uVar2 == 0xffffffff && (char)param_1[8] != '\0') {
    param_1[7] = 0;
    uVar2 = param_1[5];
    param_1[3] = 0xffffffff;
    param_1[4] = param_1[1];
    *param_1 = uVar2;
    param_1[1] = 0;
    param_1[2] = 0xffffffff;
    *(undefined1 *)((long)param_1 + 0x21) = 1;
    *(undefined1 *)((long)param_1 + 0x23) = 1;
    uVar1 = uVar2;
    if (param_1[10] <= uVar2) {
      uVar1 = 0;
    }
    lVar4 = *(long *)(*(long *)(param_1 + 0xc) + (long)(int)uVar1 * 0x40);
    if (lVar4 != 0) {
      (**(code **)(lVar4 + 0x10))();
      uVar2 = *param_1;
    }
  }
  if (param_1[10] <= uVar2) {
    uVar2 = 0;
  }
  lVar4 = *(long *)(*(long *)(param_1 + 0xc) + (long)(int)uVar2 * 0x40);
  if (lVar4 != 0) {
    (**(code **)(lVar4 + 0x18))();
  }
  uVar2 = param_1[1];
  param_1[2] = uVar2;
  lVar4 = DAT_7104202ae8;
  if (*(char *)((long)param_1 + 0x21) == '\0') {
    lVar5 = *DAT_7103a5a150;
    if (*(char *)((long)param_1 + 0x22) == '\0') {
      iVar3 = *(int *)(lVar5 + 0x10);
      if ((*(uint *)(DAT_7104202ae8 + 0xf0) & 2) != 0) {
        iVar3 = 0;
      }
      param_1[1] = iVar3 + uVar2;
      iVar3 = *(int *)(lVar5 + 0x18);
      if ((*(byte *)(lVar4 + 0xf0) & 2) != 0) {
        iVar3 = 0;
      }
    }
    else {
      param_1[1] = *(int *)(lVar5 + 0x10) + uVar2;
      iVar3 = *(int *)(lVar5 + 0x18);
    }
    param_1[7] = param_1[7] + iVar3;
    if (*(char *)((long)param_1 + 0x23) != '\0') {
      *(undefined1 *)((long)param_1 + 0x23) = 0;
    }
  }
  return;
}



void FUN_71019e92fc(undefined8 *param_1)

{
  long *plVar1;
  long lVar2;
  long lVar3;
  
  *param_1 = &DAT_710398f230;
  if (DAT_71040e3ea0 == param_1) {
    DAT_71040e3ea0 = (undefined8 *)0x0;
    if ((long *)*DAT_71040e3ea8 != (long *)0x0) {
      FUN_71019e9b70((long *)*DAT_71040e3ea8);
    }
    DAT_71040e3ea8 = (undefined8 *)0x0;
  }
  lVar2 = param_1[1];
  *param_1 = &DAT_7103a07950;
  if (lVar2 != 0) {
    if (lVar2 == 1) {
      return;
    }
    if ((*(uint *)(lVar2 + 200) & 1) == 0) {
      lVar3 = 0;
    }
    else {
      lVar3 = lVar2 + 0x88;
      thunk_EXT_FUN_02e95df0(lVar2 + 0xa8);
    }
    plVar1 = (long *)((long)*(int *)(lVar2 + 0x7c) + (long)param_1);
    if (*plVar1 != 0) {
      *(long *)(*plVar1 + 8) = plVar1[1];
    }
    if ((long *)plVar1[1] != (long *)0x0) {
      *(long *)plVar1[1] = *plVar1;
    }
    *plVar1 = 0;
    plVar1[1] = 0;
    *(int *)(lVar2 + 0x78) = *(int *)(lVar2 + 0x78) + -1;
    if (lVar3 != 0) {
      thunk_EXT_FUN_02e95df0(lVar3 + 0x20);
    }
  }
  param_1[1] = 1;
  return;
}



void FUN_71019e93e0(undefined8 *param_1)

{
  long *plVar1;
  
  FUN_71019e92fc(param_1);
  if (DAT_7105a06420 == 0) {
    FUN_71005fbbd0((long)param_1);
    return;
  }
  plVar1 = FUN_71024ef490(DAT_7105a06420,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071019e9424. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



long * FUN_71019e9444(long *param_1)

{
  undefined8 *puVar1;
  long lVar2;
  long *plVar3;
  long lVar4;
  
  if (DAT_71040e3ea8 != (long *)0x0) {
    return DAT_71040e3ea8;
  }
  lVar4 = *DAT_7103a65db8;
  if (lVar4 == 0) {
    plVar3 = (long *)FUN_71005fbcb0(8,0x1140);
  }
  else {
    plVar3 = param_1;
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar1 = (undefined8 *)(lVar4 + 8);
      if (lVar2 != 0) {
        puVar1 = (undefined8 *)(lVar2 + 0x88);
      }
      plVar3 = (long *)*puVar1;
      if (plVar3 == (long *)0x0) {
        plVar3 = (long *)0x0;
        goto LAB_71019e94d0;
      }
    }
    plVar3 = (long *)(**(code **)(*plVar3 + 0x30))(plVar3,0x1140,8);
  }
LAB_71019e94d0:
  FUN_71024ea784(plVar3 + 0x224,param_1,3);
  plVar3[0x224] = (long)&DAT_710398f230;
  DAT_71040e3ea0 = plVar3 + 0x224;
  FUN_71019e9524(plVar3);
  DAT_71040e3ea8 = plVar3;
  return plVar3;
}



void FUN_71019e9524(long *param_1)

{
  long *plVar1;
  undefined *local_48;
  undefined *puStack_40;
  char *local_28;
  
  param_1[0x213] = 0;
  param_1[0x15] = (long)(param_1 + 0x26);
  param_1[2] = 0;
  param_1[3] = 0;
  plVar1 = param_1 + 4;
  *plVar1 = (long)(param_1 + 0x15);
  *(undefined4 *)((long)param_1 + 0x1c) = 0x20;
  param_1[0x26] = (long)(param_1 + 0x37);
  param_1[0x37] = (long)(param_1 + 0x48);
  param_1[0x48] = (long)(param_1 + 0x59);
  param_1[0x59] = (long)(param_1 + 0x6a);
  param_1[0x6a] = (long)(param_1 + 0x7b);
  param_1[0x7b] = (long)(param_1 + 0x8c);
  param_1[0x8c] = (long)(param_1 + 0x9d);
  param_1[2] = (long)plVar1;
  param_1[0x9d] = (long)(param_1 + 0xae);
  param_1[0xae] = (long)(param_1 + 0xbf);
  param_1[0xbf] = (long)(param_1 + 0xd0);
  param_1[0xd0] = (long)(param_1 + 0xe1);
  param_1[0xe1] = (long)(param_1 + 0xf2);
  param_1[0xf2] = (long)(param_1 + 0x103);
  param_1[0x103] = (long)(param_1 + 0x114);
  param_1[0x114] = (long)(param_1 + 0x125);
  param_1[0x125] = (long)(param_1 + 0x136);
  param_1[0x136] = (long)(param_1 + 0x147);
  param_1[0x147] = (long)(param_1 + 0x158);
  param_1[0x158] = (long)(param_1 + 0x169);
  param_1[0x169] = (long)(param_1 + 0x17a);
  param_1[0x17a] = (long)(param_1 + 0x18b);
  param_1[0x18b] = (long)(param_1 + 0x19c);
  param_1[0x19c] = (long)(param_1 + 0x1ad);
  param_1[0x1ad] = (long)(param_1 + 0x1be);
  param_1[0x1be] = (long)(param_1 + 0x1cf);
  param_1[0x1cf] = (long)(param_1 + 0x1e0);
  param_1[0x1e0] = (long)(param_1 + 0x1f1);
  param_1[0x1f1] = (long)(param_1 + 0x202);
  param_1[0x202] = (long)(param_1 + 0x213);
  *param_1 = 0;
  param_1[1] = (long)plVar1;
  local_48 = &DAT_710398f288;
  puStack_40 = &DAT_710313d163;
  local_28 = "int";
  FUN_71019e9880(param_1,&local_28,(long *)&local_48);
  (**(code **)(local_48 + 0x18))(&local_48);
  local_48 = &DAT_710398f2c0;
  puStack_40 = &DAT_71030c375b;
  local_28 = "float";
  FUN_71019e9880(param_1,&local_28,(long *)&local_48);
  (**(code **)(local_48 + 0x18))(&local_48);
  local_48 = &DAT_710398f2f8;
  puStack_40 = &DAT_7103176cba;
  local_28 = "ActorHandle";
  FUN_71019e9880(param_1,&local_28,(long *)&local_48);
  (**(code **)(local_48 + 0x18))(&local_48);
  local_48 = &DAT_710398f330;
  puStack_40 = &DAT_71030c375b;
  local_28 = "sead::Vector3<float>";
  FUN_71019e9880(param_1,&local_28,(long *)&local_48);
  (**(code **)(local_48 + 0x18))(&local_48);
  local_48 = &DAT_710398f368;
  puStack_40 = &DAT_710310c78b;
  local_28 = "const char *";
  FUN_71019e9880(param_1,&local_28,(long *)&local_48);
  (**(code **)(local_48 + 0x18))(&local_48);
  local_48 = &DAT_710398f3a0;
  puStack_40 = &DAT_71030e2328;
  local_28 = "const void *";
  FUN_71019e9880(param_1,&local_28,(long *)&local_48);
  (**(code **)(local_48 + 0x18))(&local_48);
  local_48 = &DAT_710398f3d8;
  puStack_40 = (undefined *)0x0;
  local_28 = "bool";
  FUN_71019e9880(param_1,&local_28,(long *)&local_48);
  (**(code **)(local_48 + 0x18))(&local_48);
  local_48 = &DAT_710398f410;
  local_28 = "GroupActionResultType";
  FUN_71019e9880(param_1,&local_28,(long *)&local_48);
  (**(code **)(local_48 + 0x18))(&local_48);
  local_48 = &DAT_710398f250;
  local_28 = "sead::FixedSafeString<64>";
  FUN_71019e9880(param_1,&local_28,(long *)&local_48);
  (**(code **)(local_48 + 0x18))(&local_48);
  return;
}



void FUN_71019e9880(long *param_1,undefined8 *param_2,long *param_3)

{
  long *plVar1;
  bool bVar2;
  byte bVar3;
  byte bVar4;
  long lVar5;
  long *plVar6;
  int iVar7;
  long lVar8;
  byte *pbVar9;
  ulong uVar10;
  long *plVar11;
  byte *pbVar12;
  long *plVar13;
  ulong local_40;
  int local_38;
  
  if ((int)param_1[3] < *(int *)((long)param_1 + 0x1c)) {
    plVar13 = (long *)param_1[1];
    if (plVar13 != (long *)0x0) {
      param_1[1] = *plVar13;
    }
    lVar8 = DAT_7103a59fe0;
    plVar13[4] = (long)&DAT_710398f538;
    *plVar13 = 0;
    plVar13[1] = 0;
    plVar13[2] = 0;
    plVar13[3] = lVar8;
    (**(code **)(*param_3 + 0x10))(param_3);
    *(undefined1 *)(plVar13 + 0x10) = 0;
    plVar1 = plVar13 + 8;
    plVar6 = (long *)*param_2;
    if (plVar1 != plVar6) {
      if ((plVar6 == (long *)0x0) || ((char)*plVar6 == '\0')) {
LAB_71019e99d4:
        iVar7 = 0;
      }
      else {
        lVar8 = 0;
        do {
          if (lVar8 == 0x400000) goto LAB_71019e99d4;
          if (*(char *)((long)plVar6 + lVar8 + 1) == '\0') {
            lVar8 = lVar8 + 1;
            break;
          }
          lVar5 = lVar8 + 2;
          lVar8 = lVar8 + 2;
        } while (*(char *)((long)plVar6 + lVar5) != '\0');
        iVar7 = (int)lVar8;
        if (0x40 < iVar7) {
          iVar7 = 0x40;
        }
      }
      thunk_EXT_FUN_02e95df0(plVar1,plVar6,(long)iVar7);
      *(char *)((long)plVar1 + (long)iVar7) = '\0';
    }
    *(undefined1 *)(plVar13 + 0x10) = 0;
    plVar13[3] = (long)plVar1;
    *(int *)(param_1 + 3) = (int)param_1[3] + 1;
    if ((long *)*param_1 == (long *)0x0) {
      *param_1 = (long)plVar13;
    }
    else {
      iVar7 = 0;
      uVar10 = 0;
      plVar1 = (long *)*param_1;
      do {
        plVar6 = plVar1;
        if ((byte *)plVar13[3] == (byte *)plVar6[3]) {
LAB_71019e9a98:
          if (plVar6 != plVar13) {
            lVar8 = plVar6[1];
            plVar13[1] = lVar8;
            if (lVar8 != 0) {
              *(ulong *)(lVar8 + 0x10) = *(ulong *)(lVar8 + 0x10) & 1 | (ulong)plVar13;
            }
            lVar8 = *plVar6;
            *plVar13 = lVar8;
            if (lVar8 != 0) {
              *(ulong *)(lVar8 + 0x10) = *(ulong *)(lVar8 + 0x10) & 1 | (ulong)plVar13;
            }
            uVar10 = plVar6[2];
            plVar13[2] = uVar10;
            plVar1 = (long *)(uVar10 & 0xfffffffffffffffe);
            plVar11 = param_1;
            if ((plVar1 != (long *)0x0) && (plVar11 = plVar1, (long *)*plVar1 != plVar6)) {
              plVar11 = plVar1 + 1;
            }
            *plVar11 = (long)plVar13;
            (**(code **)(plVar6[4] + 0x18))();
            *plVar6 = param_1[1];
            param_1[1] = (long)plVar6;
            *(int *)(param_1 + 3) = (int)param_1[3] + -1;
          }
          goto LAB_71019e9b28;
        }
        pbVar9 = (byte *)plVar6[3];
        pbVar12 = (byte *)plVar13[3];
        lVar8 = 0x3fffff;
        while( true ) {
          bVar3 = *pbVar12;
          bVar4 = *pbVar9;
          if (bVar3 != bVar4) break;
          if ((bVar3 == 0) ||
             (bVar2 = lVar8 == 0, pbVar9 = pbVar9 + 1, pbVar12 = pbVar12 + 1, lVar8 = lVar8 + -1,
             bVar2)) goto LAB_71019e9a98;
        }
        iVar7 = iVar7 + 1;
        uVar10 = (ulong)(bVar4 <= bVar3) | uVar10 << 1;
        plVar11 = plVar6 + 1;
        if (bVar4 > bVar3) {
          plVar11 = plVar6;
        }
        plVar1 = (long *)*plVar11;
        local_40 = uVar10;
        local_38 = iVar7;
      } while ((long *)*plVar11 != (long *)0x0);
      *plVar11 = (long)plVar13;
      *plVar13 = 0;
      plVar13[1] = 0;
      plVar13[2] = (long)plVar6;
      FUN_7100f26320(param_1,(long)plVar13,&local_40);
LAB_71019e9b28:
      plVar13 = (long *)*param_1;
    }
    plVar13[2] = 1;
  }
  else {
    plVar13 = (long *)*param_1;
    if (plVar13 != (long *)0x0) {
      do {
        if ((byte *)*param_2 == (byte *)plVar13[3]) {
LAB_71019e9994:
          plVar13 = plVar13 + 4;
          (**(code **)(*plVar13 + 0x18))(plVar13);
          *plVar13 = (long)&DAT_710398f538;
                    // WARNING: Could not recover jumptable at 0x0071019e99d0. Too many branches
                    // WARNING: Treating indirect jump as call
          (**(code **)(*param_3 + 0x10))(param_3,plVar13);
          return;
        }
        pbVar9 = (byte *)plVar13[3];
        pbVar12 = (byte *)*param_2;
        lVar8 = 0x3fffff;
        while( true ) {
          bVar3 = *pbVar12;
          if (bVar3 != *pbVar9) break;
          if ((bVar3 == 0) ||
             (bVar2 = lVar8 == 0, pbVar9 = pbVar9 + 1, pbVar12 = pbVar12 + 1, lVar8 = lVar8 + -1,
             bVar2)) goto LAB_71019e9994;
        }
        if (*pbVar9 <= bVar3) {
          plVar13 = plVar13 + 1;
        }
        plVar13 = (long *)*plVar13;
      } while (plVar13 != (long *)0x0);
    }
  }
  return;
}



void FUN_71019e9b70(long *param_1)

{
  long *plVar1;
  
  do {
    if ((long *)*param_1 != (long *)0x0) {
      FUN_71019e9b70((long *)*param_1);
    }
    plVar1 = param_1 + 4;
    param_1 = (long *)param_1[1];
    (**(code **)(*plVar1 + 0x18))(plVar1);
  } while (param_1 != (long *)0x0);
  return;
}



void FUN_71019e9bf0(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071019e9c30. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



void FUN_71019e9c78(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071019e9cb8. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



void FUN_71019e9d04(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071019e9d44. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



void FUN_71019e9d80(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071019e9dc0. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



void FUN_71019e9e1c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071019e9e5c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



void FUN_71019e9eac(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071019e9eec. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



void FUN_71019e9f34(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071019e9f74. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



void FUN_71019e9f94(long param_1,byte *param_2,undefined8 param_3,long *param_4,undefined8 param_5,
                   undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  uint uVar1;
  char *pcVar2;
  undefined8 uVar3;
  undefined1 *local_50;
  int local_48;
  undefined1 local_44 [31];
  undefined1 local_25;
  
  if (*(long *)(param_1 + 8) != 0) {
    local_25 = 0;
    local_50 = local_44;
    local_44[0] = 0;
    local_48 = 0x20;
    uVar1 = FUN_7100bc08f0((long *)&local_50,*(long *)(param_1 + 8),(ulong)*param_2,param_4,param_5,
                           param_6,param_7,param_8);
    local_50[(long)local_48 + -1] = 0;
    (**(code **)(*param_4 + 0x10))(param_4,local_50,uVar1);
    return;
  }
  if (*param_2 == 0) {
    pcVar2 = "false";
    uVar3 = 5;
  }
  else {
    pcVar2 = "true";
    uVar3 = 4;
  }
                    // WARNING: Could not recover jumptable at 0x0071019ea050. Too many branches
                    // WARNING: Treating indirect jump as call
  (**(code **)(*param_4 + 0x10))(param_4,pcVar2,uVar3);
  return;
}



void FUN_71019ea06c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071019ea0ac. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



void FUN_71019ea11c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071019ea15c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



void FUN_71019ea19c(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071019ea1dc. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



void FUN_71019ea1fc(undefined8 *param_1)

{
  long *plVar1;
  long lVar2;
  long lVar3;
  
  *param_1 = &DAT_710398f570;
  lVar2 = DAT_71040e3eb8;
  if (DAT_71040e3eb0 == param_1) {
    DAT_71040e3eb0 = (undefined8 *)0x0;
    if (*(char *)(DAT_71040e3eb8 + 0x28) != '\0') {
      thunk_EXT_FUN_02e95df0(DAT_71040e3eb8);
      *(undefined1 *)(lVar2 + 0x28) = 0;
      *(undefined8 *)(lVar2 + 0x18) = 0;
      *(undefined8 *)(lVar2 + 0x20) = 0;
    }
    DAT_71040e3eb8 = 0;
  }
  lVar2 = param_1[1];
  *param_1 = &DAT_7103a07950;
  if (lVar2 != 0) {
    if (lVar2 == 1) {
      return;
    }
    if ((*(uint *)(lVar2 + 200) & 1) == 0) {
      lVar3 = 0;
    }
    else {
      lVar3 = lVar2 + 0x88;
      thunk_EXT_FUN_02e95df0(lVar2 + 0xa8);
    }
    plVar1 = (long *)((long)*(int *)(lVar2 + 0x7c) + (long)param_1);
    if (*plVar1 != 0) {
      *(long *)(*plVar1 + 8) = plVar1[1];
    }
    if ((long *)plVar1[1] != (long *)0x0) {
      *(long *)plVar1[1] = *plVar1;
    }
    *plVar1 = 0;
    plVar1[1] = 0;
    *(int *)(lVar2 + 0x78) = *(int *)(lVar2 + 0x78) + -1;
    if (lVar3 != 0) {
      thunk_EXT_FUN_02e95df0(lVar3 + 0x20);
    }
  }
  param_1[1] = 1;
  return;
}



void FUN_71019ea2ec(undefined8 *param_1)

{
  long *plVar1;
  
  FUN_71019ea1fc(param_1);
  if (DAT_7105a06420 == 0) {
    FUN_71005fbbd0((long)param_1);
    return;
  }
  plVar1 = FUN_71024ef490(DAT_7105a06420,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071019ea330. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



undefined8 * FUN_71019ea350(long *param_1)

{
  long lVar1;
  long *plVar2;
  undefined8 *puVar3;
  long lVar4;
  
  if (DAT_71040e3eb8 != (undefined8 *)0x0) {
    return DAT_71040e3eb8;
  }
  lVar4 = *DAT_7103a65db8;
  if (lVar4 == 0) {
    puVar3 = (undefined8 *)FUN_71005fbcb0(8,0x50);
  }
  else {
    plVar2 = param_1;
    if (param_1 == (long *)0x0) {
      lVar1 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar3 = (undefined8 *)(lVar4 + 8);
      if (lVar1 != 0) {
        puVar3 = (undefined8 *)(lVar1 + 0x88);
      }
      plVar2 = (long *)*puVar3;
      if (plVar2 == (long *)0x0) {
        puVar3 = (undefined8 *)0x0;
        goto LAB_71019ea3dc;
      }
    }
    puVar3 = (undefined8 *)(**(code **)(*plVar2 + 0x30))(plVar2,0x50,8);
  }
LAB_71019ea3dc:
  FUN_71024ea784(puVar3 + 6,param_1,3);
  puVar3[2] = 0;
  puVar3[3] = 0;
  DAT_71040e3eb0 = puVar3 + 6;
  puVar3[6] = &DAT_710398f570;
  puVar3[4] = 0;
  *(undefined1 *)(puVar3 + 5) = 0;
  *puVar3 = 0;
  puVar3[1] = 0;
  thunk_EXT_FUN_02e95df0();
  DAT_71040e3eb8 = puVar3;
  return puVar3;
}



void FUN_71019ea440(undefined8 *param_1)

{
  long lVar1;
  long *plVar2;
  long lVar3;
  long *plVar4;
  long lVar5;
  long lVar6;
  
  *param_1 = &DAT_710398f590;
  if (DAT_71040e3ec0 == param_1) {
    DAT_71040e3ec0 = (undefined8 *)0x0;
    *(undefined **)(DAT_71040e3ec8 + 0x60) = &DAT_710398f5b0;
    lVar6 = *(long *)(DAT_71040e3ec8 + 0x70);
    while (lVar6 != DAT_71040e3ec8 + 0x68) {
      lVar3 = *(long *)(lVar6 + 8);
      lVar1 = *(long *)(lVar6 + 0x10);
      plVar4 = *(long **)(lVar1 + 0x28);
      plVar2 = (long *)(lVar1 + 0x20);
      lVar5 = *plVar2;
      lVar6 = lVar3;
      if ((plVar4 != (long *)0x0 || lVar5 != 0) && (lVar3 = *(long *)(lVar1 + 0x38), lVar3 != 0)) {
        *(undefined8 *)(lVar1 + 0x38) = 0;
        if (lVar5 != 0) {
          *(long **)(lVar5 + 8) = plVar4;
          plVar4 = *(long **)(lVar1 + 0x28);
        }
        if (plVar4 != (long *)0x0) {
          *plVar4 = *plVar2;
        }
        *plVar2 = 0;
        *(undefined8 *)(lVar1 + 0x28) = 0;
        *(int *)(lVar3 + 0x10) = *(int *)(lVar3 + 0x10) + -1;
      }
    }
    DAT_71040e3ec8 = 0;
  }
  lVar6 = param_1[1];
  *param_1 = &DAT_7103a07950;
  if (lVar6 != 0) {
    if (lVar6 == 1) {
      return;
    }
    if ((*(uint *)(lVar6 + 200) & 1) == 0) {
      lVar3 = 0;
    }
    else {
      lVar3 = lVar6 + 0x88;
      thunk_EXT_FUN_02e95df0(lVar6 + 0xa8);
    }
    plVar2 = (long *)((long)*(int *)(lVar6 + 0x7c) + (long)param_1);
    if (*plVar2 != 0) {
      *(long *)(*plVar2 + 8) = plVar2[1];
    }
    if ((long *)plVar2[1] != (long *)0x0) {
      *(long *)plVar2[1] = *plVar2;
    }
    *plVar2 = 0;
    plVar2[1] = 0;
    *(int *)(lVar6 + 0x78) = *(int *)(lVar6 + 0x78) + -1;
    if (lVar3 != 0) {
      thunk_EXT_FUN_02e95df0(lVar3 + 0x20);
    }
  }
  param_1[1] = 1;
  return;
}



void FUN_71019ea588(undefined8 *param_1)

{
  long *plVar1;
  
  FUN_71019ea440(param_1);
  if (DAT_7105a06420 == 0) {
    FUN_71005fbbd0((long)param_1);
    return;
  }
  plVar1 = FUN_71024ef490(DAT_7105a06420,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071019ea5cc. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



undefined8 * FUN_71019ea5ec(long *param_1)

{
  long lVar1;
  long *plVar2;
  undefined8 *puVar3;
  long lVar4;
  
  if (DAT_71040e3ec8 != (undefined8 *)0x0) {
    return DAT_71040e3ec8;
  }
  lVar4 = *DAT_7103a65db8;
  if (lVar4 == 0) {
    puVar3 = (undefined8 *)FUN_71005fbcb0(8,0xa0);
  }
  else {
    plVar2 = param_1;
    if (param_1 == (long *)0x0) {
      lVar1 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar3 = (undefined8 *)(lVar4 + 8);
      if (lVar1 != 0) {
        puVar3 = (undefined8 *)(lVar1 + 0x88);
      }
      plVar2 = (long *)*puVar3;
      if (plVar2 == (long *)0x0) {
        puVar3 = (undefined8 *)0x0;
        goto LAB_71019ea678;
      }
    }
    puVar3 = (undefined8 *)(**(code **)(*plVar2 + 0x30))(plVar2,0xa0,8);
  }
LAB_71019ea678:
  FUN_71024ea784(puVar3 + 0x10,param_1,3);
  DAT_71040e3ec0 = puVar3 + 0x10;
  puVar3[0x10] = &DAT_710398f590;
  *(undefined4 *)(puVar3 + 6) = 0;
  *(undefined1 *)(puVar3 + 0xb) = 0;
  *puVar3 = 0x200000001;
  puVar3[1] = 0x23d4ccccd;
  puVar3[2] = 0x3d4ccccd00000006;
  puVar3[3] = 0x600000002;
  puVar3[4] = 0x3c0000001e;
  *(undefined4 *)(puVar3 + 0xf) = 0;
  *(undefined4 *)(puVar3 + 5) = 10;
  DAT_71040e3ec8 = puVar3;
  puVar3[9] = 0;
  puVar3[10] = 0x3c0000003c;
  puVar3[0xc] = &DAT_710398f5b0;
  puVar3[7] = 0;
  puVar3[8] = 0;
  puVar3[0xd] = puVar3 + 0xd;
  puVar3[0xe] = puVar3 + 0xd;
  return puVar3;
}



undefined8 FUN_71019ea888(long param_1,int param_2,uint param_3,uint param_4)

{
  bool bVar1;
  uint uVar2;
  ulong uVar3;
  long lVar4;
  undefined4 local_48;
  uint local_44;
  undefined8 local_40;
  undefined8 uStack_38;
  undefined1 uStack_11;
  
  if (param_1 != 0) {
    if (param_2 != -1) {
      local_44 = 0;
      local_40 = (undefined1 *)0xffffffff;
      uStack_38 = 0xffffffff00000000;
      FUN_7100ec0c48(&local_40,param_2,param_3);
      uVar2 = (int)local_40 - 1;
      if ((uVar2 < 8) && ((199U >> (ulong)(uVar2 & 0x1f) & 1) != 0)) {
        local_44 = *(uint *)(&DAT_71030baee0 + (long)(int)uVar2 * 4);
        lVar4 = *(long *)(&UNK_71032b47f8 + (long)(int)uVar2 * 8);
        local_48 = local_40._4_4_;
      }
      else {
        lVar4 = 0;
      }
      local_40 = &uStack_11;
      uVar3 = (*(code *)(&DAT_7103990700)[lVar4])(&local_40,&local_48);
      if ((uVar3 & 1) != 0) {
        *(undefined4 *)(param_1 + 0x670) = 1;
        bVar1 = FUN_7102493860(uVar3,(ulong *)&local_48);
        if (bVar1) {
          if (local_44 == 0xffffffff) {
                    // WARNING: Subroutine does not return
            FUN_7100c98d00();
          }
          local_40 = &uStack_11;
          uVar2 = (**(code **)(&DAT_7103990658 + (ulong)local_44 * 8))(&local_40,&local_48);
          if (((uVar2 < 9) && ((1 << (ulong)(uVar2 & 0x1f) & 0x18eU) != 0)) &&
             ((*(int *)(param_1 + 0x3c4) != -1 || (local_44 != 0xffffffff)))) {
            if (local_44 == 0xffffffff) {
              *(undefined4 *)(param_1 + 0x3c4) = 0xffffffff;
              return 1;
            }
            local_40 = (undefined1 *)(param_1 + 0x3c0);
            (**(code **)(&DAT_7103a04bc0 + (ulong)local_44 * 8))(&local_40,local_40,&local_48);
          }
        }
        return 1;
      }
    }
    if (param_4 < 300) {
      *(uint *)(param_1 + 0x3b0) = param_4;
      *(undefined4 *)(param_1 + 0x670) = 2;
    }
    else {
      *(undefined4 *)(param_1 + 0x670) = 0;
    }
  }
  return 0;
}



void FUN_71019eaa24(undefined8 *param_1)

{
  long *plVar1;
  long lVar2;
  long lVar3;
  
  *param_1 = &DAT_710398f5d0;
  if (DAT_71040e3ed0 == param_1) {
    DAT_71040e3ed0 = (undefined8 *)0x0;
    (**(code **)*DAT_71040e3ef8)();
    DAT_71040e3ef8 = (undefined8 *)0x0;
  }
  lVar2 = param_1[1];
  *param_1 = &DAT_7103a07950;
  if (lVar2 != 0) {
    if (lVar2 == 1) {
      return;
    }
    if ((*(uint *)(lVar2 + 200) & 1) == 0) {
      lVar3 = 0;
    }
    else {
      lVar3 = lVar2 + 0x88;
      thunk_EXT_FUN_02e95df0(lVar2 + 0xa8);
    }
    plVar1 = (long *)((long)*(int *)(lVar2 + 0x7c) + (long)param_1);
    if (*plVar1 != 0) {
      *(long *)(*plVar1 + 8) = plVar1[1];
    }
    if ((long *)plVar1[1] != (long *)0x0) {
      *(long *)plVar1[1] = *plVar1;
    }
    *plVar1 = 0;
    plVar1[1] = 0;
    *(int *)(lVar2 + 0x78) = *(int *)(lVar2 + 0x78) + -1;
    if (lVar3 != 0) {
      thunk_EXT_FUN_02e95df0(lVar3 + 0x20);
    }
  }
  param_1[1] = 1;
  return;
}



void FUN_71019eab08(undefined8 *param_1)

{
  long *plVar1;
  
  FUN_71019eaa24(param_1);
  if (DAT_7105a06420 == 0) {
    FUN_71005fbbd0((long)param_1);
    return;
  }
  plVar1 = FUN_71024ef490(DAT_7105a06420,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071019eab4c. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



undefined8 * FUN_71019eab6c(long *param_1)

{
  long lVar1;
  long *plVar2;
  undefined8 *puVar3;
  long lVar4;
  
  if (DAT_71040e3ef8 != (undefined8 *)0x0) {
    return DAT_71040e3ef8;
  }
  lVar4 = *DAT_7103a65db8;
  if (lVar4 == 0) {
    puVar3 = (undefined8 *)FUN_71005fbcb0(8,0x80);
  }
  else {
    plVar2 = param_1;
    if (param_1 == (long *)0x0) {
      lVar1 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar3 = (undefined8 *)(lVar4 + 8);
      if (lVar1 != 0) {
        puVar3 = (undefined8 *)(lVar1 + 0x88);
      }
      plVar2 = (long *)*puVar3;
      if (plVar2 == (long *)0x0) {
        puVar3 = (undefined8 *)0x0;
        goto LAB_71019eabf8;
      }
    }
    puVar3 = (undefined8 *)(**(code **)(*plVar2 + 0x30))(plVar2,0x80,8);
  }
LAB_71019eabf8:
  FUN_71024ea784(puVar3 + 0xc,param_1,3);
  *(undefined1 *)(puVar3 + 3) = 0;
  puVar3[0xc] = &DAT_710398f5d0;
  DAT_71040e3ed0 = puVar3 + 0xc;
  *puVar3 = &DAT_710398f5f0;
  puVar3[1] = &DAT_710398f610;
  *(undefined2 *)(puVar3 + 2) = 0x101;
  *(undefined4 *)((long)puVar3 + 0x14) = 0xfffffc19;
  FUN_710254e134(puVar3 + 4);
  DAT_71040e3ef8 = puVar3;
  return puVar3;
}



void FUN_71019ead10(long param_1)

{
  long *plVar1;
  ulong uVar2;
  long lVar3;
  undefined8 local_80;
  undefined4 uStack_78;
  char local_74;
  undefined4 local_70;
  undefined4 uStack_6c;
  undefined8 local_68;
  undefined4 local_60;
  char local_5c;
  undefined8 local_58;
  long local_50;
  undefined4 local_48;
  undefined1 local_44;
  undefined8 local_40;
  byte local_34 [4];
  
  plVar1 = DAT_7103a5bbd8;
  local_50 = 0;
  local_48 = 0;
  local_44 = 0;
  local_40 = 0xffffffff;
  FUN_7102de9fa0(*DAT_7103a5bbd8,&local_50,0x275391e9);
  thunk_EXT_FUN_02e95df0(param_1 + 0x40);
  if (((DAT_71040e86a0 != 0) && (*(int *)(DAT_71040e86a0 + 0x944) == 1)) &&
     (*(int *)(param_1 + 0x14) != *(int *)(DAT_71040e86a0 + 0x948))) {
    *(int *)(param_1 + 0x14) = *(int *)(DAT_71040e86a0 + 0x948);
    *(undefined1 *)(param_1 + 0x11) = *(undefined1 *)(param_1 + 0x10);
  }
  thunk_EXT_FUN_02e95df0(param_1 + 0x40);
  local_68._0_5_ = 0;
  local_68._5_3_ = 0;
  local_60 = 0;
  local_5c = '\0';
  local_58 = 0xffffffff;
  if (local_50 == 0) {
    FUN_7102de9fa0(*plVar1,&local_68,0x5cb9d7d5);
  }
  else {
    FUN_7102dea100(*plVar1,&local_68,&local_50,0x5cb9d7d5);
  }
  if (CONCAT35(local_68._5_3_,(undefined5)local_68) == 0) {
    lVar3 = *plVar1;
  }
  else {
    local_70 = 0xffffffff;
    uStack_6c = 0xf2d54c08;
    local_34[0] = 0;
    lVar3 = *plVar1;
    local_80._0_5_ = (undefined5)local_68;
    local_80._5_3_ = local_68._5_3_;
    uStack_78 = local_60;
    local_74 = local_5c;
    if (CONCAT35(local_68._5_3_,(undefined5)local_68) != 0) {
      if (local_5c == '\0') {
        uVar2 = FUN_7102dd9d60((long *)(lVar3 + 8),local_34,&local_80,0xf2d54c08);
      }
      else {
        uVar2 = FUN_7102dda1a0((long *)(lVar3 + 0x68),local_34,&local_80,0xf2d54c08);
      }
      if ((uVar2 & 1) == 0) {
        FUN_7102dd9eb0((long *)(lVar3 + 0x68),local_34,&local_80,0xf2d54c08,0);
      }
      goto LAB_71019eae88;
    }
  }
  local_34[0] = 0;
  FUN_7102dd9a00(lVar3,local_34,0xf2d54c08);
LAB_71019eae88:
  *(byte *)(param_1 + 0x10) = local_34[0];
  return;
}



long FUN_71019eaeb0(long param_1)

{
  thunk_EXT_FUN_02e95df0(param_1 + 0x38);
  if ((DAT_71040e86a0 != 0) && (*(int *)(DAT_71040e86a0 + 0x944) == 1)) {
    if (*(int *)(param_1 + 0xc) != *(int *)(DAT_71040e86a0 + 0x948)) {
      *(int *)(param_1 + 0xc) = *(int *)(DAT_71040e86a0 + 0x948);
      *(undefined1 *)(param_1 + 9) = *(undefined1 *)(param_1 + 8);
    }
  }
  thunk_EXT_FUN_02e95df0(param_1 + 0x38);
  return param_1 + 8;
}



void FUN_71019eaf20(long param_1)

{
  long lVar1;
  char cVar2;
  long *plVar3;
  long lVar4;
  int iVar5;
  undefined8 local_88;
  undefined5 uStack_80;
  undefined4 local_78;
  undefined4 uStack_74;
  undefined8 local_70;
  undefined4 local_68;
  undefined1 local_64;
  undefined8 local_60;
  long local_58;
  undefined4 local_50;
  undefined1 local_4c;
  undefined8 local_48;
  
  plVar3 = DAT_7103a5bbd8;
  local_58 = 0;
  local_50 = 0;
  local_4c = 0;
  local_48 = 0xffffffff;
  FUN_7102de9fa0(*DAT_7103a5bbd8,&local_58,0x275391e9);
  thunk_EXT_FUN_02e95df0(param_1 + 0x40);
  *(undefined1 *)(param_1 + 0x18) = 1;
  iVar5 = 0;
  if (*DAT_7103a5c098 != 0) {
    iVar5 = *(int *)(*DAT_7103a5c098 + 0x948);
  }
  lVar1 = 0x10;
  if (*(int *)(param_1 + 0x14) == iVar5) {
    lVar1 = 0x11;
  }
  thunk_EXT_FUN_02e95df0(param_1 + 0x40);
  local_70._0_5_ = 0;
  local_70._5_3_ = 0;
  local_68 = 0;
  local_64 = 0;
  local_60 = 0xffffffff;
  if (local_58 == 0) {
    FUN_7102de9fa0(*plVar3,&local_70,0x5cb9d7d5);
  }
  else {
    FUN_7102dea100(*plVar3,&local_70,&local_58,0x5cb9d7d5);
  }
  if (CONCAT35(local_70._5_3_,(undefined5)local_70) == 0) {
    cVar2 = *(char *)(param_1 + lVar1);
    lVar4 = *plVar3;
  }
  else {
    local_78 = 0xffffffff;
    uStack_74 = 0xf2d54c08;
    local_88._0_5_ = (undefined5)local_70;
    lVar4 = *plVar3;
    local_88._5_3_ = local_70._5_3_;
    uStack_80 = (undefined5)(CONCAT17(local_64,CONCAT43(local_68,local_70._5_3_)) >> 0x18);
    cVar2 = *(char *)(param_1 + lVar1);
    if (CONCAT35(local_70._5_3_,(undefined5)local_70) != 0) {
      FUN_7102dda930(lVar4,(uint)(cVar2 != '\0'),&local_88,0xf2d54c08);
      return;
    }
  }
  FUN_7102dda420(lVar4,(uint)(cVar2 != '\0'),0xf2d54c08);
  return;
}



long FUN_71019eb070(long param_1)

{
  long lVar1;
  int iVar2;
  
  thunk_EXT_FUN_02e95df0(param_1 + 0x38);
  *(undefined1 *)(param_1 + 0x10) = 1;
  iVar2 = 0;
  if (*DAT_7103a5c098 != 0) {
    iVar2 = *(int *)(*DAT_7103a5c098 + 0x948);
  }
  lVar1 = param_1 + 9;
  if (*(int *)(param_1 + 0xc) != iVar2) {
    lVar1 = param_1 + 8;
  }
  thunk_EXT_FUN_02e95df0(param_1 + 0x38);
  return lVar1;
}



undefined8 FUN_71019eb0d4(undefined8 param_1,undefined8 *param_2)

{
  int iVar1;
  
  if (((DAT_71040e3ef0 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_71040e3ef0), iVar1 != 0))
  {
    DAT_71040e3ee8 = &DAT_710398f660;
    thunk_EXT_FUN_02e95df0(&DAT_71040e3ef0);
  }
  if ((undefined **)param_2 != &DAT_71040e3ee8) {
    if (((DAT_71040e3ee0 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_71040e3ee0), iVar1 != 0)
       ) {
      DAT_71040e3ed8 = DAT_7103a59af0 + 0x10;
      thunk_EXT_FUN_02e95df0(&DAT_71040e3ee0);
    }
    if (param_2 != &DAT_71040e3ed8) {
      param_1 = 0;
    }
  }
  return param_1;
}



undefined8 * FUN_71019eb1b8(void)

{
  int iVar1;
  
  if (((DAT_71040e3ef0 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_71040e3ef0), iVar1 != 0))
  {
    DAT_71040e3ee8 = &DAT_710398f660;
    thunk_EXT_FUN_02e95df0(&DAT_71040e3ef0);
  }
  return &DAT_71040e3ee8;
}



void FUN_71019eb210(undefined8 *param_1)

{
  long *plVar1;
  
  *param_1 = &DAT_710398f610;
  FUN_710254e2d4(param_1 + 3);
  if (DAT_7105a06420 == 0) {
    FUN_71005fbbd0((long)param_1);
    return;
  }
  plVar1 = FUN_71024ef490(DAT_7105a06420,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071019eb260. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



bool FUN_71019eb4b4(uint *param_1,uint param_2,uint param_3,uint *param_4)

{
  uint *puVar1;
  uint *puVar2;
  uint uVar3;
  long *plVar4;
  bool bVar5;
  int iVar6;
  ulong uVar7;
  long lVar8;
  uint uVar9;
  uint uVar10;
  undefined8 *puVar11;
  uint *puVar12;
  uint *puVar13;
  undefined8 uStack_98;
  long *local_90;
  uint local_88;
  uint local_84;
  long local_80;
  long local_78;
  uint local_70 [2];
  long local_68;
  
  local_88 = param_2;
  FUN_71015081f0(&uStack_98,&local_88);
  plVar4 = local_90;
  if (local_90 == (long *)0x0) goto LAB_71019ebd8c;
  *(undefined1 *)((long)(int)local_90[1] + *local_90 + -1) = 0;
  if (local_90 == (long *)0x0) {
    puVar12 = param_1;
    if (*(char *)*local_90 == '\0') {
      uVar10 = 0xffffffff;
      goto LAB_71019ebc0c;
    }
  }
  else {
    uVar10 = *(uint *)((long)local_90 + 0x54);
    if (*(char *)*local_90 == '\0') {
LAB_71019ebc0c:
      FUN_71019ec04c((int *)param_1,uVar10);
      goto LAB_71019ebd8c;
    }
    puVar12 = param_1 + (ulong)uVar10 * 2;
    if (7 < uVar10) {
      puVar12 = param_1;
    }
  }
  if ((*puVar12 != 0) && (puVar12[0] = 0, puVar12[1] = 0, param_1[0x11] != 0)) {
    uVar10 = 0;
    if (local_90 != (long *)0x0) {
      if (*(int *)((long)local_90 + 0x54) == -1) {
        uVar10 = 0;
      }
      else {
        uVar10 = *(uint *)(&DAT_71030baaa0 + (long)*(int *)((long)local_90 + 0x54) * 4);
      }
    }
    *puVar12 = uVar10;
  }
  puVar1 = param_1 + 0x11;
  puVar13 = param_1 + 0x14;
  uVar10 = *param_1;
  if (uVar10 == 0) {
    if ((*puVar1 != 0) && (FUN_710150bf70((undefined8 *)local_70,puVar1), local_68 != 0)) {
      local_80 = DAT_7103a61968 + 0x10;
      local_78 = 0;
      uVar7 = FUN_710150d040((long)local_70,0,(long)&local_80);
      if ((uVar7 & 1) != 0) {
        puVar2 = DAT_7103a5d098;
        if (local_78 != 0) {
          puVar2 = (uint *)(local_78 + 0x50);
        }
        local_84 = *puVar2;
        uVar10 = local_84;
        if (local_84 != 0) goto LAB_71019eb590;
      }
    }
  }
  else if (uVar10 != 0x1854f7fd) {
LAB_71019eb590:
    local_84 = uVar10;
    FUN_71015081f0((undefined8 *)local_70,&local_84);
    if (((local_68 != 0) && (bVar5 = FUN_7101508a04((long)&uStack_98,(long)local_70), !bVar5)) &&
       (param_1[0] = 0, param_1[1] = 0, param_1[0x11] != 0)) {
      *param_1 = 0x1854f7fd;
    }
  }
  uVar10 = param_1[2];
  if (uVar10 != 0xd991f16c) {
    if (uVar10 == 0) {
      if ((*puVar1 != 0) && (FUN_710150bf70((undefined8 *)local_70,puVar1), local_68 != 0)) {
        local_80 = DAT_7103a61968 + 0x10;
        local_78 = 0;
        uVar7 = FUN_710150d040((long)local_70,1,(long)&local_80);
        if ((uVar7 & 1) != 0) {
          puVar2 = DAT_7103a5d098;
          if (local_78 != 0) {
            puVar2 = (uint *)(local_78 + 0x50);
          }
          local_84 = *puVar2;
          uVar10 = local_84;
          if (local_84 != 0) goto LAB_71019eb6b8;
        }
      }
    }
    else {
LAB_71019eb6b8:
      local_84 = uVar10;
      FUN_71015081f0((undefined8 *)local_70,&local_84);
      if ((local_68 != 0) && (bVar5 = FUN_7101508a04((long)&uStack_98,(long)local_70), !bVar5)) {
        param_1[2] = 0;
        param_1[3] = 0;
        if (param_1[0x11] != 0) {
          param_1[2] = 0xd991f16c;
        }
        *puVar13 = *DAT_7103a5d058;
      }
    }
  }
  uVar10 = param_1[4];
  if (uVar10 != 0xce9a5baa) {
    if (uVar10 == 0) {
      if ((*puVar1 != 0) && (FUN_710150bf70((undefined8 *)local_70,puVar1), local_68 != 0)) {
        local_80 = DAT_7103a61968 + 0x10;
        local_78 = 0;
        uVar7 = FUN_710150d040((long)local_70,2,(long)&local_80);
        if ((uVar7 & 1) != 0) {
          puVar2 = DAT_7103a5d098;
          if (local_78 != 0) {
            puVar2 = (uint *)(local_78 + 0x50);
          }
          local_84 = *puVar2;
          uVar10 = local_84;
          if (local_84 != 0) goto LAB_71019eb780;
        }
      }
    }
    else {
LAB_71019eb780:
      local_84 = uVar10;
      FUN_71015081f0((undefined8 *)local_70,&local_84);
      if ((local_68 != 0) && (bVar5 = FUN_7101508a04((long)&uStack_98,(long)local_70), !bVar5)) {
        param_1[4] = 0;
        param_1[5] = 0;
        if (param_1[0x11] != 0) {
          param_1[4] = 0xce9a5baa;
        }
        *puVar13 = *DAT_7103a5d058;
      }
    }
  }
  uVar10 = param_1[6];
  if (uVar10 == 0) {
    if ((*puVar1 != 0) && (FUN_710150bf70((undefined8 *)local_70,puVar1), local_68 != 0)) {
      local_80 = DAT_7103a61968 + 0x10;
      local_78 = 0;
      uVar7 = FUN_710150d040((long)local_70,3,(long)&local_80);
      if ((uVar7 & 1) != 0) {
        puVar2 = DAT_7103a5d098;
        if (local_78 != 0) {
          puVar2 = (uint *)(local_78 + 0x50);
        }
        local_84 = *puVar2;
        uVar10 = local_84;
        if (local_84 != 0) goto LAB_71019eb7e4;
      }
    }
  }
  else if (uVar10 != 0x4197b1e0) {
LAB_71019eb7e4:
    local_84 = uVar10;
    FUN_71015081f0((undefined8 *)local_70,&local_84);
    if ((local_68 != 0) && (bVar5 = FUN_7101508a04((long)&uStack_98,(long)local_70), !bVar5)) {
      param_1[6] = 0;
      param_1[7] = 0;
      if (param_1[0x11] != 0) {
        param_1[6] = 0x4197b1e0;
      }
      param_1[0x15] = *DAT_7103a5d058;
    }
  }
  uVar10 = param_1[8];
  if (uVar10 != 0xbf69f85a) {
    if (uVar10 == 0) {
      if ((*puVar1 != 0) && (FUN_710150bf70((undefined8 *)local_70,puVar1), local_68 != 0)) {
        local_80 = DAT_7103a61968 + 0x10;
        local_78 = 0;
        uVar7 = FUN_710150d040((long)local_70,4,(long)&local_80);
        if ((uVar7 & 1) != 0) {
          puVar2 = DAT_7103a5d098;
          if (local_78 != 0) {
            puVar2 = (uint *)(local_78 + 0x50);
          }
          local_84 = *puVar2;
          uVar10 = local_84;
          if (local_84 != 0) goto LAB_71019eb914;
        }
      }
    }
    else {
LAB_71019eb914:
      local_84 = uVar10;
      FUN_71015081f0((undefined8 *)local_70,&local_84);
      if (((local_68 != 0) && (bVar5 = FUN_7101508a04((long)&uStack_98,(long)local_70), !bVar5)) &&
         (param_1[8] = 0, param_1[9] = 0, param_1[0x11] != 0)) {
        param_1[8] = 0xbf69f85a;
      }
    }
  }
  uVar10 = param_1[10];
  if (uVar10 != 0x9ea25ecf) {
    if (uVar10 == 0) {
      if ((*puVar1 != 0) && (FUN_710150bf70((undefined8 *)local_70,puVar1), local_68 != 0)) {
        local_80 = DAT_7103a61968 + 0x10;
        local_78 = 0;
        uVar7 = FUN_710150d040((long)local_70,5,(long)&local_80);
        if ((uVar7 & 1) != 0) {
          puVar2 = DAT_7103a5d098;
          if (local_78 != 0) {
            puVar2 = (uint *)(local_78 + 0x50);
          }
          local_84 = *puVar2;
          uVar10 = local_84;
          if (local_84 != 0) goto LAB_71019eb9cc;
        }
      }
    }
    else {
LAB_71019eb9cc:
      local_84 = uVar10;
      FUN_71015081f0((undefined8 *)local_70,&local_84);
      if (((local_68 != 0) && (bVar5 = FUN_7101508a04((long)&uStack_98,(long)local_70), !bVar5)) &&
         (param_1[10] = 0, param_1[0xb] = 0, param_1[0x11] != 0)) {
        param_1[10] = 0x9ea25ecf;
      }
    }
  }
  uVar10 = param_1[0xc];
  if (uVar10 != 0xce76cbad) {
    if (uVar10 == 0) {
      if ((*puVar1 != 0) && (FUN_710150bf70((undefined8 *)local_70,puVar1), local_68 != 0)) {
        local_80 = DAT_7103a61968 + 0x10;
        local_78 = 0;
        uVar7 = FUN_710150d040((long)local_70,6,(long)&local_80);
        if ((uVar7 & 1) != 0) {
          puVar2 = DAT_7103a5d098;
          if (local_78 != 0) {
            puVar2 = (uint *)(local_78 + 0x50);
          }
          local_84 = *puVar2;
          uVar10 = local_84;
          if (local_84 != 0) goto LAB_71019eba84;
        }
      }
    }
    else {
LAB_71019eba84:
      local_84 = uVar10;
      FUN_71015081f0((undefined8 *)local_70,&local_84);
      if (((local_68 != 0) && (bVar5 = FUN_7101508a04((long)&uStack_98,(long)local_70), !bVar5)) &&
         (param_1[0xc] = 0, param_1[0xd] = 0, param_1[0x11] != 0)) {
        param_1[0xc] = 0xce76cbad;
      }
    }
  }
  uVar10 = param_1[0xe];
  if (uVar10 == 0) {
    if ((*puVar1 != 0) && (FUN_710150bf70((undefined8 *)local_70,puVar1), local_68 != 0)) {
      local_80 = DAT_7103a61968 + 0x10;
      local_78 = 0;
      uVar7 = FUN_710150d040((long)local_70,7,(long)&local_80);
      if ((uVar7 & 1) != 0) {
        puVar2 = DAT_7103a5d098;
        if (local_78 != 0) {
          puVar2 = (uint *)(local_78 + 0x50);
        }
        local_84 = *puVar2;
        uVar10 = local_84;
        if (local_84 != 0) goto LAB_71019ebad8;
      }
    }
  }
  else if (uVar10 != 0x45e11c6) {
LAB_71019ebad8:
    local_84 = uVar10;
    FUN_71015081f0((undefined8 *)local_70,&local_84);
    if ((local_68 != 0) && (bVar5 = FUN_7101508a04((long)&uStack_98,(long)local_70), !bVar5)) {
      param_1[0xe] = 0;
      param_1[0xf] = 0;
      if (param_1[0x11] != 0) {
        param_1[0xe] = 0x45e11c6;
      }
      param_1[0x16] = *DAT_7103a5d058;
    }
  }
  *puVar12 = local_88;
  if (local_90 == (long *)0x0) {
    uVar10 = 0xffffffff;
  }
  else {
    uVar10 = *(uint *)((long)local_90 + 0x54);
  }
  FUN_71019ebdf4(param_1,uVar10,param_3 & ((int)param_3 >> 0x1f ^ 0xffffffffU));
  if (local_90 != (long *)0x0) {
    iVar6 = *(int *)((long)local_90 + 0x54);
    if ((int)local_90[0xd] == 1) {
      uVar10 = *param_4;
    }
    else {
      uVar10 = *DAT_7103a5d058;
    }
    if (((iVar6 - 1U < 2) || (puVar13 = param_1 + 0x16, iVar6 == 7)) ||
       (puVar13 = param_1 + 0x15, iVar6 == 3)) {
      *puVar13 = uVar10;
    }
  }
  uVar10 = param_1[0x10];
  puVar11 = *(undefined8 **)(*DAT_7103a59ec8 + 0x28);
  lVar8 = 0;
  if (puVar11 != (undefined8 *)0x0) {
    if (((*DAT_7103a61988 & 1) == 0) && (iVar6 = thunk_EXT_FUN_02e95df0(DAT_7103a61988), iVar6 != 0)
       ) {
      *DAT_7103a61980 = DAT_7103a59e80 + 0x10;
      thunk_EXT_FUN_02e95df0(DAT_7103a61988);
    }
    lVar8 = (**(code **)*puVar11)(puVar11,DAT_7103a61980);
  }
  uVar3 = param_1[4];
  if (uVar3 == 0) {
    uVar9 = 0;
    if (*puVar1 != 0) {
      FUN_710150bf70((undefined8 *)local_70,puVar1);
      if (local_68 != 0) {
        local_80 = DAT_7103a61968 + 0x10;
        local_78 = 0;
        uVar7 = FUN_710150d040((long)local_70,2,(long)&local_80);
        if ((uVar7 & 1) != 0) {
          puVar12 = DAT_7103a5d098;
          if (local_78 != 0) {
            puVar12 = (uint *)(local_78 + 0x50);
          }
          uVar9 = *puVar12;
          goto LAB_71019ebce8;
        }
      }
      uVar9 = 0;
    }
  }
  else {
    uVar9 = 0;
    if (uVar3 != 0xce9a5baa) {
      uVar9 = uVar3;
    }
  }
LAB_71019ebce8:
  uVar3 = param_1[6];
  local_84 = uVar9;
  if (uVar3 == 0) {
    local_70[0] = 0;
    if (*puVar1 != 0) {
      FUN_710150bf70((undefined8 *)local_70,puVar1);
      if (local_68 != 0) {
        local_80 = DAT_7103a61968 + 0x10;
        local_78 = 0;
        uVar7 = FUN_710150d040((long)local_70,3,(long)&local_80);
        if ((uVar7 & 1) != 0) {
          puVar12 = DAT_7103a5d098;
          if (local_78 != 0) {
            puVar12 = (uint *)(local_78 + 0x50);
          }
          local_70[0] = *puVar12;
          goto LAB_71019ebd64;
        }
      }
      local_70[0] = 0;
    }
  }
  else {
    local_70[0] = 0;
    if (uVar3 != 0x4197b1e0) {
      local_70[0] = uVar3;
    }
  }
LAB_71019ebd64:
  bVar5 = FUN_710150b3c0(lVar8,&local_84,local_70,(uint)((char)uVar10 != '\0'));
  *(bool *)(param_1 + 0x10) = bVar5;
LAB_71019ebd8c:
  return plVar4 != (long *)0x0;
}



void FUN_71019ebdf4(uint *param_1,uint param_2,uint param_3)

{
  uint *puVar1;
  ulong uVar2;
  uint uVar3;
  short *psVar4;
  uint uVar5;
  long lVar6;
  long lVar7;
  ulong uVar8;
  uint *puVar9;
  long local_60;
  long local_58;
  undefined8 uStack_50;
  long local_48;
  uint local_24;
  
  if (param_2 == 0xffffffff) {
    return;
  }
  if ((int)param_3 < 0) {
    return;
  }
  uVar8 = (ulong)param_2;
  if (param_2 < 8) {
    puVar9 = param_1 + (ulong)param_2 * 2;
    uVar5 = *puVar9;
    if (uVar5 != 0) goto LAB_71019ebe38;
LAB_71019ebf34:
    if ((param_1[0x11] != 0) && (FUN_710150bf70(&uStack_50,param_1 + 0x11), local_48 != 0)) {
      local_60 = DAT_7103a61968 + 0x10;
      local_58 = 0;
      uVar2 = FUN_710150d040((long)&uStack_50,uVar8,(long)&local_60);
      if ((uVar2 & 1) == 0) goto LAB_71019ebf98;
      puVar1 = DAT_7103a5d098;
      if (local_58 != 0) {
        puVar1 = (uint *)(local_58 + 0x50);
      }
      local_24 = *puVar1;
      uVar5 = local_24;
      if (local_24 == 0) goto LAB_71019ebf98;
      goto LAB_71019ebe60;
    }
LAB_71019ebf98:
    uVar5 = 0;
  }
  else {
    uVar5 = *param_1;
    puVar9 = param_1;
    if (uVar5 == 0) goto LAB_71019ebf34;
LAB_71019ebe38:
    if ((uVar8 != 0xffffffff) &&
       (uVar5 == *(uint *)(&DAT_71030baaa0 +
                          (-(ulong)(param_2 >> 0x1f) & 0xfffffffc00000000 | uVar8 << 2))))
    goto LAB_71019ebf98;
LAB_71019ebe60:
    local_24 = uVar5;
    FUN_71015081f0(&uStack_50,&local_24);
    if ((local_48 == 0) || (uVar5 = *(uint *)(local_48 + 100), (int)uVar5 < 0)) goto LAB_71019ebf98;
    lVar7 = 0x460;
    if (*(uint *)(**(long **)(DAT_71040e6118 + 0xa8) + 0x10) < 0x1d) {
      lVar7 = 0;
    }
    lVar6 = *(long *)(*(long *)(**(long **)(DAT_71040e6118 + 0xa8) + 0x18) + lVar7 + 0x20);
    lVar7 = *(long *)(lVar6 + 0x28);
    if (*(uint *)(lVar6 + 0x20) <= uVar5) {
      uVar5 = 0;
    }
    if ((*(byte *)(lVar7 + (ulong)uVar5 * 0x48 + 0x14) & 0xf7) == 0xc0) {
      lVar7 = lVar7 + (ulong)uVar5 * 0x48;
      psVar4 = *(short **)(lVar7 + 8);
      uVar3 = *(uint *)((long)psVar4 + (ulong)*(uint *)(lVar7 + 0x10));
      uVar5 = uVar3 >> 8;
      if (*psVar4 == 0x5942) {
        uVar5 = uVar5 & 0xff00 | uVar3 >> 0x18 | (uVar5 & 0xff) << 0x10;
      }
    }
    else {
      uVar5 = 0;
    }
    if (0x10 < uVar5) {
      uVar5 = 0x11;
    }
  }
  if (uVar5 < 2) {
    uVar5 = 1;
  }
  if (((uVar5 < 2) || (param_1[0x11] == 0)) || (*puVar9 != 0)) goto LAB_71019ec01c;
  FUN_710150bf70(&uStack_50,param_1 + 0x11);
  if (local_48 == 0) {
LAB_71019ec014:
    uVar3 = 0;
  }
  else {
    local_60 = DAT_7103a61968 + 0x10;
    local_58 = 0;
    uVar8 = FUN_710150d040((long)&uStack_50,uVar8,(long)&local_60);
    if ((uVar8 & 1) == 0) goto LAB_71019ec014;
    puVar1 = DAT_7103a5d098;
    if (local_58 != 0) {
      puVar1 = (uint *)(local_58 + 0x50);
    }
    uVar3 = *puVar1;
  }
  *puVar9 = uVar3;
LAB_71019ec01c:
  if ((int)(uVar5 - 1) <= (int)param_3) {
    param_3 = uVar5 - 1;
  }
  puVar9[1] = param_3;
  return;
}



void FUN_71019ec04c(int *param_1,uint param_2)

{
  int *piVar1;
  uint *puVar2;
  uint uVar3;
  bool bVar4;
  int iVar5;
  ulong uVar6;
  long lVar7;
  int iVar8;
  int *piVar9;
  uint *puVar10;
  ulong uVar11;
  undefined8 *puVar12;
  uint local_54;
  long local_50;
  long local_48;
  uint local_40 [2];
  long local_38;
  
  if (param_2 == 0xffffffff) {
    return;
  }
  if (param_2 < 8) {
    piVar1 = param_1 + (ulong)param_2 * 2;
    iVar8 = *piVar1;
  }
  else {
    iVar8 = *param_1;
    piVar1 = param_1;
  }
  if (iVar8 != 0) {
    piVar1[0] = 0;
    piVar1[1] = 0;
    if (param_2 - 1 < 2) {
      piVar9 = param_1 + 0x14;
    }
    else if (param_2 == 3) {
      piVar9 = param_1 + 0x15;
    }
    else {
      if (param_2 != 7) goto LAB_71019ec0c4;
      piVar9 = param_1 + 0x16;
    }
    *piVar9 = *DAT_7103a5d058;
  }
LAB_71019ec0c4:
  puVar10 = (uint *)(param_1 + 0x11);
  if (*puVar10 != 0) {
    uVar11 = (ulong)param_2;
    FUN_710150bf70((undefined8 *)local_40,puVar10);
    uVar6 = FUN_710150d230((long)local_40,uVar11);
    if ((uVar6 & 1) != 0) {
      if (uVar11 == 0xffffffff) {
        iVar8 = 0;
      }
      else {
        iVar8 = *(int *)(&DAT_71030baaa0 +
                        (-(ulong)(param_2 >> 0x1f) & 0xfffffffc00000000 | uVar11 << 2));
      }
      *piVar1 = iVar8;
    }
  }
  iVar8 = param_1[0x10];
  puVar12 = *(undefined8 **)(*DAT_7103a59ec8 + 0x28);
  lVar7 = 0;
  if (puVar12 != (undefined8 *)0x0) {
    if (((*DAT_7103a61988 & 1) == 0) && (iVar5 = thunk_EXT_FUN_02e95df0(DAT_7103a61988), iVar5 != 0)
       ) {
      *DAT_7103a61980 = DAT_7103a59e80 + 0x10;
      thunk_EXT_FUN_02e95df0(DAT_7103a61988);
    }
    lVar7 = (**(code **)*puVar12)(puVar12,DAT_7103a61980);
  }
  uVar3 = param_1[4];
  if (uVar3 == 0) {
    local_54 = 0;
    if (*puVar10 != 0) {
      FUN_710150bf70((undefined8 *)local_40,puVar10);
      if (local_38 != 0) {
        local_50 = DAT_7103a61968 + 0x10;
        local_48 = 0;
        uVar6 = FUN_710150d040((long)local_40,2,(long)&local_50);
        if ((uVar6 & 1) != 0) {
          puVar2 = DAT_7103a5d098;
          if (local_48 != 0) {
            puVar2 = (uint *)(local_48 + 0x50);
          }
          local_54 = *puVar2;
          goto LAB_71019ec1d4;
        }
      }
      local_54 = 0;
    }
  }
  else {
    local_54 = 0;
    if (uVar3 != 0xce9a5baa) {
      local_54 = uVar3;
    }
  }
LAB_71019ec1d4:
  uVar3 = param_1[6];
  if (uVar3 == 0) {
    local_40[0] = 0;
    if (*puVar10 != 0) {
      FUN_710150bf70((undefined8 *)local_40,puVar10);
      if (local_38 != 0) {
        local_50 = DAT_7103a61968 + 0x10;
        local_48 = 0;
        uVar6 = FUN_710150d040((long)local_40,3,(long)&local_50);
        if ((uVar6 & 1) != 0) {
          puVar10 = DAT_7103a5d098;
          if (local_48 != 0) {
            puVar10 = (uint *)(local_48 + 0x50);
          }
          local_40[0] = *puVar10;
          goto LAB_71019ec258;
        }
      }
      local_40[0] = 0;
    }
  }
  else {
    local_40[0] = 0;
    if (uVar3 != 0x4197b1e0) {
      local_40[0] = uVar3;
    }
  }
LAB_71019ec258:
  bVar4 = FUN_710150b3c0(lVar7,&local_54,local_40,(uint)((char)iVar8 != '\0'));
  *(bool *)(param_1 + 0x10) = bVar4;
  return;
}



void FUN_71019ec2e4(long param_1,uint param_2)

{
  uint *puVar1;
  uint uVar2;
  bool bVar3;
  int iVar4;
  long lVar5;
  ulong uVar6;
  undefined8 *puVar7;
  long local_50;
  long local_48;
  uint local_40 [2];
  long local_38;
  uint local_14;
  
  puVar7 = *(undefined8 **)(*DAT_7103a59ec8 + 0x28);
  lVar5 = 0;
  if (puVar7 != (undefined8 *)0x0) {
    if (((*DAT_7103a61988 & 1) == 0) && (iVar4 = thunk_EXT_FUN_02e95df0(DAT_7103a61988), iVar4 != 0)
       ) {
      *DAT_7103a61980 = DAT_7103a59e80 + 0x10;
      thunk_EXT_FUN_02e95df0(DAT_7103a61988);
    }
    lVar5 = (**(code **)*puVar7)(puVar7,DAT_7103a61980);
  }
  uVar2 = *(uint *)(param_1 + 0x10);
  if (uVar2 == 0) {
    local_14 = 0;
    if (*(uint *)(param_1 + 0x44) != 0) {
      FUN_710150bf70((undefined8 *)local_40,(uint *)(param_1 + 0x44));
      if (local_38 != 0) {
        local_50 = DAT_7103a61968 + 0x10;
        local_48 = 0;
        uVar6 = FUN_710150d040((long)local_40,2,(long)&local_50);
        if ((uVar6 & 1) != 0) {
          puVar1 = DAT_7103a5d098;
          if (local_48 != 0) {
            puVar1 = (uint *)(local_48 + 0x50);
          }
          local_14 = *puVar1;
          goto LAB_71019ec3c0;
        }
      }
      local_14 = 0;
    }
  }
  else {
    local_14 = 0;
    if (uVar2 != 0xce9a5baa) {
      local_14 = uVar2;
    }
  }
LAB_71019ec3c0:
  uVar2 = *(uint *)(param_1 + 0x18);
  if (uVar2 == 0) {
    local_40[0] = 0;
    if (*(uint *)(param_1 + 0x44) != 0) {
      FUN_710150bf70((undefined8 *)local_40,(uint *)(param_1 + 0x44));
      if (local_38 != 0) {
        local_50 = DAT_7103a61968 + 0x10;
        local_48 = 0;
        uVar6 = FUN_710150d040((long)local_40,3,(long)&local_50);
        if ((uVar6 & 1) != 0) {
          puVar1 = DAT_7103a5d098;
          if (local_48 != 0) {
            puVar1 = (uint *)(local_48 + 0x50);
          }
          local_40[0] = *puVar1;
          goto LAB_71019ec444;
        }
      }
      local_40[0] = 0;
    }
  }
  else {
    local_40[0] = 0;
    if (uVar2 != 0x4197b1e0) {
      local_40[0] = uVar2;
    }
  }
LAB_71019ec444:
  bVar3 = FUN_710150b3c0(lVar5,&local_14,local_40,param_2 & 1);
  *(bool *)(param_1 + 0x40) = bVar3;
  return;
}



bool FUN_71019ec4c0(uint *param_1,uint *param_2,uint param_3)

{
  uint uVar1;
  byte bVar2;
  long *plVar3;
  bool bVar4;
  int iVar5;
  ulong uVar6;
  uint uVar7;
  long lVar8;
  uint *puVar9;
  uint *puVar10;
  uint uVar11;
  ulong uVar12;
  uint *puVar13;
  undefined8 *puVar14;
  uint *puVar15;
  uint *puVar16;
  uint *puVar17;
  uint *puVar18;
  undefined8 uStack_98;
  long *local_90;
  uint local_84;
  long local_80;
  long local_78;
  long local_70;
  long local_68;
  
  FUN_710150bf70(&uStack_98,param_2);
  plVar3 = local_90;
  if (local_90 == (long *)0x0) goto LAB_71019ecc60;
  *(undefined1 *)((long)(int)local_90[1] + *local_90 + -1) = 0;
  if (*(char *)*local_90 == '\0') {
    uVar11 = param_1[0x10];
    puVar13 = param_1 + 0x11;
    puVar13[0] = 0;
    puVar13[1] = 0;
    puVar14 = *(undefined8 **)(*DAT_7103a59ec8 + 0x28);
    lVar8 = 0;
    if (puVar14 != (undefined8 *)0x0) {
      if (((*DAT_7103a61988 & 1) == 0) &&
         (iVar5 = thunk_EXT_FUN_02e95df0(DAT_7103a61988), iVar5 != 0)) {
        *DAT_7103a61980 = DAT_7103a59e80 + 0x10;
        thunk_EXT_FUN_02e95df0(DAT_7103a61988);
      }
      lVar8 = (**(code **)*puVar14)(puVar14,DAT_7103a61980);
    }
    uVar1 = param_1[4];
    if (uVar1 == 0) {
      local_84 = 0;
      if (*puVar13 != 0) {
        FUN_710150bf70(&local_70,puVar13);
        if (local_68 != 0) {
          local_80 = DAT_7103a61968 + 0x10;
          local_78 = 0;
          uVar12 = FUN_710150d040((long)&local_70,2,(long)&local_80);
          if ((uVar12 & 1) != 0) {
            puVar10 = DAT_7103a5d098;
            if (local_78 != 0) {
              puVar10 = (uint *)(local_78 + 0x50);
            }
            local_84 = *puVar10;
            goto LAB_71019ecbb4;
          }
        }
        local_84 = 0;
      }
    }
    else {
      local_84 = 0;
      if (uVar1 != 0xce9a5baa) {
        local_84 = uVar1;
      }
    }
LAB_71019ecbb4:
    uVar1 = param_1[6];
    if (uVar1 == 0) {
      uVar7 = 0;
      if (*puVar13 != 0) {
        FUN_710150bf70(&local_70,puVar13);
        if (local_68 != 0) {
          local_80 = DAT_7103a61968 + 0x10;
          local_78 = 0;
          uVar12 = FUN_710150d040((long)&local_70,3,(long)&local_80);
          if ((uVar12 & 1) != 0) {
            puVar13 = DAT_7103a5d098;
            if (local_78 != 0) {
              puVar13 = (uint *)(local_78 + 0x50);
            }
            uVar7 = *puVar13;
            goto LAB_71019ecc38;
          }
        }
        uVar7 = 0;
      }
    }
    else {
      uVar7 = 0;
      if (uVar1 != 0x4197b1e0) {
        uVar7 = uVar1;
      }
    }
LAB_71019ecc38:
    local_70 = CONCAT44(local_70._4_4_,uVar7);
    bVar4 = FUN_710150b3c0(lVar8,&local_84,(uint *)&local_70,(uint)((char)uVar11 != '\0'));
  }
  else {
    if (*param_1 == 0x1854f7fd) {
      param_1[0] = 0;
      param_1[1] = 0;
    }
    puVar13 = param_1 + 2;
    if (*puVar13 == 0xd991f16c) {
      param_1[2] = 0;
      param_1[3] = 0;
    }
    puVar10 = param_1 + 4;
    if (*puVar10 == 0xce9a5baa) {
      param_1[4] = 0;
      param_1[5] = 0;
    }
    puVar9 = param_1 + 6;
    if (*puVar9 == 0x4197b1e0) {
      param_1[6] = 0;
      param_1[7] = 0;
    }
    puVar15 = param_1 + 8;
    if (*puVar15 == 0xbf69f85a) {
      param_1[8] = 0;
      param_1[9] = 0;
    }
    puVar16 = param_1 + 10;
    if (*puVar16 == 0x9ea25ecf) {
      param_1[10] = 0;
      param_1[0xb] = 0;
    }
    puVar17 = param_1 + 0xc;
    if (*puVar17 == 0xce76cbad) {
      param_1[0xc] = 0;
      param_1[0xd] = 0;
    }
    puVar18 = param_1 + 0xe;
    if (*puVar18 == 0x45e11c6) {
      param_1[0xe] = 0;
      param_1[0xf] = 0;
    }
    uVar12 = 0;
    lVar8 = DAT_7103a61968 + 0x10;
    do {
      local_68 = 0;
      local_70 = lVar8;
      uVar6 = FUN_710150d040((long)&uStack_98,uVar12,(long)&local_70);
      if ((uVar6 & 1) != 0) {
        if (((*param_1 != 0) && (FUN_71015081f0(&local_80,param_1), local_78 != 0)) &&
           (bVar4 = FUN_7101508a04((long)&local_70,(long)&local_80), !bVar4)) {
          param_1[0] = 0;
          param_1[1] = 0;
        }
        if (((*puVar13 != 0) && (FUN_71015081f0(&local_80,puVar13), local_78 != 0)) &&
           (bVar4 = FUN_7101508a04((long)&local_70,(long)&local_80), !bVar4)) {
          param_1[2] = 0;
          param_1[3] = 0;
          param_1[0x14] = *DAT_7103a5d058;
        }
        if (((*puVar10 != 0) && (FUN_71015081f0(&local_80,puVar10), local_78 != 0)) &&
           (bVar4 = FUN_7101508a04((long)&local_70,(long)&local_80), !bVar4)) {
          param_1[4] = 0;
          param_1[5] = 0;
          param_1[0x14] = *DAT_7103a5d058;
        }
        if (((*puVar9 != 0) && (FUN_71015081f0(&local_80,puVar9), local_78 != 0)) &&
           (bVar4 = FUN_7101508a04((long)&local_70,(long)&local_80), !bVar4)) {
          param_1[6] = 0;
          param_1[7] = 0;
          param_1[0x15] = *DAT_7103a5d058;
        }
        if (((*puVar15 != 0) && (FUN_71015081f0(&local_80,puVar15), local_78 != 0)) &&
           (bVar4 = FUN_7101508a04((long)&local_70,(long)&local_80), !bVar4)) {
          param_1[8] = 0;
          param_1[9] = 0;
        }
        if (((*puVar16 != 0) && (FUN_71015081f0(&local_80,puVar16), local_78 != 0)) &&
           (bVar4 = FUN_7101508a04((long)&local_70,(long)&local_80), !bVar4)) {
          param_1[10] = 0;
          param_1[0xb] = 0;
        }
        if (((*puVar17 != 0) && (FUN_71015081f0(&local_80,puVar17), local_78 != 0)) &&
           (bVar4 = FUN_7101508a04((long)&local_70,(long)&local_80), !bVar4)) {
          param_1[0xc] = 0;
          param_1[0xd] = 0;
        }
        if (((*puVar18 != 0) && (FUN_71015081f0(&local_80,puVar18), local_78 != 0)) &&
           (bVar4 = FUN_7101508a04((long)&local_70,(long)&local_80), !bVar4)) {
          param_1[0xe] = 0;
          param_1[0xf] = 0;
          param_1[0x16] = *DAT_7103a5d058;
        }
      }
      uVar12 = uVar12 + 1;
    } while (uVar12 != 8);
    puVar13 = param_1 + 0x11;
    *puVar13 = *param_2;
    if ((int)param_3 < 0) {
      param_1[0x12] = 0;
      if (local_90 != (long *)0x0) goto LAB_71019ec980;
LAB_71019ec9e8:
      uVar11 = 0;
    }
    else {
      if ((local_90 == (long *)0x0) || (uVar11 = *(uint *)((long)local_90 + 0x1c), (int)uVar11 < 0))
      {
LAB_71019ec950:
        uVar11 = 1;
      }
      else {
        lVar8 = 0x4b0;
        if (*(uint *)(**(long **)(*DAT_7103a5a038 + 0xa8) + 0x10) < 0x1f) {
          lVar8 = 0;
        }
        lVar8 = *(long *)(*(long *)(**(long **)(*DAT_7103a5a038 + 0xa8) + 0x18) + lVar8 + 0x20);
        if ((lVar8 == 0) || (*(long *)(lVar8 + 0x28) == 0)) goto LAB_71019ec950;
        if (*(uint *)(lVar8 + 0x20) <= uVar11) {
          uVar11 = 0;
        }
        lVar8 = *(long *)(lVar8 + 0x28) + (ulong)uVar11 * 0x40;
        bVar2 = *(byte *)(lVar8 + 0x14);
        if (((((bVar2 & 0xf7) == 0xc0) || (bVar2 == 0xc1)) || (bVar2 == 0xc4)) ||
           ((bVar2 & 0xe0) == 0x20)) {
          uVar1 = *(uint *)((long)*(short **)(lVar8 + 8) + (ulong)*(uint *)(lVar8 + 0x10));
          uVar11 = uVar1 >> 8;
          if (**(short **)(lVar8 + 8) == 0x5942) {
            uVar11 = uVar11 & 0xff00 | uVar1 >> 0x18 | (uVar11 & 0xff) << 0x10;
          }
        }
        else {
          uVar11 = 0;
        }
      }
      if ((int)(uVar11 - 1) <= (int)param_3) {
        param_3 = uVar11 - 1;
      }
      param_1[0x12] = param_3 & ((int)param_3 >> 0x1f ^ 0xffffffffU);
      if (local_90 == (long *)0x0) goto LAB_71019ec9e8;
LAB_71019ec980:
      uVar11 = *(uint *)((long)local_90 + 0x1c);
      if ((int)uVar11 < 0) goto LAB_71019ec9e8;
      lVar8 = 0x4b0;
      if (*(uint *)(**(long **)(*DAT_7103a5a038 + 0xa8) + 0x10) < 0x1f) {
        lVar8 = 0;
      }
      lVar8 = *(long *)(*(long *)(**(long **)(*DAT_7103a5a038 + 0xa8) + 0x18) + lVar8 + 0x20);
      if ((lVar8 == 0) || (*(long *)(lVar8 + 0x28) == 0)) goto LAB_71019ec9e8;
      if (*(uint *)(lVar8 + 0x20) <= uVar11) {
        uVar11 = 0;
      }
      uVar11 = (uint)(*(char *)(*(long *)(lVar8 + 0x28) + (ulong)uVar11 * 0x40 + 0x3c) != '\0');
    }
    puVar14 = *(undefined8 **)(*DAT_7103a59ec8 + 0x28);
    lVar8 = 0;
    if (puVar14 != (undefined8 *)0x0) {
      if (((*DAT_7103a61988 & 1) == 0) &&
         (iVar5 = thunk_EXT_FUN_02e95df0(DAT_7103a61988), iVar5 != 0)) {
        *DAT_7103a61980 = DAT_7103a59e80 + 0x10;
        thunk_EXT_FUN_02e95df0(DAT_7103a61988);
      }
      lVar8 = (**(code **)*puVar14)(puVar14,DAT_7103a61980);
    }
    uVar1 = *puVar10;
    if (uVar1 == 0) {
      local_84 = 0;
      if (*puVar13 != 0) {
        FUN_710150bf70(&local_70,puVar13);
        if (local_68 != 0) {
          local_80 = DAT_7103a61968 + 0x10;
          local_78 = 0;
          uVar12 = FUN_710150d040((long)&local_70,2,(long)&local_80);
          if ((uVar12 & 1) != 0) {
            puVar10 = DAT_7103a5d098;
            if (local_78 != 0) {
              puVar10 = (uint *)(local_78 + 0x50);
            }
            local_84 = *puVar10;
            goto LAB_71019ecb0c;
          }
        }
        local_84 = 0;
      }
    }
    else {
      local_84 = 0;
      if (uVar1 != 0xce9a5baa) {
        local_84 = uVar1;
      }
    }
LAB_71019ecb0c:
    uVar1 = *puVar9;
    if (uVar1 == 0) {
      uVar7 = 0;
      if (*puVar13 != 0) {
        FUN_710150bf70(&local_70,puVar13);
        if (local_68 != 0) {
          local_80 = DAT_7103a61968 + 0x10;
          local_78 = 0;
          uVar12 = FUN_710150d040((long)&local_70,3,(long)&local_80);
          if ((uVar12 & 1) != 0) {
            puVar13 = DAT_7103a5d098;
            if (local_78 != 0) {
              puVar13 = (uint *)(local_78 + 0x50);
            }
            uVar7 = *puVar13;
            goto LAB_71019ecb90;
          }
        }
        uVar7 = 0;
      }
    }
    else {
      uVar7 = 0;
      if (uVar1 != 0x4197b1e0) {
        uVar7 = uVar1;
      }
    }
LAB_71019ecb90:
    local_70 = CONCAT44(local_70._4_4_,uVar7);
    bVar4 = FUN_710150b3c0(lVar8,&local_84,(uint *)&local_70,uVar11);
  }
  *(bool *)(param_1 + 0x10) = bVar4 == true;
LAB_71019ecc60:
  return plVar3 != (long *)0x0;
}



void FUN_71019ecd10(long param_1)

{
  uint *puVar1;
  uint uVar2;
  char cVar3;
  bool bVar4;
  int iVar5;
  long lVar6;
  ulong uVar7;
  undefined8 *puVar8;
  uint *puVar9;
  uint local_54;
  long local_50;
  long local_48;
  uint local_40 [2];
  long local_38;
  
  puVar9 = (uint *)(param_1 + 0x44);
  puVar9[0] = 0;
  puVar9[1] = 0;
  cVar3 = *(char *)(param_1 + 0x40);
  puVar8 = *(undefined8 **)(*DAT_7103a59ec8 + 0x28);
  lVar6 = 0;
  if (puVar8 != (undefined8 *)0x0) {
    if (((*DAT_7103a61988 & 1) == 0) && (iVar5 = thunk_EXT_FUN_02e95df0(DAT_7103a61988), iVar5 != 0)
       ) {
      *DAT_7103a61980 = DAT_7103a59e80 + 0x10;
      thunk_EXT_FUN_02e95df0(DAT_7103a61988);
    }
    lVar6 = (**(code **)*puVar8)(puVar8,DAT_7103a61980);
  }
  uVar2 = *(uint *)(param_1 + 0x10);
  if (uVar2 == 0) {
    local_54 = 0;
    if (*puVar9 != 0) {
      FUN_710150bf70((undefined8 *)local_40,puVar9);
      if (local_38 != 0) {
        local_50 = DAT_7103a61968 + 0x10;
        local_48 = 0;
        uVar7 = FUN_710150d040((long)local_40,2,(long)&local_50);
        if ((uVar7 & 1) != 0) {
          puVar1 = DAT_7103a5d098;
          if (local_48 != 0) {
            puVar1 = (uint *)(local_48 + 0x50);
          }
          local_54 = *puVar1;
          goto LAB_71019ecdf4;
        }
      }
      local_54 = 0;
    }
  }
  else {
    local_54 = 0;
    if (uVar2 != 0xce9a5baa) {
      local_54 = uVar2;
    }
  }
LAB_71019ecdf4:
  uVar2 = *(uint *)(param_1 + 0x18);
  if (uVar2 == 0) {
    local_40[0] = 0;
    if (*puVar9 != 0) {
      FUN_710150bf70((undefined8 *)local_40,puVar9);
      if (local_38 != 0) {
        local_50 = DAT_7103a61968 + 0x10;
        local_48 = 0;
        uVar7 = FUN_710150d040((long)local_40,3,(long)&local_50);
        if ((uVar7 & 1) != 0) {
          puVar9 = DAT_7103a5d098;
          if (local_48 != 0) {
            puVar9 = (uint *)(local_48 + 0x50);
          }
          local_40[0] = *puVar9;
          goto LAB_71019ece78;
        }
      }
      local_40[0] = 0;
    }
  }
  else {
    local_40[0] = 0;
    if (uVar2 != 0x4197b1e0) {
      local_40[0] = uVar2;
    }
  }
LAB_71019ece78:
  bVar4 = FUN_710150b3c0(lVar6,&local_54,local_40,(uint)(cVar3 != '\0'));
  *(bool *)(param_1 + 0x40) = bVar4;
  return;
}



void FUN_71019ed2b0(uint *param_1,long param_2)

{
  uint *puVar1;
  uint uVar2;
  char cVar3;
  long lVar4;
  long *plVar5;
  byte *pbVar6;
  bool bVar7;
  int iVar8;
  long lVar9;
  long lVar10;
  long lVar11;
  ulong uVar12;
  uint uVar13;
  undefined8 *puVar14;
  long *plVar15;
  uint *puVar16;
  uint local_84;
  long local_80;
  long local_78;
  uint local_70 [2];
  long local_68;
  
  param_1[0] = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  param_1[3] = 0;
  puVar16 = param_1 + 0x11;
  puVar16[0] = 0;
  puVar16[1] = 0;
  param_1[4] = 0;
  param_1[5] = 0;
  param_1[6] = 0;
  param_1[7] = 0;
  param_1[8] = 0;
  param_1[9] = 0;
  param_1[10] = 0;
  pbVar6 = DAT_7103a65010;
  param_1[0xb] = 0;
  param_1[0x14] = 0xffffffff;
  param_1[0x15] = 0xffffffff;
  param_1[0xc] = 0;
  param_1[0xd] = 0;
  param_1[0xe] = 0;
  lVar4 = DAT_7103a59c60;
  param_1[0xf] = 0;
  lVar11 = DAT_7103a59c60 + 0x10;
  param_1[0x16] = 0xffffffff;
  plVar5 = DAT_7103a65008;
  *(undefined1 *)(param_1 + 0x10) = 0;
  lVar10 = param_2;
  do {
    lVar9 = lVar10;
    if (((((*(byte *)(lVar9 + 0x81) & 1) != 0) || (*(long *)(lVar9 + 0x10) == 0)) ||
        (puVar14 = *(undefined8 **)(lVar9 + 0x18), puVar14 == (undefined8 *)0x0)) ||
       ((*(int *)((long)puVar14 + 0xc) != *(int *)(lVar9 + 0x20) ||
        (puVar14 = (undefined8 *)*puVar14, puVar14 == (undefined8 *)0x0)))) break;
    if (((*pbVar6 & 1) == 0) && (iVar8 = thunk_EXT_FUN_02e95df0(pbVar6), iVar8 != 0)) {
      *plVar5 = lVar11;
      thunk_EXT_FUN_02e95df0(pbVar6);
    }
    lVar10 = (**(code **)*puVar14)(puVar14,plVar5);
  } while (lVar10 != 0);
  local_70[0] = *(uint *)(lVar9 + 0x54);
  if (local_70[0] != 0) {
    lVar11 = param_2;
    do {
      lVar10 = lVar11;
      if ((((*(byte *)(lVar10 + 0x82) & 1) != 0) || (*(long *)(lVar10 + 0x10) == 0)) ||
         ((puVar14 = *(undefined8 **)(lVar10 + 0x18), puVar14 == (undefined8 *)0x0 ||
          ((*(int *)((long)puVar14 + 0xc) != *(int *)(lVar10 + 0x20) ||
           (puVar14 = (undefined8 *)*puVar14, puVar14 == (undefined8 *)0x0)))))) break;
      if (((*pbVar6 & 1) == 0) && (iVar8 = thunk_EXT_FUN_02e95df0(pbVar6), iVar8 != 0)) {
        *plVar5 = lVar4 + 0x10;
        thunk_EXT_FUN_02e95df0(pbVar6);
      }
      lVar11 = (**(code **)*puVar14)(puVar14,plVar5);
    } while (lVar11 != 0);
    FUN_71019ec4c0(param_1,local_70,*(uint *)(lVar10 + 0x50));
  }
  lVar11 = param_2;
  do {
    lVar10 = lVar11;
    if (((((*(byte *)(lVar10 + 0x83) & 1) != 0) || (*(long *)(lVar10 + 0x10) == 0)) ||
        (puVar14 = *(undefined8 **)(lVar10 + 0x18), puVar14 == (undefined8 *)0x0)) ||
       ((*(int *)((long)puVar14 + 0xc) != *(int *)(lVar10 + 0x20) ||
        (puVar14 = (undefined8 *)*puVar14, puVar14 == (undefined8 *)0x0)))) break;
    if (((*pbVar6 & 1) == 0) && (iVar8 = thunk_EXT_FUN_02e95df0(pbVar6), iVar8 != 0)) {
      *plVar5 = lVar4 + 0x10;
      thunk_EXT_FUN_02e95df0(pbVar6);
    }
    lVar11 = (**(code **)*puVar14)(puVar14,plVar5);
  } while (lVar11 != 0);
  uVar2 = *(uint *)(lVar10 + 0x44);
  lVar11 = param_2;
  do {
    lVar10 = lVar11;
    if ((((*(byte *)(lVar10 + 0x84) & 1) != 0) || (*(long *)(lVar10 + 0x10) == 0)) ||
       ((plVar15 = *(long **)(lVar10 + 0x18), plVar15 == (long *)0x0 ||
        ((*(int *)((long)plVar15 + 0xc) != *(int *)(lVar10 + 0x20) ||
         (puVar14 = (undefined8 *)*plVar15, puVar14 == (undefined8 *)0x0)))))) break;
    if (((*pbVar6 & 1) == 0) && (iVar8 = thunk_EXT_FUN_02e95df0(pbVar6), iVar8 != 0)) {
      *plVar5 = lVar4 + 0x10;
      thunk_EXT_FUN_02e95df0(pbVar6);
    }
    lVar11 = (**(code **)*puVar14)(puVar14,plVar5);
  } while (lVar11 != 0);
  puVar1 = DAT_7103a5d058;
  if (uVar2 != 0) {
    local_70[0] = *DAT_7103a5d058;
    FUN_71019eb4b4(param_1,uVar2,*(uint *)(lVar10 + 0x40),local_70);
  }
  lVar11 = param_2;
  do {
    lVar10 = lVar11;
    if (((((*(byte *)(lVar10 + 0x85) & 1) != 0) || (*(long *)(lVar10 + 0x10) == 0)) ||
        (puVar14 = *(undefined8 **)(lVar10 + 0x18), puVar14 == (undefined8 *)0x0)) ||
       ((*(int *)((long)puVar14 + 0xc) != *(int *)(lVar10 + 0x20) ||
        (puVar14 = (undefined8 *)*puVar14, puVar14 == (undefined8 *)0x0)))) break;
    if (((*pbVar6 & 1) == 0) && (iVar8 = thunk_EXT_FUN_02e95df0(pbVar6), iVar8 != 0)) {
      *plVar5 = lVar4 + 0x10;
      thunk_EXT_FUN_02e95df0(pbVar6);
    }
    lVar11 = (**(code **)*puVar14)(puVar14,plVar5);
  } while (lVar11 != 0);
  uVar2 = *(uint *)(lVar10 + 0x7c);
  lVar11 = param_2;
  do {
    lVar10 = lVar11;
    if ((((*(byte *)(lVar10 + 0x86) & 1) != 0) || (*(long *)(lVar10 + 0x10) == 0)) ||
       ((plVar15 = *(long **)(lVar10 + 0x18), plVar15 == (long *)0x0 ||
        ((*(int *)((long)plVar15 + 0xc) != *(int *)(lVar10 + 0x20) ||
         (puVar14 = (undefined8 *)*plVar15, puVar14 == (undefined8 *)0x0)))))) break;
    if (((*pbVar6 & 1) == 0) && (iVar8 = thunk_EXT_FUN_02e95df0(pbVar6), iVar8 != 0)) {
      *plVar5 = lVar4 + 0x10;
      thunk_EXT_FUN_02e95df0(pbVar6);
    }
    lVar11 = (**(code **)*puVar14)(puVar14,plVar5);
  } while (lVar11 != 0);
  if (uVar2 != 0) {
    local_70[0] = *puVar1;
    FUN_71019eb4b4(param_1,uVar2,*(uint *)(lVar10 + 0x78),local_70);
  }
  lVar11 = param_2;
  do {
    lVar10 = lVar11;
    if (((((*(byte *)(lVar10 + 0x87) & 1) != 0) || (*(long *)(lVar10 + 0x10) == 0)) ||
        (puVar14 = *(undefined8 **)(lVar10 + 0x18), puVar14 == (undefined8 *)0x0)) ||
       ((*(int *)((long)puVar14 + 0xc) != *(int *)(lVar10 + 0x20) ||
        (puVar14 = (undefined8 *)*puVar14, puVar14 == (undefined8 *)0x0)))) break;
    if (((*pbVar6 & 1) == 0) && (iVar8 = thunk_EXT_FUN_02e95df0(pbVar6), iVar8 != 0)) {
      *plVar5 = lVar4 + 0x10;
      thunk_EXT_FUN_02e95df0(pbVar6);
    }
    lVar11 = (**(code **)*puVar14)(puVar14,plVar5);
  } while (lVar11 != 0);
  uVar2 = *(uint *)(lVar10 + 0x74);
  lVar11 = param_2;
  do {
    lVar10 = lVar11;
    if ((((*(byte *)(lVar10 + 0x88) & 1) != 0) || (*(long *)(lVar10 + 0x10) == 0)) ||
       ((plVar15 = *(long **)(lVar10 + 0x18), plVar15 == (long *)0x0 ||
        ((*(int *)((long)plVar15 + 0xc) != *(int *)(lVar10 + 0x20) ||
         (puVar14 = (undefined8 *)*plVar15, puVar14 == (undefined8 *)0x0)))))) break;
    if (((*pbVar6 & 1) == 0) && (iVar8 = thunk_EXT_FUN_02e95df0(pbVar6), iVar8 != 0)) {
      *plVar5 = lVar4 + 0x10;
      thunk_EXT_FUN_02e95df0(pbVar6);
    }
    lVar11 = (**(code **)*puVar14)(puVar14,plVar5);
  } while (lVar11 != 0);
  if (uVar2 != 0) {
    local_70[0] = *puVar1;
    FUN_71019eb4b4(param_1,uVar2,*(uint *)(lVar10 + 0x70),local_70);
  }
  lVar11 = param_2;
  do {
    lVar10 = lVar11;
    if (((((*(byte *)(lVar10 + 0x89) & 1) != 0) || (*(long *)(lVar10 + 0x10) == 0)) ||
        (puVar14 = *(undefined8 **)(lVar10 + 0x18), puVar14 == (undefined8 *)0x0)) ||
       ((*(int *)((long)puVar14 + 0xc) != *(int *)(lVar10 + 0x20) ||
        (puVar14 = (undefined8 *)*puVar14, puVar14 == (undefined8 *)0x0)))) break;
    if (((*pbVar6 & 1) == 0) && (iVar8 = thunk_EXT_FUN_02e95df0(pbVar6), iVar8 != 0)) {
      *plVar5 = lVar4 + 0x10;
      thunk_EXT_FUN_02e95df0(pbVar6);
    }
    lVar11 = (**(code **)*puVar14)(puVar14,plVar5);
  } while (lVar11 != 0);
  uVar2 = *(uint *)(lVar10 + 0x4c);
  lVar11 = param_2;
  do {
    lVar10 = lVar11;
    if ((((*(byte *)(lVar10 + 0x8a) & 1) != 0) || (*(long *)(lVar10 + 0x10) == 0)) ||
       ((plVar15 = *(long **)(lVar10 + 0x18), plVar15 == (long *)0x0 ||
        ((*(int *)((long)plVar15 + 0xc) != *(int *)(lVar10 + 0x20) ||
         (puVar14 = (undefined8 *)*plVar15, puVar14 == (undefined8 *)0x0)))))) break;
    if (((*pbVar6 & 1) == 0) && (iVar8 = thunk_EXT_FUN_02e95df0(pbVar6), iVar8 != 0)) {
      *plVar5 = lVar4 + 0x10;
      thunk_EXT_FUN_02e95df0(pbVar6);
    }
    lVar11 = (**(code **)*puVar14)(puVar14,plVar5);
  } while (lVar11 != 0);
  if (uVar2 != 0) {
    local_70[0] = *puVar1;
    FUN_71019eb4b4(param_1,uVar2,*(uint *)(lVar10 + 0x48),local_70);
  }
  lVar11 = param_2;
  do {
    lVar10 = lVar11;
    if (((((*(byte *)(lVar10 + 0x8b) & 1) != 0) || (*(long *)(lVar10 + 0x10) == 0)) ||
        (puVar14 = *(undefined8 **)(lVar10 + 0x18), puVar14 == (undefined8 *)0x0)) ||
       ((*(int *)((long)puVar14 + 0xc) != *(int *)(lVar10 + 0x20) ||
        (puVar14 = (undefined8 *)*puVar14, puVar14 == (undefined8 *)0x0)))) break;
    if (((*pbVar6 & 1) == 0) && (iVar8 = thunk_EXT_FUN_02e95df0(pbVar6), iVar8 != 0)) {
      *plVar5 = lVar4 + 0x10;
      thunk_EXT_FUN_02e95df0(pbVar6);
    }
    lVar11 = (**(code **)*puVar14)(puVar14,plVar5);
  } while (lVar11 != 0);
  uVar2 = *(uint *)(lVar10 + 0x6c);
  lVar11 = param_2;
  do {
    lVar10 = lVar11;
    if ((((*(byte *)(lVar10 + 0x8c) & 1) != 0) || (*(long *)(lVar10 + 0x10) == 0)) ||
       ((plVar15 = *(long **)(lVar10 + 0x18), plVar15 == (long *)0x0 ||
        ((*(int *)((long)plVar15 + 0xc) != *(int *)(lVar10 + 0x20) ||
         (puVar14 = (undefined8 *)*plVar15, puVar14 == (undefined8 *)0x0)))))) break;
    if (((*pbVar6 & 1) == 0) && (iVar8 = thunk_EXT_FUN_02e95df0(pbVar6), iVar8 != 0)) {
      *plVar5 = lVar4 + 0x10;
      thunk_EXT_FUN_02e95df0(pbVar6);
    }
    lVar11 = (**(code **)*puVar14)(puVar14,plVar5);
  } while (lVar11 != 0);
  if (uVar2 != 0) {
    local_70[0] = *puVar1;
    FUN_71019eb4b4(param_1,uVar2,*(uint *)(lVar10 + 0x68),local_70);
  }
  lVar11 = param_2;
  do {
    lVar10 = lVar11;
    if (((((*(byte *)(lVar10 + 0x8d) & 1) != 0) || (*(long *)(lVar10 + 0x10) == 0)) ||
        (puVar14 = *(undefined8 **)(lVar10 + 0x18), puVar14 == (undefined8 *)0x0)) ||
       ((*(int *)((long)puVar14 + 0xc) != *(int *)(lVar10 + 0x20) ||
        (puVar14 = (undefined8 *)*puVar14, puVar14 == (undefined8 *)0x0)))) break;
    if (((*pbVar6 & 1) == 0) && (iVar8 = thunk_EXT_FUN_02e95df0(pbVar6), iVar8 != 0)) {
      *plVar5 = lVar4 + 0x10;
      thunk_EXT_FUN_02e95df0(pbVar6);
    }
    lVar11 = (**(code **)*puVar14)(puVar14,plVar5);
  } while (lVar11 != 0);
  uVar2 = *(uint *)(lVar10 + 100);
  lVar11 = param_2;
  do {
    lVar10 = lVar11;
    if ((((*(byte *)(lVar10 + 0x8e) & 1) != 0) || (*(long *)(lVar10 + 0x10) == 0)) ||
       ((plVar15 = *(long **)(lVar10 + 0x18), plVar15 == (long *)0x0 ||
        ((*(int *)((long)plVar15 + 0xc) != *(int *)(lVar10 + 0x20) ||
         (puVar14 = (undefined8 *)*plVar15, puVar14 == (undefined8 *)0x0)))))) break;
    if (((*pbVar6 & 1) == 0) && (iVar8 = thunk_EXT_FUN_02e95df0(pbVar6), iVar8 != 0)) {
      *plVar5 = lVar4 + 0x10;
      thunk_EXT_FUN_02e95df0(pbVar6);
    }
    lVar11 = (**(code **)*puVar14)(puVar14,plVar5);
  } while (lVar11 != 0);
  if (uVar2 != 0) {
    local_70[0] = *puVar1;
    FUN_71019eb4b4(param_1,uVar2,*(uint *)(lVar10 + 0x60),local_70);
  }
  lVar11 = param_2;
  do {
    lVar10 = lVar11;
    if (((((*(byte *)(lVar10 + 0x8f) & 1) != 0) || (*(long *)(lVar10 + 0x10) == 0)) ||
        (puVar14 = *(undefined8 **)(lVar10 + 0x18), puVar14 == (undefined8 *)0x0)) ||
       ((*(int *)((long)puVar14 + 0xc) != *(int *)(lVar10 + 0x20) ||
        (puVar14 = (undefined8 *)*puVar14, puVar14 == (undefined8 *)0x0)))) break;
    if (((*pbVar6 & 1) == 0) && (iVar8 = thunk_EXT_FUN_02e95df0(pbVar6), iVar8 != 0)) {
      *plVar5 = lVar4 + 0x10;
      thunk_EXT_FUN_02e95df0(pbVar6);
    }
    lVar11 = (**(code **)*puVar14)(puVar14,plVar5);
  } while (lVar11 != 0);
  uVar2 = *(uint *)(lVar10 + 0x3c);
  lVar11 = param_2;
  do {
    lVar10 = lVar11;
    if ((((*(byte *)(lVar10 + 0x90) & 1) != 0) || (*(long *)(lVar10 + 0x10) == 0)) ||
       ((plVar15 = *(long **)(lVar10 + 0x18), plVar15 == (long *)0x0 ||
        ((*(int *)((long)plVar15 + 0xc) != *(int *)(lVar10 + 0x20) ||
         (puVar14 = (undefined8 *)*plVar15, puVar14 == (undefined8 *)0x0)))))) break;
    if (((*pbVar6 & 1) == 0) && (iVar8 = thunk_EXT_FUN_02e95df0(pbVar6), iVar8 != 0)) {
      *plVar5 = lVar4 + 0x10;
      thunk_EXT_FUN_02e95df0(pbVar6);
    }
    lVar11 = (**(code **)*puVar14)(puVar14,plVar5);
  } while (lVar11 != 0);
  if (uVar2 != 0) {
    local_70[0] = *puVar1;
    FUN_71019eb4b4(param_1,uVar2,*(uint *)(lVar10 + 0x38),local_70);
  }
  lVar11 = param_2;
  do {
    lVar10 = lVar11;
    if (((((*(byte *)(lVar10 + 0x91) & 1) != 0) || (*(long *)(lVar10 + 0x10) == 0)) ||
        (puVar14 = *(undefined8 **)(lVar10 + 0x18), puVar14 == (undefined8 *)0x0)) ||
       ((*(int *)((long)puVar14 + 0xc) != *(int *)(lVar10 + 0x20) ||
        (puVar14 = (undefined8 *)*puVar14, puVar14 == (undefined8 *)0x0)))) break;
    if (((*pbVar6 & 1) == 0) && (iVar8 = thunk_EXT_FUN_02e95df0(pbVar6), iVar8 != 0)) {
      *plVar5 = lVar4 + 0x10;
      thunk_EXT_FUN_02e95df0(pbVar6);
    }
    lVar11 = (**(code **)*puVar14)(puVar14,plVar5);
  } while (lVar11 != 0);
  uVar2 = *(uint *)(lVar10 + 0x5c);
  lVar11 = param_2;
  do {
    lVar10 = lVar11;
    if ((((*(byte *)(lVar10 + 0x92) & 1) != 0) || (*(long *)(lVar10 + 0x10) == 0)) ||
       ((plVar15 = *(long **)(lVar10 + 0x18), plVar15 == (long *)0x0 ||
        ((*(int *)((long)plVar15 + 0xc) != *(int *)(lVar10 + 0x20) ||
         (puVar14 = (undefined8 *)*plVar15, puVar14 == (undefined8 *)0x0)))))) break;
    if (((*pbVar6 & 1) == 0) && (iVar8 = thunk_EXT_FUN_02e95df0(pbVar6), iVar8 != 0)) {
      *plVar5 = lVar4 + 0x10;
      thunk_EXT_FUN_02e95df0(pbVar6);
    }
    lVar11 = (**(code **)*puVar14)(puVar14,plVar5);
  } while (lVar11 != 0);
  if (uVar2 != 0) {
    local_70[0] = *puVar1;
    FUN_71019eb4b4(param_1,uVar2,*(uint *)(lVar10 + 0x58),local_70);
  }
  do {
    lVar11 = param_2;
    if (((((*(byte *)(lVar11 + 0x93) & 1) != 0) || (*(long *)(lVar11 + 0x10) == 0)) ||
        (puVar14 = *(undefined8 **)(lVar11 + 0x18), puVar14 == (undefined8 *)0x0)) ||
       ((*(int *)((long)puVar14 + 0xc) != *(int *)(lVar11 + 0x20) ||
        (puVar14 = (undefined8 *)*puVar14, puVar14 == (undefined8 *)0x0)))) break;
    if (((*pbVar6 & 1) == 0) && (iVar8 = thunk_EXT_FUN_02e95df0(pbVar6), iVar8 != 0)) {
      *plVar5 = lVar4 + 0x10;
      thunk_EXT_FUN_02e95df0(pbVar6);
    }
    param_2 = (**(code **)*puVar14)(puVar14,plVar5);
  } while (param_2 != 0);
  cVar3 = *(char *)(lVar11 + 0x80);
  puVar14 = *(undefined8 **)(*DAT_7103a59ec8 + 0x28);
  lVar11 = 0;
  if (puVar14 != (undefined8 *)0x0) {
    if (((*DAT_7103a61988 & 1) == 0) && (iVar8 = thunk_EXT_FUN_02e95df0(DAT_7103a61988), iVar8 != 0)
       ) {
      *DAT_7103a61980 = DAT_7103a59e80 + 0x10;
      thunk_EXT_FUN_02e95df0(DAT_7103a61988);
    }
    lVar11 = (**(code **)*puVar14)(puVar14,DAT_7103a61980);
  }
  uVar2 = param_1[4];
  if (uVar2 == 0) {
    local_84 = 0;
    if (*puVar16 != 0) {
      FUN_710150bf70((undefined8 *)local_70,puVar16);
      if (local_68 != 0) {
        local_80 = DAT_7103a61968 + 0x10;
        local_78 = 0;
        uVar12 = FUN_710150d040((long)local_70,2,(long)&local_80);
        if ((uVar12 & 1) != 0) {
          puVar1 = DAT_7103a5d098;
          if (local_78 != 0) {
            puVar1 = (uint *)(local_78 + 0x50);
          }
          local_84 = *puVar1;
          goto LAB_71019edef0;
        }
      }
      local_84 = 0;
    }
  }
  else {
    local_84 = 0;
    if (uVar2 != 0xce9a5baa) {
      local_84 = uVar2;
    }
  }
LAB_71019edef0:
  uVar2 = param_1[6];
  if (uVar2 == 0) {
    uVar13 = 0;
    if (*puVar16 != 0) {
      FUN_710150bf70((undefined8 *)local_70,puVar16);
      if (local_68 != 0) {
        local_80 = DAT_7103a61968 + 0x10;
        local_78 = 0;
        uVar12 = FUN_710150d040((long)local_70,3,(long)&local_80);
        if ((uVar12 & 1) != 0) {
          puVar16 = DAT_7103a5d098;
          if (local_78 != 0) {
            puVar16 = (uint *)(local_78 + 0x50);
          }
          uVar13 = *puVar16;
          goto LAB_71019edf74;
        }
      }
      uVar13 = 0;
    }
  }
  else {
    uVar13 = 0;
    if (uVar2 != 0x4197b1e0) {
      uVar13 = uVar2;
    }
  }
LAB_71019edf74:
  local_70[0] = uVar13;
  bVar7 = FUN_710150b3c0(lVar11,&local_84,local_70,(uint)(cVar3 != '\0'));
  *(bool *)(param_1 + 0x10) = bVar7;
  return;
}



bool FUN_71019edff4(int *param_1,int *param_2)

{
  bool bVar1;
  
  bVar1 = false;
  if ((((((((*param_1 == *param_2 && param_1[1] == param_2[1]) && (param_1[2] == param_2[2])) &&
          (param_1[3] == param_2[3])) &&
         ((bVar1 = false, param_1[4] == param_2[4] && (param_1[5] == param_2[5])))) &&
        ((bVar1 = false, param_1[6] == param_2[6] &&
         ((param_1[7] == param_2[7] && (bVar1 = false, param_1[8] == param_2[8])))))) &&
       (param_1[9] == param_2[9])) &&
      (((bVar1 = false, param_1[10] == param_2[10] && (param_1[0xb] == param_2[0xb])) &&
       (bVar1 = false, param_1[0xc] == param_2[0xc])))) &&
     (((param_1[0xd] == param_2[0xd] && (bVar1 = false, param_1[0xe] == param_2[0xe])) &&
      (param_1[0xf] == param_2[0xf])))) {
    if ((((char)param_1[0x10] != (char)param_2[0x10]) || (param_1[0x11] != param_2[0x11])) ||
       ((param_1[0x12] != param_2[0x12] ||
        ((param_1[0x14] != param_2[0x14] || (param_1[0x15] != param_2[0x15])))))) {
      return false;
    }
    bVar1 = param_1[0x16] == param_2[0x16];
  }
  return bVar1;
}



void FUN_71019ef588(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if ((*DAT_7103a65ea0 & 1) == 0) {
    iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a65ea0);
    if (iVar1 != 0) {
      *DAT_7103a65e98 = (long)&DAT_710398f740;
      thunk_EXT_FUN_02e95df0(DAT_7103a65ea0);
    }
  }
  if (param_2 != DAT_7103a65e98) {
    FUN_71019ef848(param_1,param_2);
    return;
  }
  return;
}



undefined8 * FUN_71019ef61c(void)

{
  int iVar1;
  
  if (((*DAT_7103a65ea0 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a65ea0), iVar1 != 0))
  {
    *DAT_7103a65e98 = &DAT_710398f740;
    thunk_EXT_FUN_02e95df0(DAT_7103a65ea0);
  }
  return DAT_7103a65e98;
}



undefined8 FUN_71019ef848(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if (((*DAT_7103a65eb8 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a65eb8), iVar1 != 0))
  {
    *DAT_7103a65eb0 = (long)&DAT_710398f790;
    thunk_EXT_FUN_02e95df0(DAT_7103a65eb8);
  }
  if (param_2 != DAT_7103a65eb0) {
    if (((*DAT_7103a65ed0 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a65ed0), iVar1 != 0)
       ) {
      *DAT_7103a65ec8 = (long)&DAT_710398f7a8;
      thunk_EXT_FUN_02e95df0(DAT_7103a65ed0);
    }
    if (param_2 != DAT_7103a65ec8) {
      if (((*DAT_7103a65ee8 & 1) == 0) &&
         (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a65ee8), iVar1 != 0)) {
        *DAT_7103a65ee0 = DAT_7103a59af0 + 0x10;
        thunk_EXT_FUN_02e95df0(DAT_7103a65ee8);
      }
      if (param_2 != DAT_7103a65ee0) {
        param_1 = 0;
      }
    }
  }
  return param_1;
}



void FUN_71019ef9b4(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071019ef9f4. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



void FUN_71019efba0(long *param_1)

{
  long *plVar1;
  long *plVar2;
  long lVar3;
  
  lVar3 = param_1[0x31];
  *param_1 = DAT_7103a71238 + 0x10;
  plVar2 = DAT_7103a65db8;
  if (lVar3 != 0) {
    if (*DAT_7103a65db8 == 0) {
      FUN_71005fbbd0(lVar3);
    }
    else {
      plVar1 = FUN_71024ef490(*DAT_7103a65db8,lVar3);
      if (plVar1 != (long *)0x0) {
        (**(code **)(*plVar1 + 0x38))(plVar1,lVar3);
      }
    }
    param_1[0x30] = 0;
    param_1[0x31] = 0;
  }
  if (*plVar2 != 0) {
    plVar2 = FUN_71024ef490(*plVar2,param_1);
    if (plVar2 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071019efc38. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*plVar2 + 0x38))(plVar2,param_1);
      return;
    }
    return;
  }
  FUN_71005fbbd0((long)param_1);
  return;
}



void FUN_71019efc60(long param_1,long *param_2)

{
  long *plVar1;
  long lVar2;
  undefined8 *puVar3;
  long *plVar4;
  long lVar5;
  int iVar6;
  ulong uVar7;
  
  if (*(int *)(param_1 + 0x180) != 0) {
    plVar4 = *(long **)(param_1 + 0x188);
    plVar1 = plVar4 + *(int *)(param_1 + 0x180);
    do {
      lVar5 = *plVar4;
      iVar6 = *(int *)(lVar5 + 0x100);
      if (0 < iVar6) {
        uVar7 = 0;
        do {
          if (uVar7 < 0x1c) {
            *(undefined1 *)(lVar5 + uVar7 + 0xb0) = 0x1c;
            *(undefined1 *)(lVar5 + uVar7 + 0xd0) = 6;
            iVar6 = *(int *)(lVar5 + 0x100);
          }
          uVar7 = uVar7 + 1;
        } while ((long)uVar7 < (long)iVar6);
      }
      plVar4 = plVar4 + 1;
    } while (plVar4 != plVar1);
  }
  iVar6 = *(int *)(param_1 + 0x100);
  if (0 < iVar6) {
    uVar7 = 0;
    do {
      if (uVar7 < 0x1c) {
        *(undefined1 *)(param_1 + uVar7 + 0xb0) = 0x1c;
        *(undefined1 *)(param_1 + uVar7 + 0xd0) = 6;
        iVar6 = *(int *)(param_1 + 0x100);
      }
      uVar7 = uVar7 + 1;
    } while ((long)uVar7 < (long)iVar6);
  }
  lVar5 = DAT_7105a06420;
  if (DAT_7105a06420 == 0) {
    puVar3 = (undefined8 *)FUN_71005fbcb0(8,0x34);
  }
  else {
    if (param_2 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar3 = (undefined8 *)(lVar5 + 8);
      if (lVar2 != 0) {
        puVar3 = (undefined8 *)(lVar2 + 0x88);
      }
      param_2 = (long *)*puVar3;
    }
    puVar3 = (undefined8 *)(**(code **)(*param_2 + 0x30))(param_2,0x34,8);
  }
  *(undefined4 *)(puVar3 + 4) = 0;
  puVar3[5] = 0x3d072b023d072b02;
  *(undefined4 *)(puVar3 + 6) = 0x3cf5c28f;
  puVar3[2] = 0;
  puVar3[3] = 0;
  *puVar3 = 0;
  puVar3[1] = 0;
  *(undefined8 **)(param_1 + 0x1f8) = puVar3;
  *(undefined4 *)((long)puVar3 + 0x24) = 0x3f751eb8;
  *(undefined8 *)(*(long *)(param_1 + 0x1f8) + 0x28) = 0x3df5c28f3da3d70a;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_71019efdf0(long *param_1)

{
  bool bVar1;
  long lVar2;
  uint uVar3;
  uint uVar4;
  byte bVar5;
  uint uVar6;
  int iVar7;
  long *plVar8;
  long *plVar9;
  ulong uVar10;
  long *plVar11;
  char *pcVar12;
  long lVar13;
  uint uVar14;
  uint uVar15;
  uint uVar16;
  undefined8 *puVar17;
  long lVar18;
  char *pcVar19;
  int iVar20;
  char *pcVar21;
  undefined4 local_88;
  long *local_80;
  
  lVar18 = -0x80000000800001;
  if ((*(ushort *)((long)param_1 + 0x14) & 1) != 0) {
    lVar18 = param_1[0x23];
  }
  param_1[0x36] = lVar18;
  FUN_710254f8c0(param_1);
  uVar16 = *(uint *)((long)param_1 + 0x114);
  uVar6 = *(uint *)(param_1 + 1);
  uVar15 = *(uint *)((long)param_1 + 0xc);
  uVar14 = *(uint *)(param_1 + 2);
  if ((uVar16 >> 0x12 & 1) == 0) {
    if ((uVar16 >> 0x10 & 1) == 0) goto LAB_71019efe40;
LAB_71019efee4:
    uVar3 = uVar16 & 0xfffdffff;
    uVar6 = uVar6 & 0xfffdffff;
    *(uint *)((long)param_1 + 0x114) = uVar3;
    uVar15 = uVar15 & 0xfffdffff;
    uVar14 = uVar14 & 0xfffdffff;
    *(uint *)(param_1 + 1) = uVar6;
    *(uint *)((long)param_1 + 0xc) = uVar15;
    *(uint *)(param_1 + 2) = uVar14;
    uVar4 = uVar16 & 0xd0000;
  }
  else {
    uVar16 = uVar16 & 0xfff7ffff;
    uVar6 = uVar6 & 0xfff7ffff;
    *(uint *)((long)param_1 + 0x114) = uVar16;
    uVar15 = uVar15 & 0xfff7ffff;
    uVar14 = uVar14 & 0xfff7ffff;
    *(uint *)(param_1 + 1) = uVar6;
    *(uint *)((long)param_1 + 0xc) = uVar15;
    *(uint *)(param_1 + 2) = uVar14;
    if ((uVar16 >> 0x10 & 1) != 0) goto LAB_71019efee4;
LAB_71019efe40:
    uVar4 = uVar16 & 0xf0000;
    uVar3 = uVar16;
  }
  if (uVar4 != 0) {
    uVar6 = uVar6 & 0xff0fffff;
    param_1[0x24] = 0;
    *(uint *)((long)param_1 + 0x114) = uVar3 & 0xff0fffff;
    *(uint *)(param_1 + 1) = uVar6;
    *(uint *)((long)param_1 + 0xc) = uVar15 & 0xff0fffff;
    *(uint *)(param_1 + 2) = uVar14 & 0xff0fffff;
  }
  plVar11 = DAT_7103a5bd20;
  if ((int)param_1[0x34] != 3) goto LAB_71019f0220;
  puVar17 = *(undefined8 **)(*DAT_7103a5bd20 + 0x40);
  if (((*DAT_7103a686f8 & 1) == 0) && (iVar7 = thunk_EXT_FUN_02e95df0(DAT_7103a686f8), iVar7 != 0))
  {
    *DAT_7103a686f0 = DAT_7103a68700 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a686f8);
  }
  if ((puVar17 == (undefined8 *)0x0) ||
     (plVar8 = (long *)(**(code **)*puVar17)(puVar17,DAT_7103a686f0), plVar8 == (long *)0x0)) {
    plVar8 = (long *)0x0;
    lVar18 = _DAT_00000028;
    if (_DAT_00000028 != 0) goto LAB_71019eff18;
LAB_71019eff5c:
    if (*(int *)((long)param_1 + 0x1a4) != 3) {
LAB_71019f0068:
      iVar7 = 0;
LAB_71019f0208:
      lVar18 = *plVar8;
      goto LAB_71019f0214;
    }
    lVar18 = *plVar11;
    pcVar21 = *(char **)(lVar18 + 0x20);
    iVar7 = *(int *)(lVar18 + 8);
    pcVar12 = pcVar21;
    if ((*pcVar21 < '\0') && (0 < iVar7)) {
      lVar13 = 0;
      do {
        lVar2 = lVar13 + 1;
        if (-1 < pcVar21[lVar13 + 1]) break;
        lVar13 = lVar2;
      } while ((int)lVar2 < iVar7);
      pcVar12 = pcVar21 + lVar2;
    }
    iVar20 = *(int *)(lVar18 + 0x18);
    pcVar19 = pcVar21 + iVar20;
    if ((*pcVar19 < '\0') && (lVar13 = (long)iVar20, iVar20 < iVar7)) {
      do {
        lVar2 = lVar13 + 1;
        if (-1 < pcVar21[lVar13 + 1]) break;
        lVar13 = lVar2;
      } while ((int)lVar2 < iVar7);
      pcVar19 = pcVar21 + lVar2;
    }
    if (pcVar12 != pcVar19) {
      iVar7 = (int)pcVar21;
      do {
        iVar20 = (int)pcVar12;
        uVar6 = iVar20 - iVar7;
        uVar10 = (**(code **)(**(long **)(*(long *)(lVar18 + 0x10) +
                                         (-(ulong)(uVar6 >> 0x1f) & 0xfffffff800000000 |
                                         (ulong)uVar6 << 3)) + 0x358))();
        if ((uVar10 & 1) != 0) goto LAB_71019f0068;
        pcVar12 = pcVar12 + 1;
        if ((*pcVar12 < '\0') && ((int)pcVar12 - iVar7 < *(int *)(lVar18 + 8))) {
          iVar20 = (2 - iVar7) + iVar20;
          do {
            pcVar12 = pcVar12 + 1;
            if (-1 < *pcVar12) break;
            bVar1 = iVar20 < *(int *)(lVar18 + 8);
            iVar20 = iVar20 + 1;
          } while (bVar1);
        }
      } while (pcVar12 != pcVar19);
    }
    uVar6 = *(uint *)(param_1 + 1);
    if ((uVar6 & 1) != 0) {
      iVar7 = 1;
      goto LAB_71019f0208;
    }
    if ((uVar6 >> 0x14 & 1) == 0) {
      if ((uVar6 >> 0x10 & 1) != 0) {
        uVar16 = *(uint *)(param_1 + 2);
        if ((*(byte *)((long)param_1 + 0x116) >> 4 & 1) != 0) {
          *(int *)(param_1 + 0xe) = (int)param_1[0x10];
          uVar15 = uVar16 >> 0x14;
          goto joined_r0x0071019f00c4;
        }
        goto LAB_71019f00fc;
      }
      uVar16 = *(uint *)(param_1 + 2);
      if ((uVar16 & 0x110000) != 0) goto LAB_71019f00fc;
LAB_71019f00e4:
      if ((uVar6 >> 0x15 & 1) == 0) {
        if ((uVar6 >> 0x11 & 1) != 0) {
          if ((*(byte *)((long)param_1 + 0x116) >> 5 & 1) != 0) {
            *(undefined4 *)((long)param_1 + 0x74) = *(undefined4 *)((long)param_1 + 0x84);
            uVar15 = uVar16 >> 0x15;
            goto joined_r0x0071019f0118;
          }
          goto LAB_71019f014c;
        }
        uVar15 = uVar16 & 0x220000;
joined_r0x0071019f0118:
        if (uVar15 != 0) goto LAB_71019f014c;
        if ((uVar6 >> 0x16 & 1) == 0) {
          if ((uVar6 >> 0x12 & 1) != 0) {
            if ((*(byte *)((long)param_1 + 0x116) >> 6 & 1) != 0) {
              *(int *)(param_1 + 0xf) = (int)param_1[0x11];
              uVar15 = uVar16 >> 0x16;
              goto joined_r0x0071019f0168;
            }
            goto LAB_71019f019c;
          }
          uVar15 = uVar16 & 0x440000;
joined_r0x0071019f0168:
          if (uVar15 != 0) goto LAB_71019f019c;
          if ((uVar6 >> 0x17 & 1) == 0) {
            if ((uVar6 >> 0x13 & 1) == 0) {
              uVar6 = uVar16 & 0x880000;
joined_r0x0071019f01b8:
              if (uVar6 == 0) {
                iVar7 = (uVar16 & 1) << 1;
                goto LAB_71019f0208;
              }
            }
            else if (*(char *)((long)param_1 + 0x116) < '\0') {
              *(undefined4 *)((long)param_1 + 0x7c) = *(undefined4 *)((long)param_1 + 0x8c);
              uVar6 = uVar16 >> 0x17;
              goto joined_r0x0071019f01b8;
            }
          }
          else if ((*(byte *)((long)param_1 + 0x116) >> 3 & 1) != 0) {
            *(undefined4 *)((long)param_1 + 0x8c) = *(undefined4 *)((long)param_1 + 0x7c);
            uVar6 = (uVar16 | uVar6) >> 0x13;
joined_r0x0071019f01b8:
            uVar6 = uVar6 & 1;
            goto joined_r0x0071019f01b8;
          }
          iVar7 = 6;
        }
        else {
          if ((*(byte *)((long)param_1 + 0x116) >> 2 & 1) != 0) {
            *(int *)(param_1 + 0x11) = (int)param_1[0xf];
            uVar15 = (uVar16 | uVar6) >> 0x12;
joined_r0x0071019f0168:
            uVar15 = uVar15 & 1;
            goto joined_r0x0071019f0168;
          }
LAB_71019f019c:
          iVar7 = 5;
        }
      }
      else {
        if ((*(byte *)((long)param_1 + 0x116) >> 1 & 1) != 0) {
          *(undefined4 *)((long)param_1 + 0x84) = *(undefined4 *)((long)param_1 + 0x74);
          uVar15 = (uVar16 | uVar6) >> 0x11;
joined_r0x0071019f0118:
          uVar15 = uVar15 & 1;
          goto joined_r0x0071019f0118;
        }
LAB_71019f014c:
        iVar7 = 4;
      }
    }
    else {
      uVar16 = *(uint *)(param_1 + 2);
      if ((*(byte *)((long)param_1 + 0x116) & 1) != 0) {
        *(int *)(param_1 + 0x10) = (int)param_1[0xe];
        uVar15 = (uVar16 | uVar6) >> 0x10;
joined_r0x0071019f00c4:
        if ((uVar15 & 1) == 0) goto LAB_71019f00e4;
      }
LAB_71019f00fc:
      iVar7 = 3;
    }
    if ((uVar16 & 0xff0000) == 0) goto LAB_71019f0208;
    (**(code **)(*plVar8 + 0x20))(plVar8,iVar7);
    *(undefined1 *)((long)plVar8 + 0x4c) = 1;
  }
  else {
    lVar18 = plVar8[5];
    if (plVar8[5] == 0) goto LAB_71019eff5c;
LAB_71019eff18:
    lVar18 = *(long *)(lVar18 + 0x58);
    if (lVar18 == 0) goto LAB_71019eff5c;
    plVar9 = *(long **)(lVar18 + 0x20);
    if (((*DAT_7103a5bca8 & 1) == 0) && (iVar7 = thunk_EXT_FUN_02e95df0(DAT_7103a5bca8), iVar7 != 0)
       ) {
      *DAT_7103a5bca0 = DAT_7103a5bcb0 + 0x10;
      thunk_EXT_FUN_02e95df0(DAT_7103a5bca8);
    }
    plVar9 = (long *)(**(code **)(*plVar9 + 0x10))(plVar9,DAT_7103a5bca0);
    uVar10 = (**(code **)(*plVar9 + 0x2a0))(plVar9,lVar18);
    if ((uVar10 & 1) != 0) goto LAB_71019eff5c;
    lVar18 = *plVar8;
    iVar7 = 0;
LAB_71019f0214:
    (**(code **)(lVar18 + 0x20))(plVar8,iVar7);
  }
  uVar6 = *(uint *)(param_1 + 1);
LAB_71019f0220:
  if (((uVar6 & 0x8001) == 0) && ((*(ushort *)((long)param_1 + 0xc) & 0x8001) == 0)) {
    *(float *)(param_1 + 0x33) =
         *(float *)(param_1 + 0x33) +
         SQRT(*(float *)((long)param_1 + 0x194) * *(float *)((long)param_1 + 0x194) +
              *(float *)(param_1 + 0x32) * *(float *)(param_1 + 0x32));
    lVar18 = *plVar11;
  }
  else {
    *(undefined4 *)(param_1 + 0x33) = 0;
    lVar18 = *plVar11;
  }
  if (lVar18 != 0) {
    uVar6 = (**(code **)(**(long **)(lVar18 + 0x28) + 0x48))(*(long **)(lVar18 + 0x28),0x110b6ad0);
    if (*(uint *)(lVar18 + 8) <= uVar6) {
      uVar6 = 0;
    }
    plVar8 = *(long **)(*(long *)(lVar18 + 0x10) + (long)(int)uVar6 * 8);
    if (((*DAT_7103a5bca8 & 1) == 0) && (iVar7 = thunk_EXT_FUN_02e95df0(DAT_7103a5bca8), iVar7 != 0)
       ) {
      *DAT_7103a5bca0 = DAT_7103a5bcb0 + 0x10;
      thunk_EXT_FUN_02e95df0(DAT_7103a5bca8);
    }
    if ((plVar8 == (long *)0x0) ||
       (plVar8 = (long *)(**(code **)(*plVar8 + 0x10))(plVar8,DAT_7103a5bca0), plVar8 == (long *)0x0
       )) {
      plVar8 = (long *)0x0;
    }
    if (((*DAT_7103a64be0 & 1) == 0) && (iVar7 = thunk_EXT_FUN_02e95df0(DAT_7103a64be0), iVar7 != 0)
       ) {
      *DAT_7103a64bd8 = DAT_7103a5bc98 + 0x10;
      thunk_EXT_FUN_02e95df0(DAT_7103a64be0);
    }
    if ((plVar8 != (long *)0x0) &&
       (lVar18 = (**(code **)(*plVar8 + 0x10))(plVar8,DAT_7103a64bd8), lVar18 != 0)) {
      FUN_71022a7068(lVar18);
    }
  }
  lVar18 = *plVar11;
  pcVar21 = *(char **)(lVar18 + 0x20);
  iVar7 = *(int *)(lVar18 + 8);
  pcVar12 = pcVar21;
  if ((*pcVar21 < '\0') && (0 < iVar7)) {
    lVar13 = 0;
    do {
      lVar2 = lVar13 + 1;
      if (-1 < pcVar21[lVar13 + 1]) break;
      lVar13 = lVar2;
    } while ((int)lVar2 < iVar7);
    pcVar12 = pcVar21 + lVar2;
  }
  iVar20 = *(int *)(lVar18 + 0x18);
  pcVar19 = pcVar21 + iVar20;
  if ((*pcVar19 < '\0') && (lVar13 = (long)iVar20, iVar20 < iVar7)) {
    do {
      lVar2 = lVar13 + 1;
      if (-1 < pcVar21[lVar13 + 1]) break;
      lVar13 = lVar2;
    } while ((int)lVar2 < iVar7);
    pcVar19 = pcVar21 + lVar2;
  }
  if (pcVar12 == pcVar19) {
    bVar5 = 1;
  }
  else {
    iVar7 = (int)pcVar21;
    do {
      iVar20 = (int)pcVar12;
      uVar6 = iVar20 - iVar7;
      bVar5 = (**(code **)(**(long **)(*(long *)(lVar18 + 0x10) +
                                      (-(ulong)(uVar6 >> 0x1f) & 0xfffffff800000000 |
                                      (ulong)uVar6 << 3)) + 0x340))();
      if ((bVar5 & 1) != 0) break;
      pcVar12 = pcVar12 + 1;
      if ((*pcVar12 < '\0') && ((int)pcVar12 - iVar7 < *(int *)(lVar18 + 8))) {
        iVar20 = (2 - iVar7) + iVar20;
        do {
          pcVar12 = pcVar12 + 1;
          if (-1 < *pcVar12) break;
          bVar1 = iVar20 < *(int *)(lVar18 + 8);
          iVar20 = iVar20 + 1;
        } while (bVar1);
      }
    } while (pcVar12 != pcVar19);
    bVar5 = bVar5 ^ 1;
  }
  local_88._0_1_ = bVar5 & (int)param_1[0x34] == 2;
  uVar6 = FUN_71019f1320((long)param_1);
  local_88._1_1_ = (byte)uVar6 & 1;
  local_88._2_1_ = 0;
  if (*(char *)((long)param_1 + 0x1c5) == '\0') {
    local_88._2_1_ = bVar5 & (int)param_1[0x34] != 3;
  }
  FUN_7101a11a3c(param_1[0x3f],(char *)&local_88);
  if ((((int)param_1[0x34] != 3) && (*(char *)((long)param_1 + 0xd) < '\0')) &&
     (plVar11 = FUN_71024bd9a0((float *)(param_1 + 0x23)), plVar11 != (long *)0x0)) {
    plVar8 = *(long **)(plVar11[4] + 0x80);
    if (((*DAT_7103a5bca8 & 1) == 0) && (iVar7 = thunk_EXT_FUN_02e95df0(DAT_7103a5bca8), iVar7 != 0)
       ) {
      *DAT_7103a5bca0 = DAT_7103a5bcb0 + 0x10;
      thunk_EXT_FUN_02e95df0(DAT_7103a5bca8);
    }
    if ((plVar8 == (long *)0x0) ||
       (lVar18 = (**(code **)(*plVar8 + 0x10))(plVar8,DAT_7103a5bca0), lVar18 == 0)) {
      lVar18 = 0;
    }
    uVar10 = FUN_71029180e0(&local_88,(long)plVar11);
    if (((((uVar10 & 1) == 0) ||
         (((plVar8 = FUN_71015a4c50(local_80), (char)plVar8[0x1b] == '\0' &&
           (*(char *)((long)plVar8 + 0xdf) == '\0')) &&
          ((*(uint *)(plVar11 + 8) & 0x30000) != 0x10000)))) &&
        (((*(char *)(lVar18 + 0x11e) == '\x02' && (-1 < *(char *)(lVar18 + 0x11d))) &&
         (*(char *)(*DAT_7103a5b9f8 + 0xf4) == '\0')))) && (*(int *)(*DAT_7103a5b9f8 + 0xcc) == 0))
    {
      if (*(long *)(lVar18 + 0x88) != lVar18 + 0x80) {
        lVar13 = (long)*(int *)(lVar18 + 0x94);
        puVar17 = (undefined8 *)(*(long *)(lVar18 + 0x88) - lVar13);
        do {
          if ((long *)puVar17[3] == plVar11) goto LAB_71019f0544;
          puVar17 = (undefined8 *)(*(long *)((long)puVar17 + lVar13 + 8) - lVar13);
        } while (puVar17 != (undefined8 *)((lVar18 + 0x80) - lVar13));
      }
      puVar17 = (undefined8 *)0x0;
LAB_71019f0544:
      if (((*DAT_7103a68720 & 1) == 0) &&
         (iVar7 = thunk_EXT_FUN_02e95df0(DAT_7103a68720), iVar7 != 0)) {
        *DAT_7103a68718 = DAT_7103a68728 + 0x10;
        thunk_EXT_FUN_02e95df0(DAT_7103a68720);
      }
      if (((puVar17 != (undefined8 *)0x0) &&
          (lVar13 = (**(code **)*puVar17)(puVar17,DAT_7103a68718), lVar13 != 0)) &&
         (*(long *)(lVar18 + 0x100) != lVar13)) {
        *(long *)(lVar18 + 0x100) = lVar13;
        *(ushort *)(lVar18 + 0x124) = *(ushort *)(lVar18 + 0x124) | 4;
      }
    }
  }
  return;
}



uint FUN_71019f1320(long param_1)

{
  bool bVar1;
  long lVar2;
  int iVar3;
  long lVar4;
  ulong uVar5;
  undefined8 uVar6;
  uint uVar7;
  char *pcVar8;
  long lVar9;
  int iVar10;
  char *pcVar11;
  char *pcVar12;
  int iVar13;
  
  lVar4 = DAT_7105a08f10;
  if (*(int *)(param_1 + 0x1d0) != 2 || *(int *)(param_1 + 0x1a0) == 3) {
    return 0;
  }
  pcVar11 = *(char **)(DAT_7105a08f10 + 0x20);
  iVar10 = *(int *)(DAT_7105a08f10 + 8);
  pcVar8 = pcVar11;
  if ((*pcVar11 < '\0') && (0 < iVar10)) {
    lVar9 = 0;
    do {
      lVar2 = lVar9 + 1;
      if (-1 < pcVar11[lVar9 + 1]) break;
      lVar9 = lVar2;
    } while ((int)lVar2 < iVar10);
    pcVar8 = pcVar11 + lVar2;
  }
  iVar13 = *(int *)(DAT_7105a08f10 + 0x18);
  pcVar12 = pcVar11 + iVar13;
  if ((*pcVar12 < '\0') && (lVar9 = (long)iVar13, iVar13 < iVar10)) {
    do {
      lVar2 = lVar9 + 1;
      if (-1 < pcVar11[lVar9 + 1]) break;
      lVar9 = lVar2;
    } while ((int)lVar2 < iVar10);
    pcVar12 = pcVar11 + lVar2;
  }
  if (pcVar8 != pcVar12) {
    iVar10 = (int)pcVar11;
    do {
      iVar13 = (int)pcVar8;
      uVar7 = iVar13 - iVar10;
      uVar5 = (**(code **)(**(long **)(*(long *)(lVar4 + 0x10) +
                                      (-(ulong)(uVar7 >> 0x1f) & 0xfffffff800000000 |
                                      (ulong)uVar7 << 3)) + 0x340))();
      if ((uVar5 & 1) != 0) {
        uVar7 = 0;
        goto LAB_71019f1468;
      }
      pcVar8 = pcVar8 + 1;
      if ((*pcVar8 < '\0') && (iVar3 = *(int *)(lVar4 + 8), (int)pcVar8 - iVar10 < iVar3)) {
        iVar13 = (2 - iVar10) + iVar13;
        do {
          pcVar8 = pcVar8 + 1;
          if (-1 < *pcVar8) break;
          bVar1 = iVar13 < iVar3;
          iVar13 = iVar13 + 1;
        } while (bVar1);
      }
    } while (pcVar8 != pcVar12);
  }
  uVar6 = FUN_71024bf2e0();
  uVar7 = (uint)uVar6 ^ 1;
LAB_71019f1468:
  return uVar7 & 1;
}



void FUN_71019f1608(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if ((*DAT_7103a65d30 & 1) == 0) {
    iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a65d30);
    if (iVar1 != 0) {
      *DAT_7103a65d28 = DAT_7103a65d38 + 0x10;
      thunk_EXT_FUN_02e95df0(DAT_7103a65d30);
    }
  }
  if (param_2 != DAT_7103a65d28) {
    FUN_71019f1708(param_1,param_2);
    return;
  }
  return;
}



long * FUN_71019f16a0(void)

{
  int iVar1;
  
  if (((*DAT_7103a65d30 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a65d30), iVar1 != 0))
  {
    *DAT_7103a65d28 = DAT_7103a65d38 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a65d30);
  }
  return DAT_7103a65d28;
}



undefined8 FUN_71019f1708(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if (((*DAT_7103a65d48 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a65d48), iVar1 != 0))
  {
    *DAT_7103a65d40 = DAT_7103a65cf8 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a65d48);
  }
  if (param_2 != DAT_7103a65d40) {
    if (((*DAT_7103a65d08 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a65d08), iVar1 != 0)
       ) {
      *DAT_7103a65d00 = DAT_7103a65d10 + 0x10;
      thunk_EXT_FUN_02e95df0(DAT_7103a65d08);
    }
    if (param_2 != DAT_7103a65d00) {
      if (((*DAT_7103a65d20 & 1) == 0) &&
         (iVar1 = thunk_EXT_FUN_02e95df0(DAT_7103a65d20), iVar1 != 0)) {
        *DAT_7103a65d18 = DAT_7103a59af0 + 0x10;
        thunk_EXT_FUN_02e95df0(DAT_7103a65d20);
      }
      if (param_2 != DAT_7103a65d18) {
        param_1 = 0;
      }
    }
  }
  return param_1;
}



void FUN_71019f187c(undefined8 *param_1)

{
  long *plVar1;
  long lVar2;
  long lVar3;
  
  *param_1 = &DAT_710398f838;
  if (DAT_71040e3f60 == param_1) {
    DAT_71040e3f60 = (undefined8 *)0x0;
    (**(code **)*DAT_71040e3f68)();
    DAT_71040e3f68 = (undefined8 *)0x0;
  }
  lVar2 = param_1[1];
  *param_1 = &DAT_7103a07950;
  if (lVar2 != 0) {
    if (lVar2 == 1) {
      return;
    }
    if ((*(uint *)(lVar2 + 200) & 1) == 0) {
      lVar3 = 0;
    }
    else {
      lVar3 = lVar2 + 0x88;
      thunk_EXT_FUN_02e95df0(lVar2 + 0xa8);
    }
    plVar1 = (long *)((long)*(int *)(lVar2 + 0x7c) + (long)param_1);
    if (*plVar1 != 0) {
      *(long *)(*plVar1 + 8) = plVar1[1];
    }
    if ((long *)plVar1[1] != (long *)0x0) {
      *(long *)plVar1[1] = *plVar1;
    }
    *plVar1 = 0;
    plVar1[1] = 0;
    *(int *)(lVar2 + 0x78) = *(int *)(lVar2 + 0x78) + -1;
    if (lVar3 != 0) {
      thunk_EXT_FUN_02e95df0(lVar3 + 0x20);
    }
  }
  param_1[1] = 1;
  return;
}



void FUN_71019f1960(undefined8 *param_1)

{
  long *plVar1;
  
  FUN_71019f187c(param_1);
  if (DAT_7105a06420 == 0) {
    FUN_71005fbbd0((long)param_1);
    return;
  }
  plVar1 = FUN_71024ef490(DAT_7105a06420,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071019f19a4. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



// WARNING: Removing unreachable block (ram,0x0071019f2590)
// WARNING: Removing unreachable block (ram,0x0071019f24ec)
// WARNING: Removing unreachable block (ram,0x0071019f263c)

int FUN_71019f1ca0(long param_1,int *param_2)

{
  long *plVar1;
  uint uVar2;
  byte *pbVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  long lVar7;
  undefined8 *puVar8;
  long lVar9;
  long lVar10;
  long *plVar11;
  int *piVar12;
  uint uVar13;
  long lVar14;
  uint uVar15;
  uint uVar16;
  ulong uVar17;
  
  pbVar3 = DAT_7103a65020;
  plVar1 = DAT_7103a65018;
  if (*(long *)(param_1 + 8) == 0) {
    return 0;
  }
  lVar7 = *(long *)(*(long *)(param_1 + 8) + 0x150);
  if (lVar7 == 0) {
    return 0;
  }
  if (*param_2 == 1) {
    lVar9 = DAT_7103a59c60 + 0x10;
    do {
      lVar10 = lVar7;
      if (((((*(byte *)(lVar10 + 0x131) & 1) != 0) || (*(long *)(lVar10 + 0x10) == 0)) ||
          (plVar11 = *(long **)(lVar10 + 0x18), plVar11 == (long *)0x0)) ||
         ((*(int *)((long)plVar11 + 0xc) != *(int *)(lVar10 + 0x20) ||
          (puVar8 = (undefined8 *)*plVar11, puVar8 == (undefined8 *)0x0)))) break;
      if (((*pbVar3 & 1) == 0) && (iVar5 = thunk_EXT_FUN_02e95df0(pbVar3), iVar5 != 0)) {
        *plVar1 = lVar9;
        thunk_EXT_FUN_02e95df0(pbVar3);
      }
      lVar7 = (**(code **)*puVar8)(puVar8,plVar1);
    } while (lVar7 != 0);
    piVar12 = (int *)(lVar10 + 0x11c);
LAB_71019f1e2c:
    iVar5 = *piVar12;
    iVar4 = param_2[1];
    lVar7 = DAT_7103a59c60;
    plVar1 = DAT_7103a65018;
    pbVar3 = DAT_7103a65020;
  }
  else {
    if (*param_2 == 4) {
      lVar9 = DAT_7103a59c60 + 0x10;
      do {
        lVar10 = lVar7;
        if ((((*(byte *)(lVar10 + 0x132) & 1) != 0) || (*(long *)(lVar10 + 0x10) == 0)) ||
           ((plVar11 = *(long **)(lVar10 + 0x18), plVar11 == (long *)0x0 ||
            ((*(int *)((long)plVar11 + 0xc) != *(int *)(lVar10 + 0x20) ||
             (puVar8 = (undefined8 *)*plVar11, puVar8 == (undefined8 *)0x0)))))) break;
        if (((*pbVar3 & 1) == 0) && (iVar5 = thunk_EXT_FUN_02e95df0(pbVar3), iVar5 != 0)) {
          *plVar1 = lVar9;
          thunk_EXT_FUN_02e95df0(pbVar3);
        }
        lVar7 = (**(code **)*puVar8)(puVar8,plVar1);
      } while (lVar7 != 0);
      piVar12 = (int *)(lVar10 + 0x118);
      goto LAB_71019f1e2c;
    }
    iVar5 = 0;
    iVar4 = param_2[1];
    lVar7 = DAT_7103a59c60;
  }
  DAT_7103a59c60 = lVar7;
  DAT_7103a65018 = plVar1;
  DAT_7103a65020 = pbVar3;
  if (iVar4 != 0) {
    if (*(long *)(param_1 + 8) == 0) {
      lVar9 = 0;
    }
    else {
      lVar9 = *(long *)(*(long *)(param_1 + 8) + 0x150);
    }
    do {
      lVar10 = lVar9;
      if (((((*(byte *)(lVar10 + 0x12d) & 1) != 0) || (*(long *)(lVar10 + 0x10) == 0)) ||
          (plVar11 = *(long **)(lVar10 + 0x18), plVar11 == (long *)0x0)) ||
         ((*(int *)((long)plVar11 + 0xc) != *(int *)(lVar10 + 0x20) ||
          (puVar8 = (undefined8 *)*plVar11, puVar8 == (undefined8 *)0x0)))) break;
      if (((*pbVar3 & 1) == 0) && (iVar4 = thunk_EXT_FUN_02e95df0(pbVar3), iVar4 != 0)) {
        *plVar1 = lVar7 + 0x10;
        thunk_EXT_FUN_02e95df0(pbVar3);
      }
      lVar9 = (**(code **)*puVar8)(puVar8,plVar1);
    } while (lVar9 != 0);
    lVar10 = lVar10 + 200;
    lVar9 = lVar10;
    uVar15 = 0;
    do {
      uVar16 = uVar15;
      lVar9 = *(long *)(lVar9 + 0x10);
      uVar15 = uVar16 + 1;
      lVar14 = lVar10;
    } while (lVar9 != 0);
    do {
      uVar15 = uVar15 - 1;
      if (uVar15 == 0) goto joined_r0x0071019f1f38;
      plVar11 = (long *)(lVar14 + 0x10);
      lVar14 = *plVar11;
    } while (*plVar11 != 0);
    goto LAB_71019f1f6c;
  }
  goto LAB_71019f2134;
joined_r0x0071019f1f38:
  uVar15 = uVar16;
  if (lVar14 == 0) goto LAB_71019f1f6c;
  if (*(int *)(lVar14 + 0x24) != 0) {
    uVar16 = 0;
    goto LAB_71019f2468;
  }
  uVar16 = uVar15 - 1;
  lVar14 = lVar10;
  if ((int)uVar15 < 1) goto LAB_71019f1f6c;
  while (uVar15 = uVar15 - 1, uVar15 != 0) {
    plVar11 = (long *)(lVar14 + 0x10);
    lVar14 = *plVar11;
    if (*plVar11 == 0) goto LAB_71019f1f6c;
  }
  goto joined_r0x0071019f1f38;
LAB_71019f2468:
  do {
    do {
      uVar17 = (ulong)uVar16;
      if (*(int *)(lVar14 + 0x24) <= (int)uVar16 || 0x7fffffff < uVar16) {
        uVar17 = 0;
      }
      if (param_2[1] == *(int *)(*(long *)(lVar14 + 0x18) + uVar17 * 4)) {
        if (*(long *)(param_1 + 8) == 0) {
          lVar9 = 0;
        }
        else {
          lVar9 = *(long *)(*(long *)(param_1 + 8) + 0x150);
        }
        goto LAB_71019f2684;
      }
      uVar16 = uVar16 + 1;
      if (*(int *)(lVar14 + 0x24) <= (int)uVar16) {
        uVar2 = uVar15 & (int)uVar15 >> 0x1f;
        uVar13 = uVar15;
        do {
          uVar15 = uVar13 - 1;
          lVar14 = lVar10;
          if ((int)uVar13 < 1) {
            lVar14 = 0;
            uVar16 = 0;
            uVar15 = uVar2 - 1;
            goto LAB_71019f2464;
          }
          while (uVar13 = uVar13 - 1, uVar13 != 0) {
            lVar14 = *(long *)(lVar14 + 0x10);
            if (lVar14 == 0) {
              uVar16 = 0;
              goto LAB_71019f2460;
            }
          }
          uVar16 = 0;
        } while ((lVar14 != 0) && (uVar13 = uVar15, *(int *)(lVar14 + 0x24) == 0));
      }
LAB_71019f2460:
    } while (lVar14 != 0);
LAB_71019f2464:
  } while (uVar16 != 0);
LAB_71019f1f6c:
  if (*(long *)(param_1 + 8) == 0) {
    lVar9 = 0;
  }
  else {
    lVar9 = *(long *)(*(long *)(param_1 + 8) + 0x150);
  }
  do {
    lVar10 = lVar9;
    if (((((*(byte *)(lVar10 + 0x12f) & 1) != 0) || (*(long *)(lVar10 + 0x10) == 0)) ||
        (plVar11 = *(long **)(lVar10 + 0x18), plVar11 == (long *)0x0)) ||
       ((*(int *)((long)plVar11 + 0xc) != *(int *)(lVar10 + 0x20) ||
        (puVar8 = (undefined8 *)*plVar11, puVar8 == (undefined8 *)0x0)))) break;
    if (((*pbVar3 & 1) == 0) && (iVar4 = thunk_EXT_FUN_02e95df0(pbVar3), iVar4 != 0)) {
      *plVar1 = lVar7 + 0x10;
      thunk_EXT_FUN_02e95df0(pbVar3);
    }
    lVar9 = (**(code **)*puVar8)(puVar8,plVar1);
  } while (lVar9 != 0);
  lVar10 = lVar10 + 0xf0;
  lVar9 = lVar10;
  uVar15 = 0;
  do {
    uVar16 = uVar15;
    lVar9 = *(long *)(lVar9 + 0x10);
    uVar15 = uVar16 + 1;
    lVar14 = lVar10;
  } while (lVar9 != 0);
  do {
    uVar15 = uVar15 - 1;
    if (uVar15 == 0) goto joined_r0x0071019f2038;
    plVar11 = (long *)(lVar14 + 0x10);
    lVar14 = *plVar11;
  } while (*plVar11 != 0);
  goto LAB_71019f206c;
  while( true ) {
    if (((*pbVar3 & 1) == 0) && (iVar4 = thunk_EXT_FUN_02e95df0(pbVar3), iVar4 != 0)) {
      *plVar1 = lVar7 + 0x10;
      thunk_EXT_FUN_02e95df0(pbVar3);
    }
    lVar9 = (**(code **)*puVar8)(puVar8,plVar1);
    if (lVar9 == 0) break;
LAB_71019f2684:
    lVar10 = lVar9;
    if ((((*(byte *)(lVar10 + 300) & 1) != 0) || (*(long *)(lVar10 + 0x10) == 0)) ||
       ((plVar11 = *(long **)(lVar10 + 0x18), plVar11 == (long *)0x0 ||
        ((*(int *)((long)plVar11 + 0xc) != *(int *)(lVar10 + 0x20) ||
         (puVar8 = (undefined8 *)*plVar11, puVar8 == (undefined8 *)0x0)))))) break;
  }
  iVar4 = *(int *)(lVar10 + 0x124);
  goto LAB_71019f2138;
joined_r0x0071019f2038:
  uVar15 = uVar16;
  if (lVar14 == 0) goto LAB_71019f206c;
  if (*(int *)(lVar14 + 0x24) != 0) {
    uVar16 = 0;
    goto LAB_71019f250c;
  }
  uVar16 = uVar15 - 1;
  lVar14 = lVar10;
  if ((int)uVar15 < 1) goto LAB_71019f206c;
  while (uVar15 = uVar15 - 1, uVar15 != 0) {
    plVar11 = (long *)(lVar14 + 0x10);
    lVar14 = *plVar11;
    if (*plVar11 == 0) goto LAB_71019f206c;
  }
  goto joined_r0x0071019f2038;
LAB_71019f250c:
  do {
    do {
      uVar17 = (ulong)uVar16;
      if (*(int *)(lVar14 + 0x24) <= (int)uVar16 || 0x7fffffff < uVar16) {
        uVar17 = 0;
      }
      if (param_2[1] == *(int *)(*(long *)(lVar14 + 0x18) + uVar17 * 4)) {
        if (*(long *)(param_1 + 8) == 0) {
          lVar9 = 0;
        }
        else {
          lVar9 = *(long *)(*(long *)(param_1 + 8) + 0x150);
        }
        goto LAB_71019f2718;
      }
      uVar16 = uVar16 + 1;
      if (*(int *)(lVar14 + 0x24) <= (int)uVar16) {
        uVar2 = uVar15 & (int)uVar15 >> 0x1f;
        uVar13 = uVar15;
        do {
          uVar15 = uVar13 - 1;
          lVar14 = lVar10;
          if ((int)uVar13 < 1) {
            lVar14 = 0;
            uVar16 = 0;
            uVar15 = uVar2 - 1;
            goto LAB_71019f2508;
          }
          while (uVar13 = uVar13 - 1, uVar13 != 0) {
            lVar14 = *(long *)(lVar14 + 0x10);
            if (lVar14 == 0) {
              uVar16 = 0;
              goto LAB_71019f2504;
            }
          }
          uVar16 = 0;
        } while ((lVar14 != 0) && (uVar13 = uVar15, *(int *)(lVar14 + 0x24) == 0));
      }
LAB_71019f2504:
    } while (lVar14 != 0);
LAB_71019f2508:
  } while (uVar16 != 0);
LAB_71019f206c:
  if (*(long *)(param_1 + 8) == 0) {
    lVar9 = 0;
  }
  else {
    lVar9 = *(long *)(*(long *)(param_1 + 8) + 0x150);
  }
  do {
    lVar10 = lVar9;
    if (((((*(byte *)(lVar10 + 0x130) & 1) != 0) || (*(long *)(lVar10 + 0x10) == 0)) ||
        (plVar11 = *(long **)(lVar10 + 0x18), plVar11 == (long *)0x0)) ||
       ((*(int *)((long)plVar11 + 0xc) != *(int *)(lVar10 + 0x20) ||
        (puVar8 = (undefined8 *)*plVar11, puVar8 == (undefined8 *)0x0)))) break;
    if (((*pbVar3 & 1) == 0) && (iVar4 = thunk_EXT_FUN_02e95df0(pbVar3), iVar4 != 0)) {
      *plVar1 = lVar7 + 0x10;
      thunk_EXT_FUN_02e95df0(pbVar3);
    }
    lVar9 = (**(code **)*puVar8)(puVar8,plVar1);
  } while (lVar9 != 0);
  lVar10 = lVar10 + 0xa0;
  lVar7 = lVar10;
  uVar15 = 0;
  do {
    uVar16 = uVar15;
    lVar7 = *(long *)(lVar7 + 0x10);
    uVar15 = uVar16 + 1;
    lVar9 = lVar10;
  } while (lVar7 != 0);
  do {
    uVar15 = uVar15 - 1;
    if (uVar15 == 0) goto joined_r0x0071019f2158;
    plVar1 = (long *)(lVar9 + 0x10);
    lVar9 = *plVar1;
  } while (*plVar1 != 0);
LAB_71019f2134:
  iVar4 = 0;
  goto LAB_71019f2138;
  while( true ) {
    if (((*pbVar3 & 1) == 0) && (iVar4 = thunk_EXT_FUN_02e95df0(pbVar3), iVar4 != 0)) {
      *plVar1 = lVar7 + 0x10;
      thunk_EXT_FUN_02e95df0(pbVar3);
    }
    lVar9 = (**(code **)*puVar8)(puVar8,plVar1);
    if (lVar9 == 0) break;
LAB_71019f2718:
    lVar10 = lVar9;
    if ((((*(byte *)(lVar10 + 0x12e) & 1) != 0) || (*(long *)(lVar10 + 0x10) == 0)) ||
       ((plVar11 = *(long **)(lVar10 + 0x18), plVar11 == (long *)0x0 ||
        ((*(int *)((long)plVar11 + 0xc) != *(int *)(lVar10 + 0x20) ||
         (puVar8 = (undefined8 *)*plVar11, puVar8 == (undefined8 *)0x0)))))) break;
  }
  iVar4 = *(int *)(lVar10 + 0x128);
  goto LAB_71019f2138;
joined_r0x0071019f2158:
  uVar15 = uVar16;
  iVar4 = 0;
  if (lVar9 == 0) goto LAB_71019f2138;
  if (*(int *)(lVar9 + 0x24) != 0) {
    uVar16 = 0;
    goto LAB_71019f25b4;
  }
  uVar16 = uVar15 - 1;
  lVar9 = lVar10;
  if ((int)uVar15 < 1) goto LAB_71019f2134;
  while (uVar15 = uVar15 - 1, uVar15 != 0) {
    plVar1 = (long *)(lVar9 + 0x10);
    lVar9 = *plVar1;
    if (*plVar1 == 0) goto LAB_71019f2134;
  }
  goto joined_r0x0071019f2158;
LAB_71019f25b4:
  do {
    do {
      uVar17 = (ulong)uVar16;
      if (*(int *)(lVar9 + 0x24) <= (int)uVar16 || 0x7fffffff < uVar16) {
        uVar17 = 0;
      }
      if (param_2[1] == *(int *)(*(long *)(lVar9 + 0x18) + uVar17 * 4)) goto LAB_71019f2134;
      uVar16 = uVar16 + 1;
      if (*(int *)(lVar9 + 0x24) <= (int)uVar16) {
        uVar2 = uVar15 & (int)uVar15 >> 0x1f;
        uVar13 = uVar15;
        do {
          uVar15 = uVar13 - 1;
          lVar9 = lVar10;
          if ((int)uVar13 < 1) {
            uVar16 = 0;
            lVar9 = 0;
            uVar15 = uVar2 - 1;
            goto LAB_71019f25ac;
          }
          while (uVar13 = uVar13 - 1, uVar13 != 0) {
            lVar9 = *(long *)(lVar9 + 0x10);
            if (lVar9 == 0) {
              uVar16 = 0;
              goto LAB_71019f25a8;
            }
          }
          uVar16 = 0;
        } while ((lVar9 != 0) && (uVar13 = uVar15, *(int *)(lVar9 + 0x24) == 0));
      }
LAB_71019f25a8:
    } while (uVar16 != 0);
LAB_71019f25ac:
    iVar4 = 0;
  } while (lVar9 != 0);
LAB_71019f2138:
  pbVar3 = DAT_7103a65020;
  plVar1 = DAT_7103a65018;
  iVar4 = iVar4 + iVar5;
  lVar7 = *(long *)(param_1 + 8);
  if ((char)param_2[2] != '\0') {
    if (lVar7 == 0) {
      lVar7 = 0;
    }
    else {
      lVar7 = *(long *)(lVar7 + 0x150);
    }
    lVar9 = DAT_7103a59c60 + 0x10;
    do {
      lVar10 = lVar7;
      if (((((*(byte *)(lVar10 + 0x133) & 1) != 0) || (*(long *)(lVar10 + 0x10) == 0)) ||
          (plVar11 = *(long **)(lVar10 + 0x18), plVar11 == (long *)0x0)) ||
         ((*(int *)((long)plVar11 + 0xc) != *(int *)(lVar10 + 0x20) ||
          (puVar8 = (undefined8 *)*plVar11, puVar8 == (undefined8 *)0x0)))) break;
      if (((*pbVar3 & 1) == 0) && (iVar5 = thunk_EXT_FUN_02e95df0(pbVar3), iVar5 != 0)) {
        *plVar1 = lVar9;
        thunk_EXT_FUN_02e95df0(pbVar3);
      }
      lVar7 = (**(code **)*puVar8)(puVar8,plVar1);
    } while (lVar7 != 0);
    iVar4 = *(int *)(lVar10 + 0x120) + iVar4;
    lVar7 = *(long *)(param_1 + 8);
  }
  pbVar3 = DAT_7103a65020;
  plVar1 = DAT_7103a65018;
  lVar9 = DAT_7103a59c60;
  if (lVar7 == 0) {
    lVar7 = 0;
  }
  else {
    lVar7 = *(long *)(lVar7 + 0x150);
  }
  lVar10 = DAT_7103a59c60 + 0x10;
  do {
    lVar14 = lVar7;
    if ((((*(byte *)(lVar14 + 0x134) & 1) != 0) || (*(long *)(lVar14 + 0x10) == 0)) ||
       ((plVar11 = *(long **)(lVar14 + 0x18), plVar11 == (long *)0x0 ||
        ((*(int *)((long)plVar11 + 0xc) != *(int *)(lVar14 + 0x20) ||
         (puVar8 = (undefined8 *)*plVar11, puVar8 == (undefined8 *)0x0)))))) break;
    if (((*pbVar3 & 1) == 0) && (iVar5 = thunk_EXT_FUN_02e95df0(pbVar3), iVar5 != 0)) {
      *plVar1 = lVar10;
      thunk_EXT_FUN_02e95df0(pbVar3);
    }
    lVar7 = (**(code **)*puVar8)(puVar8,plVar1);
  } while (lVar7 != 0);
  uVar15 = param_2[3];
  piVar12 = (int *)(lVar14 + 0x70);
  if (uVar15 < 4) {
    piVar12 = piVar12 + (ulong)uVar15 * 2;
  }
  if (((char)piVar12[1] == '\0') && (lVar7 = *(long *)(lVar14 + 0x98), lVar7 != 0)) {
    if (uVar15 < 4) {
      do {
        piVar12 = (int *)(lVar7 + 8 + (ulong)uVar15 * 8);
        if ((char)piVar12[1] != '\0') break;
        lVar7 = *(long *)(lVar7 + 0x30);
      } while (lVar7 != 0);
    }
    else {
      do {
        lVar10 = lVar7;
        if (*(char *)(lVar10 + 0xc) != '\0') break;
        lVar7 = *(long *)(lVar10 + 0x30);
      } while (*(long *)(lVar10 + 0x30) != 0);
      piVar12 = (int *)(lVar10 + 8);
    }
  }
  iVar5 = *piVar12;
  if (*(long *)(param_1 + 8) == 0) {
    lVar7 = 0;
  }
  else {
    lVar7 = *(long *)(*(long *)(param_1 + 8) + 0x150);
  }
  do {
    lVar10 = lVar7;
    if (((((*(byte *)(lVar10 + 0x135) & 1) != 0) || (*(long *)(lVar10 + 0x10) == 0)) ||
        (puVar8 = *(undefined8 **)(lVar10 + 0x18), puVar8 == (undefined8 *)0x0)) ||
       ((*(int *)((long)puVar8 + 0xc) != *(int *)(lVar10 + 0x20) ||
        (puVar8 = (undefined8 *)*puVar8, puVar8 == (undefined8 *)0x0)))) break;
    if (((*pbVar3 & 1) == 0) && (iVar6 = thunk_EXT_FUN_02e95df0(pbVar3), iVar6 != 0)) {
      *plVar1 = lVar9 + 0x10;
      thunk_EXT_FUN_02e95df0(pbVar3);
    }
    lVar7 = (**(code **)*puVar8)(puVar8,plVar1);
  } while (lVar7 != 0);
  uVar15 = param_2[5];
  piVar12 = (int *)(lVar10 + 0x40) + (ulong)uVar15 * 2;
  if (2 < uVar15) {
    piVar12 = (int *)(lVar10 + 0x40);
  }
  lVar7 = *(long *)(lVar10 + 0x60);
  if ((char)piVar12[1] == '\0' && lVar7 != 0) {
    if (uVar15 < 3) {
      do {
        piVar12 = (int *)(lVar7 + 8 + (ulong)uVar15 * 8);
        if ((char)piVar12[1] != '\0') break;
        lVar7 = *(long *)(lVar7 + 0x28);
      } while (lVar7 != 0);
    }
    else {
      do {
        lVar9 = lVar7;
        if (*(char *)(lVar9 + 0xc) != '\0') break;
        lVar7 = *(long *)(lVar9 + 0x28);
      } while (*(long *)(lVar9 + 0x28) != 0);
      piVar12 = (int *)(lVar9 + 8);
    }
  }
  iVar6 = 0;
  if (iVar5 + iVar4 < 1 && 0 < *piVar12) {
    iVar6 = *piVar12;
  }
  return iVar6 + iVar5 + iVar4;
}



void FUN_71019f27c8(long param_1)

{
  int iVar1;
  long lVar2;
  undefined8 *puVar3;
  long *plVar4;
  uint uVar5;
  long lVar6;
  undefined1 uStack_23;
  undefined1 uStack_22;
  undefined1 uStack_21;
  
  if (*(int *)(param_1 + 0x68) == -1) goto LAB_71019f2864;
  uVar5 = *(uint *)(param_1 + 0x70);
  if ((int)uVar5 < 0) {
LAB_71019f2848:
    puVar3 = FUN_7100baff84();
  }
  else {
    lVar6 = *(long *)(DAT_71040e7d48 + 2);
    if (*DAT_71040e7d48 <= uVar5) {
      uVar5 = 0;
      if (lVar6 != 0) goto LAB_71019f281c;
      goto LAB_71019f2848;
    }
    if (lVar6 == 0) goto LAB_71019f2848;
LAB_71019f281c:
    lVar6 = lVar6 + (ulong)uVar5 * 0x10;
    if ((*(int *)(lVar6 + 4) != *(int *)(param_1 + 0x6c)) ||
       (puVar3 = *(undefined8 **)(lVar6 + 8), puVar3 == (undefined8 *)0x0)) goto LAB_71019f2848;
  }
  iVar1 = *(int *)((long)puVar3 + 0xec);
  if ((iVar1 == 0) || (plVar4 = (long *)((long)iVar1 + (long)puVar3 + 0xec), plVar4 == (long *)0x0))
  {
    plVar4 = FUN_7100ef7c10();
  }
  FUN_7100e79410((long)plVar4,*(int *)(param_1 + 0x68));
LAB_71019f2864:
  if (*(char *)(param_1 + 0x1f38) != '\0') {
    *(undefined1 *)(param_1 + 0x1f38) = 0;
  }
  lVar6 = DAT_7103a59cf0;
  if (*(char *)(param_1 + 0x1f08) != '\0') {
    if (*(uint *)(param_1 + 0x1ee0) != 0xffffffff) {
      (**(code **)(&DAT_710398f8a8 + (ulong)*(uint *)(param_1 + 0x1ee0) * 8))
                (&uStack_23,param_1 + 0x1df0);
    }
    *(undefined4 *)(param_1 + 0x1ee0) = 0xffffffff;
    *(long *)(param_1 + 0x1dc8) = lVar6 + 0x10;
    if (*(int *)(param_1 + 0x1ddc) != 0) {
      *(undefined4 *)(param_1 + 0x1ddc) = 0;
    }
    *(undefined **)(param_1 + 0x1d58) = &DAT_710386bef0;
    if (*(int *)(param_1 + 0x1d6c) != 0) {
      *(undefined4 *)(param_1 + 0x1d6c) = 0;
    }
    *(undefined **)(param_1 + 0x1d18) = &DAT_710386bf10;
    if (*(int *)(param_1 + 0x1d2c) != 0) {
      *(undefined4 *)(param_1 + 0x1d2c) = 0;
    }
    if (*(uint *)(param_1 + 0x1d08) != 0xffffffff) {
      (**(code **)(&DAT_710398f8c0 + (ulong)*(uint *)(param_1 + 0x1d08) * 8))
                (&uStack_22,param_1 + 0x1c88);
    }
    *(undefined4 *)(param_1 + 0x1d08) = 0xffffffff;
    *(undefined1 *)(param_1 + 0x1f08) = 0;
  }
  lVar2 = DAT_7103a5e848;
  if (*(char *)(param_1 + 0x1c78) != '\0') {
    if (*(char *)(param_1 + 0x1c48) != '\0') {
      *(undefined1 *)(param_1 + 0x1c48) = 0;
    }
    if (*(uint *)(param_1 + 0x1c18) != 0xffffffff) {
      (**(code **)(&DAT_710398f868 + (ulong)*(uint *)(param_1 + 0x1c18) * 8))
                (&uStack_21,param_1 + 0x1b88);
    }
    *(undefined4 *)(param_1 + 0x1c18) = 0xffffffff;
    FUN_7100bca7f0(param_1 + 0x1768);
    if (*(char *)(param_1 + 0x1760) != '\0') {
      if (*(char *)(param_1 + 0x1754) != '\0') {
        *(undefined1 *)(param_1 + 0x1754) = 0;
      }
      if (*(char *)(param_1 + 0x173c) != '\0') {
        *(char *)(param_1 + 0x173c) = '\0';
      }
      *(undefined **)(param_1 + 0x1110) = &DAT_7103891c98;
      if (*(int *)(param_1 + 0x1124) != 0) {
        *(undefined4 *)(param_1 + 0x1124) = 0;
      }
      *(undefined1 *)(param_1 + 0x1760) = 0;
    }
    *(long *)(param_1 + 0xd8) = lVar2 + 0x10;
    if (*(int *)(param_1 + 0xec) != 0) {
      *(undefined4 *)(param_1 + 0xec) = 0;
    }
    *(long *)(param_1 + 0xc0) = lVar6 + 0x10;
    if (*(int *)(param_1 + 0xd4) != 0) {
      *(undefined4 *)(param_1 + 0xd4) = 0;
    }
    *(undefined1 *)(param_1 + 0x1c78) = 0;
  }
  if (*(char *)(param_1 + 0x78) != '\0') {
    *(undefined1 *)(param_1 + 0x78) = 0;
  }
  *(long *)(param_1 + 0x10) = lVar2 + 0x10;
  if (*(int *)(param_1 + 0x24) != 0) {
    *(undefined4 *)(param_1 + 0x24) = 0;
  }
  return;
}



void FUN_71019f2d70(int *param_1)

{
  int iVar1;
  int iVar2;
  undefined8 *puVar3;
  undefined8 *puVar4;
  long *plVar5;
  uint uVar6;
  long lVar7;
  int iVar8;
  
  puVar4 = DAT_7103a59c40;
  if ((char)param_1[0x7c2] == '\0') {
    return;
  }
  uVar6 = param_1[1];
  if ((int)uVar6 < 0) {
LAB_71019f2dec:
    puVar3 = FUN_7100baff84();
  }
  else {
    lVar7 = *(long *)((uint *)*DAT_7103a59c40 + 2);
    if (*(uint *)*DAT_7103a59c40 <= uVar6) {
      uVar6 = 0;
      if (lVar7 != 0) goto LAB_71019f2dc0;
      goto LAB_71019f2dec;
    }
    if (lVar7 == 0) goto LAB_71019f2dec;
LAB_71019f2dc0:
    lVar7 = lVar7 + (ulong)uVar6 * 0x10;
    if ((*(int *)(lVar7 + 4) != *param_1) ||
       (puVar3 = *(undefined8 **)(lVar7 + 8), puVar3 == (undefined8 *)0x0)) goto LAB_71019f2dec;
  }
  iVar2 = *(int *)(puVar3 + 9);
  if ((iVar2 == 0) || (plVar5 = (long *)((long)iVar2 + (long)(puVar3 + 9)), plVar5 == (long *)0x0))
  {
    plVar5 = FUN_7100bb02dc();
  }
  lVar7 = plVar5[6];
  if (*(long *)(lVar7 + 0x330) != 0) {
    FUN_7101407500(*(long *)(lVar7 + 0x330));
  }
  iVar2 = *(int *)(lVar7 + 0x348);
  if (iVar2 != 0) {
    iVar8 = 0;
    do {
      iVar1 = 0;
      if (*(int *)(lVar7 + 0x340) <= iVar8 + *(int *)(lVar7 + 0x344)) {
        iVar1 = *(int *)(lVar7 + 0x340);
      }
      FUN_7101407500(*(long *)(*(long *)(lVar7 + 0x338) +
                              (long)(iVar8 + (*(int *)(lVar7 + 0x344) - iVar1)) * 8));
      iVar8 = iVar8 + 1;
    } while (iVar2 != iVar8);
  }
  uVar6 = param_1[3];
  if (-1 < (int)uVar6) {
    lVar7 = *(long *)((uint *)*puVar4 + 2);
    if (*(uint *)*puVar4 <= uVar6) {
      uVar6 = 0;
    }
    if (((lVar7 != 0) && (lVar7 = lVar7 + (ulong)uVar6 * 0x10, *(int *)(lVar7 + 4) == param_1[2]))
       && (puVar4 = *(undefined8 **)(lVar7 + 8), puVar4 != (undefined8 *)0x0)) goto LAB_71019f2eb0;
  }
  puVar4 = FUN_7100baff84();
LAB_71019f2eb0:
  iVar2 = *(int *)(puVar4 + 9);
  if ((iVar2 == 0) || (plVar5 = (long *)((long)iVar2 + (long)(puVar4 + 9)), plVar5 == (long *)0x0))
  {
    plVar5 = FUN_7100bb02dc();
  }
  lVar7 = plVar5[6];
  if (*(long *)(lVar7 + 0x330) != 0) {
    FUN_7101407500(*(long *)(lVar7 + 0x330));
  }
  iVar2 = *(int *)(lVar7 + 0x348);
  if (iVar2 != 0) {
    iVar8 = 0;
    do {
      iVar1 = 0;
      if (*(int *)(lVar7 + 0x340) <= iVar8 + *(int *)(lVar7 + 0x344)) {
        iVar1 = *(int *)(lVar7 + 0x340);
      }
      FUN_7101407500(*(long *)(*(long *)(lVar7 + 0x338) +
                              (long)(iVar8 + (*(int *)(lVar7 + 0x344) - iVar1)) * 8));
      iVar8 = iVar8 + 1;
    } while (iVar2 != iVar8);
  }
  iVar2 = FUN_710141ebf0(param_1 + 0x720);
  param_1[0x7cc] = 0;
  lVar7 = DAT_7103a5a0f0;
  param_1[0x7cd] = 0;
  param_1[0x7c8] = 0;
  param_1[0x7c9] = 0;
  param_1[0x7c5] = iVar2;
  param_1[0x7ca] = 0;
  param_1[0x7cb] = 0;
  *(undefined1 *)(param_1 + 0x7ca) = 0;
  *(long *)(param_1 + 0x7c6) = lVar7 + 0x10;
  *(undefined1 *)(param_1 + 0x7ce) = 1;
  return;
}



void FUN_71019f324c(undefined8 *param_1,int *param_2)

{
  int iVar1;
  undefined8 *puVar2;
  uint uVar3;
  undefined8 uVar4;
  long lVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  undefined4 uVar8;
  
  uVar4 = *DAT_7103a5a248;
  uVar6 = *(undefined4 *)(DAT_7103a5a248 + 1);
  param_1[7] = 0;
  param_1[6] = 0x3f800000;
  param_1[3] = uVar4;
  puVar2 = DAT_7103a5ba00;
  *(undefined4 *)(param_1 + 1) = 0;
  *param_1 = 0;
  *(undefined4 *)(param_1 + 4) = uVar6;
  uVar6 = *(undefined4 *)(puVar2 + 1);
  uVar4 = *puVar2;
  param_1[0xc] = 0;
  param_1[0xd] = 0;
  *(undefined4 *)((long)param_1 + 0x14) = uVar6;
  *(undefined8 *)((long)param_1 + 0xc) = uVar4;
  param_1[9] = 0;
  param_1[8] = 0x3f80000000000000;
  param_1[0xb] = 0x3f800000;
  param_1[10] = 0;
  uVar3 = param_2[1];
  if ((int)uVar3 < 0) {
    return;
  }
  lVar5 = *(long *)((uint *)*DAT_7103a59c40 + 2);
  if (lVar5 == 0) {
    return;
  }
  if (*(uint *)*DAT_7103a59c40 <= uVar3) {
    uVar3 = 0;
  }
  if (*(int *)(lVar5 + (ulong)uVar3 * 0x10 + 4) != *param_2) {
    return;
  }
  puVar2 = *(undefined8 **)(lVar5 + (ulong)uVar3 * 0x10 + 8);
  if (puVar2 == (undefined8 *)0x0) {
    puVar2 = FUN_7100baff84();
  }
  if (*(int *)(puVar2 + 0x5b) != 1) {
    return;
  }
  uVar3 = param_2[1];
  if (-1 < (int)uVar3) {
    lVar5 = *(long *)((uint *)*DAT_7103a59c40 + 2);
    if (*(uint *)*DAT_7103a59c40 <= uVar3) {
      uVar3 = 0;
    }
    if (((lVar5 != 0) && (lVar5 = lVar5 + (ulong)uVar3 * 0x10, *(int *)(lVar5 + 4) == *param_2)) &&
       (puVar2 = *(undefined8 **)(lVar5 + 8), puVar2 != (undefined8 *)0x0)) goto LAB_71019f3380;
  }
  puVar2 = FUN_7100baff84();
LAB_71019f3380:
  iVar1 = *(int *)((long)puVar2 + 0x84);
  if ((iVar1 != 0) && (lVar5 = (long)iVar1 + (long)puVar2 + 0x84, lVar5 != 0)) {
    uVar6 = *(undefined4 *)(lVar5 + 0xec);
    uVar7 = *(undefined4 *)(lVar5 + 0xfc);
    uVar8 = *(undefined4 *)(lVar5 + 0x10c);
    uVar4 = *(undefined8 *)(lVar5 + 0x11c);
    *(undefined4 *)(param_1 + 1) = *(undefined4 *)(lVar5 + 0x124);
    *(undefined4 *)((long)param_1 + 0xc) = uVar6;
    *(undefined4 *)(param_1 + 2) = uVar7;
    *param_1 = uVar4;
    *(undefined4 *)((long)param_1 + 0x14) = uVar8;
    uVar4 = *(undefined8 *)(lVar5 + 0x134);
    *(undefined4 *)(param_1 + 4) = *(undefined4 *)(lVar5 + 0x13c);
    param_1[3] = uVar4;
    *(undefined4 *)(param_1 + 10) = *(undefined4 *)(param_1 + 3);
    *(undefined4 *)((long)param_1 + 0x54) = *(undefined4 *)((long)param_1 + 0x1c);
    *(undefined4 *)(param_1 + 0xb) = *(undefined4 *)(param_1 + 4);
    *(undefined4 *)((long)param_1 + 0x5c) = 0;
    param_1[9] = 0;
    param_1[8] = 0x3f80000000000000;
    *(undefined4 *)(param_1 + 6) = uVar6;
    *(undefined4 *)((long)param_1 + 0x34) = uVar7;
    *(undefined4 *)(param_1 + 7) = uVar8;
    *(undefined4 *)((long)param_1 + 0x3c) = 0;
    param_1[0xd] = (ulong)*(uint *)(param_1 + 1);
    param_1[0xc] = *param_1;
  }
  return;
}



bool FUN_71019f34bc(long param_1)

{
  int iVar1;
  ulong uVar2;
  long *plVar3;
  undefined1 auVar4 [16];
  undefined1 local_40 [16];
  long local_30;
  int *piStack_28;
  int local_4;
  
  plVar3 = (long *)(param_1 + 8);
  if ((*plVar3 != 0) &&
     ((*(char *)(param_1 + 0x14) == -0x3f || (*(char *)(param_1 + 0x14) == -0x3c)))) {
    local_4 = 0;
    piStack_28 = &local_4;
    local_30 = DAT_7103a650b8 + 0x10;
    local_40 = FUN_7102813520(plVar3,"UseType");
    uVar2 = FUN_7101816740((long)&local_30,(undefined8 *)local_40);
    iVar1 = local_4;
    if ((uVar2 & 1) == 0) {
      iVar1 = 0;
    }
    if (iVar1 == 1) {
      return false;
    }
  }
  auVar4 = FUN_7102813520(plVar3,"IsVisible");
  return (auVar4._8_8_ & 0xffffffffff) != 0xd000000000;
}



bool FUN_71019f3574(long param_1)

{
  int iVar1;
  ulong uVar2;
  long *plVar3;
  undefined1 auVar4 [16];
  undefined1 local_40 [16];
  long local_30;
  int *piStack_28;
  int local_4;
  
  plVar3 = (long *)(param_1 + 8);
  if ((*plVar3 != 0) &&
     ((*(char *)(param_1 + 0x14) == -0x3f || (*(char *)(param_1 + 0x14) == -0x3c)))) {
    local_4 = 0;
    piStack_28 = &local_4;
    local_30 = DAT_7103a650b8 + 0x10;
    local_40 = FUN_7102813520(plVar3,"UseType");
    uVar2 = FUN_7101816740((long)&local_30,(undefined8 *)local_40);
    iVar1 = local_4;
    if ((uVar2 & 1) == 0) {
      iVar1 = 0;
    }
    if (iVar1 == 1) {
      return false;
    }
  }
  auVar4 = FUN_7102813520(plVar3,"IsGravityOn");
  return (auVar4._8_8_ & 0xff00000000) == 0xd000000000 && auVar4._8_4_ != 0;
}



ulong FUN_71019f3630(long param_1)

{
  int iVar1;
  ulong uVar2;
  long *plVar3;
  undefined1 auVar4 [16];
  undefined1 local_40 [16];
  long local_30;
  int *piStack_28;
  int local_4;
  
  plVar3 = (long *)(param_1 + 8);
  if ((*plVar3 != 0) &&
     ((*(char *)(param_1 + 0x14) == -0x3f || (*(char *)(param_1 + 0x14) == -0x3c)))) {
    local_4 = 0;
    piStack_28 = &local_4;
    local_30 = DAT_7103a650b8 + 0x10;
    local_40 = FUN_7102813520(plVar3,"UseType");
    uVar2 = FUN_7101816740((long)&local_30,(undefined8 *)local_40);
    iVar1 = local_4;
    if ((uVar2 & 1) == 0) {
      iVar1 = 0;
    }
    if (iVar1 == 1) {
      return uVar2;
    }
  }
  auVar4 = FUN_7102813520(plVar3,"Scale");
  return auVar4._0_8_;
}



bool FUN_71019f36f0(long param_1)

{
  int iVar1;
  ulong uVar2;
  long *plVar3;
  undefined1 auVar4 [16];
  undefined1 local_40 [16];
  long local_30;
  int *piStack_28;
  int local_4;
  
  plVar3 = (long *)(param_1 + 8);
  if ((*plVar3 != 0) &&
     ((*(char *)(param_1 + 0x14) == -0x3f || (*(char *)(param_1 + 0x14) == -0x3c)))) {
    local_4 = 0;
    piStack_28 = &local_4;
    local_30 = DAT_7103a650b8 + 0x10;
    local_40 = FUN_7102813520(plVar3,"UseType");
    uVar2 = FUN_7101816740((long)&local_30,(undefined8 *)local_40);
    iVar1 = local_4;
    if ((uVar2 & 1) == 0) {
      iVar1 = 0;
    }
    if (iVar1 == 1) {
      return false;
    }
  }
  auVar4 = FUN_7102813520(plVar3,"IsPhysicsHit");
  return (auVar4._8_8_ & 0xff00000000) == 0xd000000000 && auVar4._8_4_ != 0;
}



bool FUN_71019f37ac(long param_1)

{
  int iVar1;
  ulong uVar2;
  long *plVar3;
  undefined1 auVar4 [16];
  undefined1 local_40 [16];
  long local_30;
  int *piStack_28;
  int local_4;
  
  plVar3 = (long *)(param_1 + 8);
  if ((*plVar3 != 0) &&
     ((*(char *)(param_1 + 0x14) == -0x3f || (*(char *)(param_1 + 0x14) == -0x3c)))) {
    local_4 = 0;
    piStack_28 = &local_4;
    local_30 = DAT_7103a650b8 + 0x10;
    local_40 = FUN_7102813520(plVar3,"UseType");
    uVar2 = FUN_7101816740((long)&local_30,(undefined8 *)local_40);
    iVar1 = local_4;
    if ((uVar2 & 1) == 0) {
      iVar1 = 0;
    }
    if (iVar1 == 1) {
      return true;
    }
  }
  auVar4 = FUN_7102813520(plVar3,"IsGroundHit");
  return (auVar4._8_8_ & 0xffffffffff) != 0xd000000000;
}



bool FUN_71019f3864(long param_1)

{
  int iVar1;
  ulong uVar2;
  long *plVar3;
  undefined1 auVar4 [16];
  undefined1 local_40 [16];
  long local_30;
  int *piStack_28;
  int local_4;
  
  plVar3 = (long *)(param_1 + 8);
  if ((*plVar3 != 0) &&
     ((*(char *)(param_1 + 0x14) == -0x3f || (*(char *)(param_1 + 0x14) == -0x3c)))) {
    local_4 = 0;
    piStack_28 = &local_4;
    local_30 = DAT_7103a650b8 + 0x10;
    local_40 = FUN_7102813520(plVar3,"UseType");
    uVar2 = FUN_7101816740((long)&local_30,(undefined8 *)local_40);
    iVar1 = local_4;
    if ((uVar2 & 1) == 0) {
      iVar1 = 0;
    }
    if (iVar1 == 1) {
      return false;
    }
  }
  auVar4 = FUN_7102813520(plVar3,"IsBillboardActor");
  return (auVar4._8_8_ & 0xffffffffff) != 0xd000000000;
}



undefined8 FUN_71019f3920(long param_1,long *param_2)

{
  uint uVar1;
  uint uVar2;
  short sVar3;
  bool bVar4;
  undefined8 uVar5;
  short *psVar6;
  char *pcVar7;
  char *pcVar8;
  uint uVar9;
  long lVar10;
  ulong uVar11;
  uint uVar12;
  uint uVar13;
  undefined1 auVar14 [16];
  short *local_50;
  undefined4 local_48;
  undefined1 local_44;
  
  if (*(long *)(param_1 + 8) == 0) {
    return 1;
  }
  if ((*(char *)(param_1 + 0x14) == -0x3c) || (*(char *)(param_1 + 0x14) == -0x3f)) {
    auVar14 = FUN_7102813520((long *)(param_1 + 8),"ForkStrMainAry");
    local_50 = auVar14._0_8_;
    uVar5 = 1;
    if ((local_50 != (short *)0x0) && ((auVar14._8_8_ & 0xf700000000) == 0xc000000000)) {
      uVar9 = auVar14._12_4_;
      local_44 = auVar14[0xc];
      uVar12 = uVar9 & 0xff;
      local_48 = auVar14._8_4_;
      if (((((uVar9 & 0xf7) == 0xc0) || (uVar12 == 0xc1)) || (uVar12 == 0xc4)) ||
         ((uVar9 & 0xe0) == 0x20)) {
        uVar2 = *(uint *)((long)local_50 + (auVar14._8_8_ & 0xffffffff));
        uVar13 = uVar2 >> 8;
        uVar1 = uVar13;
        if (*local_50 == 0x5942) {
          uVar1 = uVar13 & 0xff00 | uVar2 >> 0x18 | (uVar13 & 0xff) << 0x10;
        }
        if (uVar1 != 0) {
          if ((((uVar9 & 0xf7) == 0xc0) || (uVar12 == 0xc1)) ||
             ((uVar12 == 0xc4 || ((uVar9 & 0xe0) == 0x20)))) {
            if (*local_50 == 0x5942) {
              uVar13 = uVar13 & 0xff00 | uVar2 >> 0x18 | (uVar13 & 0xff) << 0x10;
            }
            if (uVar13 != 0) {
              uVar12 = 0;
              do {
                auVar14 = FUN_71028132dc(&local_50,uVar12);
                psVar6 = auVar14._0_8_;
                pcVar7 = "";
                if ((auVar14._8_8_ & 0xff00000000) == 0xa000000000) {
                  sVar3 = *psVar6;
                  uVar1 = *(uint *)(psVar6 + 4);
                  uVar9 = (uVar1 & 0xff00ff00) >> 8 | (uVar1 & 0xff00ff) << 8;
                  uVar9 = uVar9 >> 0x10 | uVar9 << 0x10;
                  if (sVar3 != 0x5942) {
                    uVar9 = uVar1;
                  }
                  if (uVar9 == 0) {
                    pcVar7 = "";
                  }
                  else {
                    pcVar7 = (char *)((long)psVar6 + (long)(int)uVar9);
                    if (*pcVar7 == -0x3b) {
                      uVar1 = *(uint *)(pcVar7 + 4);
                      uVar9 = (uVar1 & 0xff00ff00) >> 8 | (uVar1 & 0xff00ff) << 8;
                      uVar9 = uVar9 >> 0x10 | uVar9 << 0x10;
                      if (sVar3 != 0x5942) {
                        uVar9 = uVar1;
                      }
                      lVar10 = *(long *)(pcVar7 + uVar9);
                    }
                    else {
                      lVar10 = 0;
                    }
                    uVar1 = *(uint *)(pcVar7 + ((long)(auVar14._8_8_ << 0x20) >> 0x1e) + 4);
                    uVar9 = (uVar1 & 0xff00ff00) >> 8 | (uVar1 & 0xff00ff) << 8;
                    uVar9 = uVar9 >> 0x10 | uVar9 << 0x10;
                    if (sVar3 != 0x5942) {
                      uVar9 = uVar1;
                    }
                    pcVar7 = pcVar7 + (ulong)uVar9 + lVar10;
                  }
                }
                *(undefined1 *)((long)(int)param_2[1] + *param_2 + -1) = 0;
                pcVar8 = (char *)*param_2;
                if (pcVar7 == pcVar8) goto LAB_71019f3b5c;
                bVar4 = true;
                for (uVar11 = 0; pcVar7[uVar11] == pcVar8[uVar11]; uVar11 = uVar11 + 2) {
                  if (pcVar7[uVar11] == '\0') {
LAB_71019f3a50:
                    if (bVar4) goto LAB_71019f3b5c;
                    break;
                  }
                  if ((uVar11 == 0x400000) || (pcVar7[uVar11 + 1] != pcVar8[uVar11 + 1])) break;
                  if (pcVar7[uVar11 + 1] == '\0') {
                    bVar4 = uVar11 < 0x400000;
                    goto LAB_71019f3a50;
                  }
                  bVar4 = uVar11 + 1 < 0x400000;
                }
                uVar12 = uVar12 + 1;
              } while (uVar13 != uVar12);
            }
          }
          uVar5 = 0;
        }
      }
    }
  }
  else {
LAB_71019f3b5c:
    uVar5 = 1;
  }
  return uVar5;
}



void FUN_71019f3b88(byte *param_1,long param_2)

{
  byte bVar1;
  byte bVar2;
  undefined8 *puVar3;
  long *plVar4;
  bool bVar5;
  long *plVar6;
  ulong uVar7;
  uint *puVar8;
  int *piVar9;
  long lVar10;
  uint uVar11;
  long lVar12;
  
  *param_1 = 0;
  param_1[4] = 0;
  plVar4 = DAT_7103a5a160;
  puVar3 = DAT_7103a59c40;
  param_1[5] = 0;
  param_1[6] = 0;
  param_1[7] = 0;
  uVar7 = (ulong)*(byte *)(param_2 + 10);
  if (uVar7 == 0xff) {
    return;
  }
  lVar10 = *DAT_7103a5a160;
  piVar9 = DAT_7103a5c420;
  if ((lVar10 != 0) && (lVar12 = *(long *)(lVar10 + uVar7 * 8 + 8), lVar12 != 0)) {
    piVar9 = (int *)(lVar12 + 0x150);
  }
  uVar11 = piVar9[1];
  if ((int)uVar11 < 0) {
    return;
  }
  lVar12 = *(long *)((uint *)*DAT_7103a59c40 + 2);
  if (*(uint *)*DAT_7103a59c40 <= uVar11) {
    uVar11 = 0;
  }
  if (lVar12 == 0) {
    return;
  }
  lVar12 = lVar12 + (ulong)uVar11 * 0x10;
  if (*(int *)(lVar12 + 4) != *piVar9) {
    return;
  }
  lVar12 = *(long *)(lVar12 + 8);
  if (lVar12 == 0) {
    return;
  }
  bVar1 = *(byte *)(param_2 + 8);
  if (*(byte *)(lVar12 + 0x24) <= bVar1) {
    return;
  }
  bVar2 = *(byte *)(param_2 + 9);
  if (*(byte *)(lVar12 + 0x25) <= bVar2) {
    return;
  }
  lVar10 = *(long *)(*(long *)(lVar10 + 0x818) + 0x20);
  if ((lVar10 == 0) || ((char)*(byte *)(param_2 + 10) < '\0')) {
LAB_71019f3ca4:
    plVar6 = FUN_7100c83958();
  }
  else {
    uVar11 = *(uint *)(lVar10 + uVar7 * 4 + 8);
    if (uVar11 == 0xffffffff) goto LAB_71019f3ca4;
    puVar8 = (uint *)(lVar10 + 0x208);
    if (uVar11 < 7) {
      puVar8 = puVar8 + (ulong)uVar11 * 4;
    }
    if (*(long *)(puVar8 + 2) == 0) goto LAB_71019f3ca4;
    if (((*puVar8 <= (uint)bVar1) || (puVar8[1] <= (uint)bVar2)) ||
       (plVar6 = *(long **)(*(long *)(puVar8 + 2) +
                           (long)(int)((uint)bVar1 + *puVar8 * (uint)bVar2) * 8),
       plVar6 == (long *)0x0)) goto LAB_71019f3ca4;
  }
  *param_1 = *(byte *)((long)plVar6 + 0x24) & 1;
  if ((ulong)*(byte *)(param_2 + 10) != 0xff) {
    piVar9 = DAT_7103a5c420;
    if ((*plVar4 != 0) &&
       (lVar10 = *(long *)(*plVar4 + (ulong)*(byte *)(param_2 + 10) * 8 + 8), lVar10 != 0)) {
      piVar9 = (int *)(lVar10 + 0x150);
    }
    uVar11 = piVar9[1];
    if (-1 < (int)uVar11) {
      lVar10 = *(long *)((uint *)*puVar3 + 2);
      if (*(uint *)*puVar3 <= uVar11) {
        uVar11 = 0;
      }
      if ((lVar10 != 0) && (lVar10 = lVar10 + (ulong)uVar11 * 0x10, *(int *)(lVar10 + 4) == *piVar9)
         ) {
        lVar10 = *(long *)(lVar10 + 8);
        uVar11 = 0;
        if (lVar10 == 0) goto LAB_71019f3d50;
        if ((*(byte *)(param_2 + 8) < *(byte *)(lVar10 + 0x24)) &&
           (*(byte *)(param_2 + 9) < *(byte *)(lVar10 + 0x25))) {
          bVar5 = FUN_71019f3f00(param_2);
          uVar11 = (uint)bVar5;
          goto LAB_71019f3d50;
        }
      }
    }
  }
  uVar11 = 0;
LAB_71019f3d50:
  *(uint *)(param_1 + 4) = uVar11;
  return;
}



bool FUN_71019f3d80(byte *param_1,long param_2)

{
  uint *puVar1;
  byte bVar2;
  long *plVar3;
  bool bVar4;
  bool bVar5;
  long *plVar6;
  int *piVar7;
  uint uVar8;
  long lVar9;
  
  plVar3 = DAT_7103a5a160;
  bVar2 = *(byte *)(param_2 + 10);
  if ((((ulong)bVar2 == 0xff) ||
      (lVar9 = *(long *)(*(long *)(*DAT_7103a5a160 + 0x818) + 0x20), lVar9 == 0)) ||
     ((char)bVar2 < '\0')) {
LAB_71019f3e00:
    plVar6 = FUN_7100c83958();
  }
  else {
    uVar8 = *(uint *)(lVar9 + (ulong)bVar2 * 4 + 8);
    if (uVar8 == 0xffffffff) goto LAB_71019f3e00;
    puVar1 = (uint *)(lVar9 + 0x208) + (ulong)uVar8 * 4;
    if (6 < uVar8) {
      puVar1 = (uint *)(lVar9 + 0x208);
    }
    if (*(long *)(puVar1 + 2) == 0) goto LAB_71019f3e00;
    bVar2 = *(byte *)(param_2 + 9);
    bVar4 = false;
    bVar5 = false;
    if ((uint)*(byte *)(param_2 + 8) < *puVar1) {
      bVar5 = (uint)bVar2 <= puVar1[1];
      bVar4 = puVar1[1] == (uint)bVar2;
    }
    if ((!bVar5 || bVar4) ||
       (plVar6 = *(long **)(*(long *)(puVar1 + 2) +
                           (long)(int)((uint)*(byte *)(param_2 + 8) + *puVar1 * (uint)bVar2) * 8),
       plVar6 == (long *)0x0)) goto LAB_71019f3e00;
  }
  if (*param_1 != (*(byte *)((long)plVar6 + 0x24) & 1)) {
    return false;
  }
  if ((ulong)*(byte *)(param_2 + 10) != 0xff) {
    piVar7 = DAT_7103a5c420;
    if ((*plVar3 != 0) &&
       (lVar9 = *(long *)(*plVar3 + (ulong)*(byte *)(param_2 + 10) * 8 + 8), lVar9 != 0)) {
      piVar7 = (int *)(lVar9 + 0x150);
    }
    uVar8 = piVar7[1];
    if (-1 < (int)uVar8) {
      if (*DAT_71040e7d48 <= uVar8) {
        uVar8 = 0;
      }
      if ((*(long *)(DAT_71040e7d48 + 2) != 0) &&
         (lVar9 = *(long *)(DAT_71040e7d48 + 2) + (ulong)uVar8 * 0x10,
         *(int *)(lVar9 + 4) == *piVar7)) {
        lVar9 = *(long *)(lVar9 + 8);
        uVar8 = 0;
        if (lVar9 == 0) goto LAB_71019f3ebc;
        if ((*(byte *)(param_2 + 8) < *(byte *)(lVar9 + 0x24)) &&
           (*(byte *)(param_2 + 9) < *(byte *)(lVar9 + 0x25))) {
          bVar4 = FUN_71019f3f00(param_2);
          uVar8 = (uint)bVar4;
          goto LAB_71019f3ebc;
        }
      }
    }
  }
  uVar8 = 0;
LAB_71019f3ebc:
  return uVar8 == *(uint *)(param_1 + 4);
}



bool FUN_71019f3f00(long param_1)

{
  uint *puVar1;
  uint uVar2;
  uint uVar3;
  byte bVar4;
  byte bVar5;
  int iVar6;
  uint uVar7;
  uint uVar8;
  undefined8 *puVar9;
  undefined *puVar10;
  ulong uVar11;
  int *piVar12;
  uint uVar13;
  uint uVar14;
  long lVar15;
  long lVar16;
  
  uVar11 = (ulong)*(byte *)(param_1 + 10);
  if (uVar11 == 0xff) {
    return false;
  }
  piVar12 = &DAT_7104046478;
  if ((DAT_71041fd400 != 0) && (lVar15 = *(long *)(DAT_71041fd400 + uVar11 * 8 + 8), lVar15 != 0)) {
    piVar12 = (int *)(lVar15 + 0x150);
  }
  uVar14 = piVar12[1];
  if ((int)uVar14 < 0) {
    return false;
  }
  if (*DAT_71040e7d48 <= uVar14) {
    uVar14 = 0;
  }
  if (*(long *)(DAT_71040e7d48 + 2) == 0) {
    return false;
  }
  lVar15 = *(long *)(DAT_71040e7d48 + 2) + (ulong)uVar14 * 0x10;
  if (*(int *)(lVar15 + 4) != *piVar12) {
    return false;
  }
  lVar15 = *(long *)(lVar15 + 8);
  if (lVar15 == 0) {
    return false;
  }
  bVar4 = *(byte *)(param_1 + 8);
  if (*(byte *)(lVar15 + 0x24) <= bVar4) {
    return false;
  }
  bVar5 = *(byte *)(param_1 + 9);
  if (*(byte *)(lVar15 + 0x25) <= bVar5) {
    return false;
  }
  lVar15 = *(long *)(DAT_71041fd400 + 0x818);
  uVar14 = (uint)bVar4;
  uVar13 = (uint)bVar5;
  if (*(long *)(lVar15 + 0x10) == 0) {
LAB_71019f4000:
    puVar9 = (undefined8 *)0x0;
    lVar15 = *(long *)(lVar15 + 0x18);
    if (lVar15 != 0) goto LAB_71019f4008;
joined_r0x0071019f40c4:
    puVar10 = (undefined *)0x0;
    if (puVar9 == (undefined8 *)0x0) goto LAB_71019f40c8;
LAB_71019f405c:
    uVar14 = *(uint *)((long)puVar9 + 0xc);
  }
  else {
    puVar1 = (uint *)(*(long *)(lVar15 + 0x10) + 8 + uVar11 * 0x10);
    if (*(long *)(puVar1 + 2) == 0) {
      puVar9 = (undefined8 *)0x0;
      lVar15 = *(long *)(lVar15 + 0x18);
    }
    else {
      if ((*puVar1 <= uVar14) || (puVar1[1] <= uVar13)) goto LAB_71019f4000;
      puVar9 = *(undefined8 **)
                (*(long *)(puVar1 + 2) + (long)(int)((uint)bVar4 + *puVar1 * (uint)bVar5) * 8);
      lVar15 = *(long *)(lVar15 + 0x18);
    }
    if (lVar15 == 0) goto joined_r0x0071019f40c4;
LAB_71019f4008:
    lVar16 = *(long *)(lVar15 + 8 + uVar11 * 0x10 + 8);
    if (lVar16 == 0) goto joined_r0x0071019f40c4;
    puVar1 = (uint *)(lVar15 + 8 + uVar11 * 0x10);
    uVar3 = *puVar1;
    if ((uVar3 < bVar4 || uVar3 == uVar14) || (uVar7 = puVar1[1], uVar7 < bVar5 || uVar7 == uVar13))
    goto joined_r0x0071019f40c4;
    puVar10 = *(undefined **)(lVar16 + (long)(int)(uVar14 + uVar3 * uVar13) * 8);
    if (puVar9 != (undefined8 *)0x0) goto LAB_71019f405c;
LAB_71019f40c8:
    puVar9 = FUN_7100bc42c8();
    uVar14 = *(uint *)((long)puVar9 + 0xc);
  }
  if ((-1 < (int)uVar14) && (lVar15 = *(long *)(DAT_71040e7d48 + 2), lVar15 != 0)) {
    if (*DAT_71040e7d48 <= uVar14) {
      uVar14 = 0;
    }
    if (*(int *)(lVar15 + (ulong)uVar14 * 0x10 + 4) == *(int *)(puVar9 + 1)) {
      puVar9 = *(undefined8 **)(lVar15 + (ulong)uVar14 * 0x10 + 8);
      if (puVar9 == (undefined8 *)0x0) {
        puVar9 = FUN_7100baff84();
      }
      iVar6 = *(int *)((long)puVar9 + 0x8c);
      piVar12 = DAT_7103a5d4b8;
      if ((iVar6 != 0) && (lVar15 = (long)iVar6 + (long)puVar9 + 0x8c, lVar15 != 0)) {
        piVar12 = (int *)(lVar15 + 0x30);
      }
      goto LAB_71019f40dc;
    }
  }
  piVar12 = &DAT_71032b5460;
LAB_71019f40dc:
  if (*piVar12 != 0x779b5f66) {
    return false;
  }
  if (puVar10 == (undefined *)0x0) {
    puVar10 = FUN_7100bc46e0();
  }
  uVar14 = *(uint *)(puVar10 + 8);
  uVar13 = DAT_7103e38508;
  if (DAT_7103e38508 == 0xffffffff) {
    uVar13 = 1000000;
    lVar15 = FUN_7101ceb0d0(*DAT_7103a59ec8);
    uVar3 = *(uint *)(lVar15 + 0x2c);
    if (uVar3 != 0) {
      uVar7 = 0;
      if (uVar3 != 0) {
        uVar7 = 0x495ff388 / uVar3;
      }
      uVar7 = 0x495ff388 - uVar7 * uVar3;
      uVar8 = uVar7;
      while (iVar6 = *(int *)(*(long *)(lVar15 + 0x20) +
                             (-(ulong)(uVar8 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar8 << 4)),
            iVar6 != 0) {
        if (iVar6 == 0x495ff388) {
          lVar15 = *(long *)(*(long *)(lVar15 + 0x20) + (long)(int)uVar8 * 0x10 + 8);
          uVar13 = 1000000;
          if (lVar15 != 0) {
            uVar13 = *(uint *)(lVar15 + 0x10);
            DAT_7103e38508 = uVar13;
          }
          break;
        }
        uVar2 = 0;
        if ((int)(uVar8 + 1) < (int)uVar3) {
          uVar2 = uVar8 + 1;
        }
        uVar8 = uVar2;
        if (uVar2 == uVar7) break;
      }
    }
  }
  return uVar14 < uVar13;
}



undefined8 FUN_71019f41e0(int *param_1,int *param_2)

{
  long lVar1;
  uint uVar2;
  undefined8 *puVar3;
  long lVar4;
  
  uVar2 = param_1[1];
  if (-1 < (int)uVar2) {
    if (*DAT_71040e7d48 <= uVar2) {
      uVar2 = 0;
    }
    if (((*(long *)(DAT_71040e7d48 + 2) != 0) &&
        (lVar1 = *(long *)(DAT_71040e7d48 + 2) + (ulong)uVar2 * 0x10,
        *(int *)(lVar1 + 4) == *param_1)) &&
       (puVar3 = *(undefined8 **)(lVar1 + 8), puVar3 != (undefined8 *)0x0)) goto LAB_71019f424c;
  }
  puVar3 = FUN_7100baff84();
LAB_71019f424c:
  if (((*(int *)(puVar3 + 0x52) != 0) &&
      (lVar1 = (long)puVar3 + (long)*(int *)(puVar3 + 0x52) + 0x290, lVar1 != 0)) &&
     (*(int *)(lVar1 + 0x28) != 0)) {
    lVar4 = (long)*(int *)(lVar1 + 0x28) << 3;
    puVar3 = *(undefined8 **)(lVar1 + 0x30);
    do {
      if (*(int *)*puVar3 == 0) {
        return 0;
      }
      if (*(int *)*puVar3 == *param_2) {
        return 1;
      }
      puVar3 = puVar3 + 1;
      lVar4 = lVar4 + -8;
    } while (lVar4 != 0);
  }
  return 0;
}



void FUN_71019f42b8(long *param_1,long *param_2,int param_3)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  long lVar4;
  long lVar5;
  int iVar6;
  uint uVar7;
  long lVar8;
  long *plVar9;
  float *pfVar10;
  long lVar11;
  float fVar12;
  float fVar13;
  float fVar14;
  float fVar15;
  float fVar16;
  float fVar17;
  float fVar18;
  float fVar19;
  float fVar20;
  float fVar21;
  
  if (param_3 == -1) {
    return;
  }
  iVar2 = (int)param_1[2];
  iVar6 = (int)param_1[1];
  if (iVar6 <= iVar2) {
    return;
  }
  if ((int)param_1[0x13] <= (int)param_1[0x14]) {
    return;
  }
  if (iVar2 != 0) goto LAB_71019f446c;
  *(int *)(param_1 + 0x44) = param_3;
  if (*(uint *)((long)param_2 + 0xc) < 4) {
    pfVar10 = *(float **)(&DAT_710398f8f8 + (long)(int)*(uint *)((long)param_2 + 0xc) * 8);
  }
  else {
    pfVar10 = (float *)&DAT_71032a8e0c;
  }
  fVar12 = *pfVar10;
  fVar14 = pfVar10[1];
  fVar16 = pfVar10[2];
  fVar19 = SQRT(fVar14 * fVar14 + fVar12 * fVar12 + fVar16 * fVar16);
  if (fVar19 <= 9.094947e-14) {
LAB_71019f43bc:
    fVar16 = 1.0;
    fVar14 = 0.0;
    fVar12 = 0.0;
  }
  else {
    fVar20 = 1.0 / fVar19;
    fVar13 = fVar12 * 3.1298223e-20;
    fVar15 = fVar14 * 3.1298223e-20;
    fVar17 = fVar16 * 3.1298223e-20;
    fVar21 = SQRT(fVar15 * fVar15 + fVar13 * fVar13 + fVar17 * fVar17);
    fVar18 = 1.0 / fVar21;
    fVar16 = fVar16 * fVar20;
    fVar14 = fVar14 * fVar20;
    fVar12 = fVar12 * fVar20;
    if (fVar19 == INFINITY) {
      fVar19 = fVar21 * 3.1950695e+19;
      fVar16 = fVar17 * fVar18;
      fVar14 = fVar15 * fVar18;
      fVar12 = fVar13 * fVar18;
    }
    if (fVar19 <= 0.0) goto LAB_71019f43bc;
  }
  lVar11 = *param_2;
  lVar8 = param_2[1];
  *(float *)(param_1 + 0x39) = fVar12;
  *(float *)(param_1 + 0x3a) = fVar16;
  *(float *)((long)param_1 + 0x1cc) = fVar14;
  fVar15 = fVar14 * 0.0 - fVar12;
  fVar19 = fVar16 * -0.0 + fVar12 * 0.0;
  *(int *)(param_1 + 0x37) = (int)lVar8;
  param_1[0x36] = lVar11;
  fVar13 = fVar16 + fVar14 * -0.0;
  *(float *)(param_1 + 0x38) = fVar19;
  *(float *)((long)param_1 + 0x1c4) = fVar15;
  *(float *)((long)param_1 + 0x1bc) = fVar13;
  param_1[0x3f] = 0;
  param_1[0x3e] = 0x3f80000000000000;
  *(float *)(param_1 + 0x40) = fVar12;
  *(float *)((long)param_1 + 0x204) = fVar14;
  *(float *)(param_1 + 0x41) = fVar16;
  *(undefined4 *)((long)param_1 + 0x20c) = 0;
  *(float *)(param_1 + 0x3c) = fVar13;
  *(float *)((long)param_1 + 0x1e4) = fVar19;
  *(float *)(param_1 + 0x3d) = fVar15;
  *(undefined4 *)((long)param_1 + 0x1ec) = 0;
  param_1[0x43] = (ulong)*(uint *)(param_1 + 0x37);
  param_1[0x42] = param_1[0x36];
LAB_71019f446c:
  uVar7 = *(uint *)((long)param_2 + 0xc);
  uVar3 = uVar7 & 0xfffffffd;
  fVar12 = *(float *)((long)param_2 + 0x14);
  fVar19 = *(float *)(param_2 + 2);
  if (uVar3 != 0) {
    fVar12 = *(float *)(param_2 + 2);
    fVar19 = *(float *)((long)param_2 + 0x14);
  }
  fVar19 = fVar19 + -1.0;
  if ((0.0 <= fVar19) && (fVar12 = fVar12 + -1.0, 0.0 <= fVar12)) {
    lVar11 = *param_2;
    lVar8 = param_2[1];
    iVar1 = *(int *)((long)param_1 + 0xc) + iVar2;
    *(int *)(param_1 + 2) = iVar2 + 1;
    iVar2 = 0;
    if (iVar6 <= iVar1) {
      iVar2 = iVar6;
    }
    plVar9 = (long *)(*param_1 + (long)(iVar1 - iVar2) * 0x18);
    lVar4 = param_2[1];
    lVar5 = param_2[2];
    *plVar9 = *param_2;
    plVar9[1] = lVar4;
    plVar9[2] = lVar5;
    iVar2 = (int)param_1[0x14];
    iVar6 = (int)param_1[0x13];
    if (iVar2 < iVar6) {
      *(int *)(param_1 + 0x14) = iVar2 + 1;
      fVar14 = fVar19;
      if (uVar3 != 0) {
        fVar14 = fVar12;
        fVar12 = fVar19;
      }
      iVar2 = *(int *)((long)param_1 + 0x9c) + iVar2;
      iVar1 = 0;
      if (iVar6 <= iVar2) {
        iVar1 = iVar6;
      }
      plVar9 = (long *)(param_1[0x12] + (long)(iVar2 - iVar1) * 0x18);
      *plVar9 = lVar11;
      *(float *)(plVar9 + 2) = fVar14;
      *(float *)((long)plVar9 + 0x14) = fVar12;
      *(int *)(plVar9 + 1) = (int)lVar8;
      *(uint *)((long)plVar9 + 0xc) = uVar7;
    }
  }
  return;
}



void FUN_71019f4540(undefined4 param_1,float param_2,float param_3,long *param_4,long param_5,
                   int *param_6,uint *param_7)

{
  undefined4 *puVar1;
  uint uVar2;
  char cVar3;
  undefined8 *puVar4;
  uint uVar5;
  int iVar6;
  float *pfVar7;
  uint uVar8;
  int *piVar9;
  ulong uVar10;
  float *pfVar11;
  long lVar12;
  long *plVar13;
  long *plVar14;
  long lVar15;
  uint *puVar16;
  int iVar17;
  long lVar18;
  int iVar19;
  ulong uVar20;
  float fVar21;
  float fVar22;
  float fVar23;
  float fVar24;
  float fVar25;
  float fVar26;
  float fVar27;
  float fVar28;
  float fVar29;
  float fVar30;
  float fVar31;
  float fVar32;
  undefined8 local_c8;
  undefined8 local_c0;
  undefined8 local_b8;
  long local_b0;
  undefined1 local_a8;
  undefined1 local_a7;
  byte local_a6;
  long lStack_a0;
  byte local_98;
  byte local_97;
  byte local_96;
  
  plVar14 = DAT_7103a5a160;
  puVar4 = DAT_7103a59c40;
  if ((ulong)*(byte *)(param_5 + 10) == 0xff) {
    return;
  }
  piVar9 = DAT_7103a5c420;
  if ((*DAT_7103a5a160 != 0) &&
     (lVar12 = *(long *)(*DAT_7103a5a160 + (ulong)*(byte *)(param_5 + 10) * 8 + 8), lVar12 != 0)) {
    piVar9 = (int *)(lVar12 + 0x150);
  }
  uVar5 = piVar9[1];
  if ((int)uVar5 < 0) {
    return;
  }
  lVar12 = *(long *)((uint *)*DAT_7103a59c40 + 2);
  if (*(uint *)*DAT_7103a59c40 <= uVar5) {
    uVar5 = 0;
  }
  if (lVar12 == 0) {
    return;
  }
  lVar12 = lVar12 + (ulong)uVar5 * 0x10;
  if (*(int *)(lVar12 + 4) != *piVar9) {
    return;
  }
  lVar12 = *(long *)(lVar12 + 8);
  if (lVar12 == 0) {
    return;
  }
  if (*(byte *)(lVar12 + 0x24) <= *(byte *)(param_5 + 8)) {
    return;
  }
  if (*(byte *)(lVar12 + 0x25) <= *(byte *)(param_5 + 9)) {
    return;
  }
  fVar21 = param_2;
  uVar5 = FUN_71019fc360(*param_6);
  if (uVar5 < 0x19) {
    puVar1 = &DAT_71040e58d8 + (ulong)uVar5 * 8;
    cVar3 = (&DAT_71040e58e4)[(ulong)uVar5 * 0x20];
  }
  else {
    puVar1 = &DAT_71040e58d8;
    cVar3 = DAT_71040e58e4;
  }
  if (cVar3 == '\0') {
    return;
  }
  FUN_71019e8b20(&lStack_a0,param_5,puVar1,param_7);
  uVar10 = (ulong)local_96;
  if (uVar10 != 0xff) {
    lVar12 = *plVar14;
    piVar9 = DAT_7103a5c420;
    if ((lVar12 != 0) && (lVar15 = *(long *)(lVar12 + uVar10 * 8 + 8), lVar15 != 0)) {
      piVar9 = (int *)(lVar15 + 0x150);
    }
    uVar5 = piVar9[1];
    if (-1 < (int)uVar5) {
      puVar16 = (uint *)*puVar4;
      lVar15 = *(long *)(puVar16 + 2);
      if (*puVar16 <= uVar5) {
        uVar5 = 0;
      }
      if ((((lVar15 != 0) &&
           (lVar18 = lVar15 + (ulong)uVar5 * 0x10, *(int *)(lVar18 + 4) == *piVar9)) &&
          (lVar18 = *(long *)(lVar18 + 8), lVar18 != 0)) &&
         ((local_98 < *(byte *)(lVar18 + 0x24) && (local_97 < *(byte *)(lVar18 + 0x25))))) {
        uVar5 = puVar1[2] - 2;
        if (uVar5 < 0x10) {
          uVar20 = -(ulong)(uVar5 >> 0x1f) & 0xfffffffc00000000 | (ulong)uVar5 << 2;
          iVar6 = *(int *)(&DAT_71032b4850 + uVar20);
          iVar19 = *(int *)(&DAT_71032b4890 + uVar20);
        }
        else {
          iVar6 = 0;
          iVar19 = 0;
        }
        piVar9 = DAT_7103a5c420;
        if ((lVar12 != 0) && (lVar18 = *(long *)(lVar12 + uVar10 * 8 + 8), lVar18 != 0)) {
          piVar9 = (int *)(lVar18 + 0x150);
        }
        uVar5 = piVar9[1];
        if (-1 < (int)uVar5) {
          if (*puVar16 <= uVar5) {
            uVar5 = 0;
          }
          if ((((*(int *)(lVar15 + (ulong)uVar5 * 0x10 + 4) == *piVar9) &&
               (lVar15 = *(long *)(lVar15 + (ulong)uVar5 * 0x10 + 8), lVar15 != 0)) &&
              ((uint)local_98 < (uint)*(byte *)(lVar15 + 0x24))) &&
             ((uint)local_97 < (uint)*(byte *)(lVar15 + 0x25))) {
            uVar5 = *param_7;
            if (uVar5 == 1) {
              iVar17 = iVar6;
              iVar6 = -iVar19;
            }
            else if (uVar5 == 3) {
              iVar17 = -iVar6;
              iVar6 = iVar19;
            }
            else {
              iVar17 = iVar19;
              if (uVar5 == 2) {
                iVar17 = -iVar19;
                iVar6 = -iVar6;
              }
            }
            uVar5 = (uint)local_98 + iVar17;
            uVar2 = (uint)local_97 + iVar6;
            local_a8 = (undefined1)uVar5;
            local_a7 = (undefined1)uVar2;
            local_a6 = local_96;
            local_b0 = DAT_7103a5a2a8 + 0x10;
            piVar9 = DAT_7103a5c420;
            if ((lVar12 != 0) && (lVar12 = *(long *)(lVar12 + uVar10 * 8 + 8), lVar12 != 0)) {
              piVar9 = (int *)(lVar12 + 0x150);
            }
            uVar8 = piVar9[1];
            if (-1 < (int)uVar8) {
              if (*puVar16 <= uVar8) {
                uVar8 = 0;
              }
              if (((*(long *)(puVar16 + 2) != 0) &&
                  (lVar12 = *(long *)(puVar16 + 2) + (ulong)uVar8 * 0x10,
                  *(int *)(lVar12 + 4) == *piVar9)) &&
                 ((lVar12 = *(long *)(lVar12 + 8), lVar12 != 0 &&
                  (((uVar5 & 0xff) < (uint)*(byte *)(lVar12 + 0x24) &&
                   ((uVar2 & 0xff) < (uint)*(byte *)(lVar12 + 0x25))))))) {
                fVar25 = fVar21;
                fVar21 = FUN_7101d0f140((long)&lStack_a0);
                fVar30 = param_3;
                fVar31 = fVar25;
                fVar22 = FUN_7101d0f140((long)&local_b0);
                if (fVar21 <= fVar22) {
                  fVar22 = fVar21;
                }
                fVar26 = fVar30;
                if (param_3 <= fVar30) {
                  fVar26 = param_3;
                }
                fVar29 = fVar31;
                fVar23 = FUN_7101d0f350((long)&lStack_a0);
                fVar27 = fVar30;
                fVar21 = fVar29;
                fVar24 = FUN_7101d0f350((long)&local_b0);
                local_c8 = 0;
                local_c0 = 0;
                local_b8 = 0;
                if (fVar23 <= fVar24) {
                  fVar23 = fVar24;
                }
                fVar24 = fVar22 - fVar23;
                param_3 = fVar30;
                if (fVar30 <= fVar27) {
                  param_3 = fVar27;
                }
                fVar30 = -fVar24;
                if (0.0 <= fVar24) {
                  fVar30 = fVar24;
                }
                fVar24 = fVar26 - param_3;
                fVar27 = -fVar24;
                if (0.0 <= fVar24) {
                  fVar27 = fVar24;
                }
                uVar5 = *param_7 & 0xfffffffd;
                fVar24 = fVar27;
                if (uVar5 != 0) {
                  fVar24 = fVar30;
                  fVar30 = fVar27;
                }
                fVar30 = fVar30 + param_2;
                if ((0.0 <= fVar30) && (fVar24 = fVar24 + param_2, 0.0 <= fVar24)) {
                  if (fVar25 <= fVar31) {
                    fVar31 = fVar25;
                  }
                  if (fVar29 <= fVar21) {
                    fVar29 = fVar21;
                  }
                  fVar25 = fVar24;
                  if (uVar5 != 0) {
                    fVar25 = fVar30;
                  }
                  fVar21 = (fVar31 + fVar29) * 0.5;
                  local_c8 = CONCAT44(fVar21,(fVar22 + fVar23) * 0.5);
                  local_c0 = CONCAT44(*param_7,(fVar26 + param_3) * 0.5);
                  param_3 = fVar30;
                  if (uVar5 != 0) {
                    param_3 = fVar24;
                  }
                  local_b8 = CONCAT44(fVar25,param_3);
                }
                if ((int)param_4[0x26] < (int)param_4[0x25]) {
                  uVar5 = (uint)*(byte *)(param_5 + 10);
                  if (uVar5 == 0xff) {
                    uVar5 = 0xffffffff;
                  }
                  FUN_71019f42b8(param_4,&local_c8,uVar5);
                  iVar6 = (int)param_4[0x26];
                  iVar19 = (int)param_4[0x25];
                  if (iVar6 < iVar19) {
                    iVar17 = *(int *)((long)param_4 + 300) + iVar6;
                    *(int *)(param_4 + 0x26) = iVar6 + 1;
                    iVar6 = 0;
                    if (iVar19 <= iVar17) {
                      iVar6 = iVar19;
                    }
                    plVar13 = (long *)(param_4[0x24] + (long)(iVar17 - iVar6) * 0x18);
                    plVar13[2] = local_b8;
                    *plVar13 = local_c8;
                    plVar13[1] = local_c0;
                  }
                }
              }
            }
            goto LAB_71019f47d0;
          }
        }
        local_a8 = 0;
        local_b0 = DAT_7103a5a2a8 + 0x10;
      }
    }
  }
LAB_71019f47d0:
  if (*(char *)(puVar1 + 7) != '\0') {
    FUN_71019e8b20(&lStack_a0,param_5,puVar1 + 4,param_7);
    uVar10 = (ulong)local_96;
    if (uVar10 != 0xff) {
      lVar12 = *plVar14;
      piVar9 = DAT_7103a5c420;
      if ((lVar12 != 0) && (lVar15 = *(long *)(lVar12 + uVar10 * 8 + 8), lVar15 != 0)) {
        piVar9 = (int *)(lVar15 + 0x150);
      }
      uVar5 = piVar9[1];
      if (-1 < (int)uVar5) {
        puVar16 = (uint *)*puVar4;
        lVar15 = *(long *)(puVar16 + 2);
        if (*puVar16 <= uVar5) {
          uVar5 = 0;
        }
        if ((((lVar15 != 0) &&
             (lVar18 = lVar15 + (ulong)uVar5 * 0x10, *(int *)(lVar18 + 4) == *piVar9)) &&
            (lVar18 = *(long *)(lVar18 + 8), lVar18 != 0)) &&
           ((local_98 < *(byte *)(lVar18 + 0x24) && (local_97 < *(byte *)(lVar18 + 0x25))))) {
          uVar5 = puVar1[6] - 2;
          if (uVar5 < 0x10) {
            uVar20 = -(ulong)(uVar5 >> 0x1f) & 0xfffffffc00000000 | (ulong)uVar5 << 2;
            iVar6 = *(int *)(&DAT_71032b4850 + uVar20);
            iVar19 = *(int *)(&DAT_71032b4890 + uVar20);
          }
          else {
            iVar6 = 0;
            iVar19 = 0;
          }
          piVar9 = DAT_7103a5c420;
          if ((lVar12 != 0) && (lVar18 = *(long *)(lVar12 + uVar10 * 8 + 8), lVar18 != 0)) {
            piVar9 = (int *)(lVar18 + 0x150);
          }
          uVar5 = piVar9[1];
          if (-1 < (int)uVar5) {
            if (*puVar16 <= uVar5) {
              uVar5 = 0;
            }
            if ((((*(int *)(lVar15 + (ulong)uVar5 * 0x10 + 4) == *piVar9) &&
                 (lVar15 = *(long *)(lVar15 + (ulong)uVar5 * 0x10 + 8), lVar15 != 0)) &&
                ((uint)local_98 < (uint)*(byte *)(lVar15 + 0x24))) &&
               ((uint)local_97 < (uint)*(byte *)(lVar15 + 0x25))) {
              uVar5 = *param_7;
              if (uVar5 == 1) {
                iVar17 = iVar6;
                iVar6 = -iVar19;
              }
              else if (uVar5 == 3) {
                iVar17 = -iVar6;
                iVar6 = iVar19;
              }
              else {
                iVar17 = iVar19;
                if (uVar5 == 2) {
                  iVar17 = -iVar19;
                  iVar6 = -iVar6;
                }
              }
              uVar5 = (uint)local_98 + iVar17;
              uVar2 = (uint)local_97 + iVar6;
              local_a8 = (undefined1)uVar5;
              local_a7 = (undefined1)uVar2;
              local_a6 = local_96;
              local_b0 = DAT_7103a5a2a8 + 0x10;
              piVar9 = DAT_7103a5c420;
              if ((lVar12 != 0) && (lVar12 = *(long *)(lVar12 + uVar10 * 8 + 8), lVar12 != 0)) {
                piVar9 = (int *)(lVar12 + 0x150);
              }
              uVar8 = piVar9[1];
              if (-1 < (int)uVar8) {
                if (*puVar16 <= uVar8) {
                  uVar8 = 0;
                }
                if (((*(long *)(puVar16 + 2) != 0) &&
                    (lVar12 = *(long *)(puVar16 + 2) + (ulong)uVar8 * 0x10,
                    *(int *)(lVar12 + 4) == *piVar9)) &&
                   ((lVar12 = *(long *)(lVar12 + 8), lVar12 != 0 &&
                    (((uVar5 & 0xff) < (uint)*(byte *)(lVar12 + 0x24) &&
                     ((uVar2 & 0xff) < (uint)*(byte *)(lVar12 + 0x25))))))) {
                  fVar25 = FUN_7101d0f140((long)&lStack_a0);
                  fVar31 = fVar21;
                  fVar30 = param_3;
                  fVar22 = FUN_7101d0f140((long)&local_b0);
                  if (fVar25 <= fVar22) {
                    fVar22 = fVar25;
                  }
                  fVar25 = fVar30;
                  if (param_3 <= fVar30) {
                    fVar25 = param_3;
                  }
                  fVar29 = fVar31;
                  fVar26 = FUN_7101d0f350((long)&lStack_a0);
                  fVar23 = fVar30;
                  fVar27 = fVar29;
                  fVar24 = FUN_7101d0f350((long)&local_b0);
                  local_c8 = 0;
                  local_c0 = 0;
                  local_b8 = 0;
                  if (fVar26 <= fVar24) {
                    fVar26 = fVar24;
                  }
                  fVar24 = fVar22 - fVar26;
                  if (fVar30 <= fVar23) {
                    fVar30 = fVar23;
                  }
                  fVar23 = -fVar24;
                  if (0.0 <= fVar24) {
                    fVar23 = fVar24;
                  }
                  fVar28 = fVar25 - fVar30;
                  fVar24 = -fVar28;
                  if (0.0 <= fVar28) {
                    fVar24 = fVar28;
                  }
                  uVar5 = *param_7 & 0xfffffffd;
                  fVar28 = fVar24;
                  if (uVar5 != 0) {
                    fVar28 = fVar23;
                    fVar23 = fVar24;
                  }
                  fVar23 = fVar23 + param_2;
                  if ((0.0 <= fVar23) && (fVar28 = fVar28 + param_2, 0.0 <= fVar28)) {
                    if (fVar21 <= fVar31) {
                      fVar31 = fVar21;
                    }
                    if (fVar29 <= fVar27) {
                      fVar29 = fVar27;
                    }
                    fVar21 = fVar28;
                    if (uVar5 != 0) {
                      fVar21 = fVar23;
                    }
                    local_c8 = CONCAT44((fVar31 + fVar29) * 0.5,(fVar22 + fVar26) * 0.5);
                    local_c0 = CONCAT44(*param_7,(fVar25 + fVar30) * 0.5);
                    if (uVar5 != 0) {
                      fVar23 = fVar28;
                    }
                    local_b8 = CONCAT44(fVar21,fVar23);
                  }
                  if ((int)param_4[0x26] < (int)param_4[0x25]) {
                    uVar5 = (uint)*(byte *)(param_5 + 10);
                    if (uVar5 == 0xff) {
                      uVar5 = 0xffffffff;
                    }
                    FUN_71019f42b8(param_4,&local_c8,uVar5);
                    iVar6 = (int)param_4[0x26];
                    iVar19 = (int)param_4[0x25];
                    if (iVar6 < iVar19) {
                      iVar17 = *(int *)((long)param_4 + 300) + iVar6;
                      *(int *)(param_4 + 0x26) = iVar6 + 1;
                      iVar6 = 0;
                      if (iVar19 <= iVar17) {
                        iVar6 = iVar19;
                      }
                      plVar14 = (long *)(param_4[0x24] + (long)(iVar17 - iVar6) * 0x18);
                      plVar14[2] = local_b8;
                      *plVar14 = local_c8;
                      plVar14[1] = local_c0;
                    }
                  }
                }
              }
              goto LAB_71019f495c;
            }
          }
          local_a8 = 0;
          local_b0 = DAT_7103a5a2a8 + 0x10;
        }
      }
    }
  }
LAB_71019f495c:
  iVar6 = FUN_71019fc360(*param_6);
  fVar21 = 2.0;
  if (iVar6 == 0x14) {
    fVar31 = 0.0;
  }
  else if (iVar6 == 0x18) {
    fVar31 = 4.0;
  }
  else {
    if (iVar6 != 0x17) {
      return;
    }
    fVar21 = 1.0;
    fVar31 = fVar21;
  }
  pfVar7 = (float *)FUN_7101d33efc(param_5);
  uVar5 = *param_7;
  if (uVar5 == 1) {
    pfVar11 = (float *)&DAT_71032b47c4;
    fVar22 = fVar21 + *pfVar7;
    fVar21 = pfVar7[2] - fVar31;
  }
  else if (uVar5 == 3) {
    pfVar11 = (float *)&DAT_71032b47dc;
    fVar22 = *pfVar7 - fVar21;
    fVar21 = fVar31 + pfVar7[2];
  }
  else if (uVar5 == 2) {
    pfVar11 = (float *)&DAT_71032b47d0;
    fVar22 = *pfVar7 - fVar31;
    fVar21 = pfVar7[2] - fVar21;
  }
  else {
    fVar22 = fVar31 + *pfVar7;
    pfVar11 = (float *)&UNK_71032b47b8;
    if (uVar5 != 0) {
      pfVar11 = DAT_7103a5a248;
    }
    fVar21 = fVar21 + pfVar7[2];
  }
  fVar30 = *pfVar11;
  fVar25 = pfVar11[1];
  fVar26 = pfVar11[2];
  fVar31 = SQRT(fVar25 * fVar25 + fVar30 * fVar30 + fVar26 * fVar26);
  if (9.094947e-14 < fVar31) {
    fVar28 = 1.0 / fVar31;
    fVar23 = fVar30 * 3.1298223e-20;
    fVar27 = fVar25 * 3.1298223e-20;
    fVar29 = fVar26 * 3.1298223e-20;
    fVar32 = SQRT(fVar27 * fVar27 + fVar23 * fVar23 + fVar29 * fVar29);
    fVar24 = 1.0 / fVar32;
    fVar26 = fVar26 * fVar28;
    fVar25 = fVar25 * fVar28;
    fVar30 = fVar30 * fVar28;
    if (fVar31 == INFINITY) {
      fVar31 = fVar32 * 3.1950695e+19;
      fVar26 = fVar29 * fVar24;
      fVar25 = fVar27 * fVar24;
      fVar30 = fVar23 * fVar24;
    }
    if (0.0 < fVar31) goto LAB_71019f4af0;
  }
  fVar25 = 0.0;
  fVar26 = 1.0;
  fVar30 = 0.0;
LAB_71019f4af0:
  *(float *)(param_4 + 0x36) = fVar22;
  *(float *)(param_4 + 0x39) = fVar30;
  *(float *)(param_4 + 0x37) = fVar21;
  fVar27 = fVar25 * 0.0 - fVar30;
  *(float *)((long)param_4 + 0x1cc) = fVar25;
  *(float *)(param_4 + 0x3a) = fVar26;
  fVar23 = fVar26 + fVar25 * -0.0;
  *(undefined4 *)((long)param_4 + 0x1b4) = param_1;
  fVar31 = fVar26 * -0.0 + fVar30 * 0.0;
  *(float *)((long)param_4 + 0x1c4) = fVar27;
  *(float *)((long)param_4 + 0x1bc) = fVar23;
  *(float *)(param_4 + 0x38) = fVar31;
  param_4[0x43] = (ulong)(uint)fVar21;
  param_4[0x42] = CONCAT44(param_1,fVar22);
  param_4[0x3f] = 0;
  param_4[0x3e] = 0x3f80000000000000;
  *(float *)(param_4 + 0x40) = fVar30;
  *(float *)((long)param_4 + 0x204) = fVar25;
  *(float *)(param_4 + 0x41) = fVar26;
  *(undefined4 *)((long)param_4 + 0x20c) = 0;
  *(float *)(param_4 + 0x3c) = fVar23;
  *(float *)((long)param_4 + 0x1e4) = fVar31;
  *(float *)(param_4 + 0x3d) = fVar27;
  *(undefined4 *)((long)param_4 + 0x1ec) = 0;
  return;
}



float FUN_71019f5060(long *param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  long lVar4;
  float fVar5;
  float *pfVar6;
  float fVar7;
  float fVar8;
  float fVar9;
  float fVar10;
  
  fVar7 = 0.0;
  if (*(char *)((long)param_1 + 0x224) != '\0') {
    return 0.0;
  }
  iVar2 = (int)param_1[2];
  if (iVar2 != 0) {
    if (iVar2 < 1) {
      return 3.4028235e+38;
    }
    lVar4 = *param_1 + (long)*(int *)((long)param_1 + 0xc) * 0x18;
    fVar5 = 3.4028235e+38;
    fVar8 = fVar5;
    fVar7 = fVar5;
    iVar3 = *(int *)((long)param_1 + 0xc);
    do {
      iVar1 = 0;
      if ((int)param_1[1] <= iVar3) {
        iVar1 = (int)param_1[1];
      }
      pfVar6 = (float *)(lVar4 + (long)iVar1 * -0x18);
      lVar4 = lVar4 + 0x18;
      fVar9 = *pfVar6 - pfVar6[4] * 0.5;
      fVar10 = pfVar6[2] - pfVar6[5] * 0.5;
      if (fVar7 <= fVar9) {
        fVar9 = fVar7;
      }
      fVar7 = fVar9;
      fVar9 = pfVar6[1];
      if (fVar8 <= pfVar6[1]) {
        fVar9 = fVar8;
      }
      fVar8 = fVar9;
      if (fVar5 <= fVar10) {
        fVar10 = fVar5;
      }
      fVar5 = fVar10;
      iVar2 = iVar2 + -1;
      iVar3 = iVar3 + 1;
    } while (iVar2 != 0);
  }
  return fVar7;
}



float FUN_71019f5120(long *param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  long lVar4;
  float fVar5;
  float *pfVar6;
  float fVar7;
  float fVar8;
  float fVar9;
  float fVar10;
  
  fVar7 = 0.0;
  if (*(char *)((long)param_1 + 0x224) != '\0') {
    return 0.0;
  }
  iVar2 = (int)param_1[2];
  if (iVar2 != 0) {
    if (iVar2 < 1) {
      return -3.4028235e+38;
    }
    lVar4 = *param_1 + (long)*(int *)((long)param_1 + 0xc) * 0x18;
    fVar5 = -3.4028235e+38;
    fVar8 = fVar5;
    fVar7 = fVar5;
    iVar3 = *(int *)((long)param_1 + 0xc);
    do {
      iVar1 = 0;
      if ((int)param_1[1] <= iVar3) {
        iVar1 = (int)param_1[1];
      }
      pfVar6 = (float *)(lVar4 + (long)iVar1 * -0x18);
      lVar4 = lVar4 + 0x18;
      fVar9 = *pfVar6 + pfVar6[4] * 0.5;
      fVar10 = pfVar6[2] + pfVar6[5] * 0.5;
      if (fVar9 <= fVar7) {
        fVar9 = fVar7;
      }
      fVar7 = fVar9;
      fVar9 = pfVar6[1];
      if (pfVar6[1] <= fVar8) {
        fVar9 = fVar8;
      }
      fVar8 = fVar9;
      if (fVar10 <= fVar5) {
        fVar10 = fVar5;
      }
      fVar5 = fVar10;
      iVar2 = iVar2 + -1;
      iVar3 = iVar3 + 1;
    } while (iVar2 != 0);
  }
  return fVar7;
}



undefined8 FUN_71019f5578(long *param_1,int param_2)

{
  int iVar1;
  int iVar2;
  long *plVar3;
  float *pfVar4;
  int *piVar5;
  long lVar6;
  uint uVar7;
  float fVar8;
  float fVar9;
  float fVar10;
  float fVar11;
  float fVar12;
  float fVar13;
  
  if ((-1 < param_2) && (param_2 < (int)param_1[2])) {
    iVar1 = *(int *)((long)param_1 + 0xc) + param_2;
    iVar2 = 0;
    if ((int)param_1[1] <= iVar1) {
      iVar2 = (int)param_1[1];
    }
    piVar5 = DAT_7103a5c420;
    if (((*(uint *)(param_1 + 0x44) < 0x100) && (DAT_71041fd400 != 0)) &&
       (lVar6 = *(long *)(DAT_71041fd400 + (ulong)*(uint *)(param_1 + 0x44) * 8 + 8), lVar6 != 0)) {
      piVar5 = (int *)(lVar6 + 0x150);
    }
    uVar7 = piVar5[1];
    if ((-1 < (int)uVar7) && (lVar6 = *(long *)(DAT_71040e7d48 + 2), lVar6 != 0)) {
      if (*DAT_71040e7d48 <= uVar7) {
        uVar7 = 0;
      }
      if (*(int *)(lVar6 + (ulong)uVar7 * 0x10 + 4) == *piVar5) {
        pfVar4 = (float *)(*param_1 + (long)(iVar1 - iVar2) * 0x18);
        fVar8 = *pfVar4;
        fVar9 = pfVar4[2];
        fVar10 = pfVar4[4];
        fVar13 = pfVar4[5];
        plVar3 = *(long **)(lVar6 + (ulong)uVar7 * 0x10 + 8);
        if (plVar3 == (long *)0x0) {
          plVar3 = FUN_7100bc6230();
        }
        fVar11 = 1.0;
        if (*(int *)((long)plVar3 + 0x9c) != 2) {
          fVar11 = 1.5;
        }
        fVar12 = 2.0;
        if (*(int *)((long)plVar3 + 0x9c) != 1) {
          fVar12 = fVar11;
        }
        return CONCAT44((int)((1.0 / fVar12) *
                             ((fVar9 - fVar13 * 0.5) + 0.1 + fVar12 * 0.5 +
                             (float)*(int *)((long)plVar3 + 0x2c) * fVar12)),
                        (int)((1.0 / fVar12) *
                             ((fVar8 - fVar10 * 0.5) + 0.1 + fVar12 * 0.5 +
                             (float)(int)plVar3[5] * fVar12)));
      }
    }
  }
  return 0;
}



undefined8 FUN_71019f56f4(long *param_1,int param_2)

{
  int iVar1;
  int iVar2;
  long *plVar3;
  float *pfVar4;
  int *piVar5;
  long lVar6;
  uint uVar7;
  float fVar8;
  float fVar9;
  float fVar10;
  float fVar11;
  float fVar12;
  float fVar13;
  
  if ((-1 < param_2) && (param_2 < (int)param_1[2])) {
    iVar1 = *(int *)((long)param_1 + 0xc) + param_2;
    iVar2 = 0;
    if ((int)param_1[1] <= iVar1) {
      iVar2 = (int)param_1[1];
    }
    piVar5 = DAT_7103a5c420;
    if (((*(uint *)(param_1 + 0x44) < 0x100) && (DAT_71041fd400 != 0)) &&
       (lVar6 = *(long *)(DAT_71041fd400 + (ulong)*(uint *)(param_1 + 0x44) * 8 + 8), lVar6 != 0)) {
      piVar5 = (int *)(lVar6 + 0x150);
    }
    uVar7 = piVar5[1];
    if ((-1 < (int)uVar7) && (lVar6 = *(long *)(DAT_71040e7d48 + 2), lVar6 != 0)) {
      if (*DAT_71040e7d48 <= uVar7) {
        uVar7 = 0;
      }
      if (*(int *)(lVar6 + (ulong)uVar7 * 0x10 + 4) == *piVar5) {
        pfVar4 = (float *)(*param_1 + (long)(iVar1 - iVar2) * 0x18);
        fVar8 = *pfVar4;
        fVar9 = pfVar4[2];
        fVar10 = pfVar4[4];
        fVar13 = pfVar4[5];
        plVar3 = *(long **)(lVar6 + (ulong)uVar7 * 0x10 + 8);
        if (plVar3 == (long *)0x0) {
          plVar3 = FUN_7100bc6230();
        }
        fVar11 = 1.0;
        if (*(int *)((long)plVar3 + 0x9c) != 2) {
          fVar11 = 1.5;
        }
        fVar12 = 2.0;
        if (*(int *)((long)plVar3 + 0x9c) != 1) {
          fVar12 = fVar11;
        }
        return CONCAT44((int)((1.0 / fVar12) *
                             (fVar9 + fVar13 * 0.5 + -0.1 + fVar12 * 0.5 +
                             (float)*(int *)((long)plVar3 + 0x2c) * fVar12)),
                        (int)((1.0 / fVar12) *
                             (fVar8 + fVar10 * 0.5 + -0.1 + fVar12 * 0.5 +
                             (float)(int)plVar3[5] * fVar12)));
      }
    }
  }
  return 0;
}



void FUN_71019f5880(long param_1)

{
  FUN_71019fa128(param_1 + 0xf00);
  FUN_71019fa128(param_1 + 0xe10);
  FUN_71019fa128(param_1 + 0xd20);
  FUN_71019fa128(param_1 + 0xc30);
  FUN_71019fa128(param_1 + 0xb40);
  FUN_71019fa128(param_1 + 0xa50);
  FUN_71019fa128(param_1 + 0x960);
  FUN_71019fa128(param_1 + 0x870);
  FUN_71019fa128(param_1 + 0x780);
  FUN_71019fa128(param_1 + 0x690);
  FUN_71019fa128(param_1 + 0x5a0);
  FUN_71019fa128(param_1 + 0x4b0);
  FUN_71019fa128(param_1 + 0x3c0);
  FUN_71019fa128(param_1 + 0x2d0);
  FUN_71019fa128(param_1 + 0x1e0);
  FUN_71019fa128(param_1 + 0xf0);
  FUN_71019fa128(param_1);
  return;
}



undefined8 FUN_71019f59c0(long param_1,ulong param_2,uint param_3,uint param_4)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  byte bVar4;
  byte bVar5;
  byte bVar6;
  uint uVar7;
  uint uVar8;
  long *plVar9;
  bool bVar10;
  bool bVar11;
  uint uVar12;
  long *plVar13;
  undefined *puVar14;
  undefined8 *puVar15;
  undefined8 *puVar16;
  int *piVar17;
  ulong uVar18;
  uint *puVar19;
  long lVar20;
  long lVar21;
  uint uVar22;
  undefined8 *local_58;
  
  plVar9 = DAT_7103a5a160;
  puVar16 = DAT_7103a59c40;
  bVar4 = *(byte *)(param_1 + 10);
  uVar18 = (ulong)bVar4;
  if (bVar4 == 0xff) {
    return 0;
  }
  lVar20 = *DAT_7103a5a160;
  piVar17 = DAT_7103a5c420;
  if ((lVar20 != 0) && (lVar21 = *(long *)(lVar20 + uVar18 * 8 + 8), lVar21 != 0)) {
    piVar17 = (int *)(lVar21 + 0x150);
  }
  uVar12 = piVar17[1];
  if ((int)uVar12 < 0) {
    return 0;
  }
  lVar21 = *(long *)((uint *)*DAT_7103a59c40 + 2);
  if (*(uint *)*DAT_7103a59c40 <= uVar12) {
    uVar12 = 0;
  }
  if (lVar21 == 0) {
    return 0;
  }
  lVar21 = lVar21 + (ulong)uVar12 * 0x10;
  if (*(int *)(lVar21 + 4) != *piVar17) {
    return 0;
  }
  lVar21 = *(long *)(lVar21 + 8);
  if (lVar21 == 0) {
    return 0;
  }
  bVar5 = *(byte *)(param_1 + 8);
  if (*(byte *)(lVar21 + 0x24) <= bVar5) {
    return 0;
  }
  bVar6 = *(byte *)(param_1 + 9);
  if (*(byte *)(lVar21 + 0x25) <= bVar6) {
    return 0;
  }
  if ((param_2 & 1) == 0) {
LAB_71019f5b90:
    lVar20 = *(long *)(*(long *)(*plVar9 + 0x818) + 0x18);
    if (lVar20 == 0) goto LAB_71019f5be4;
    lVar20 = lVar20 + 8;
    lVar21 = *(long *)(lVar20 + uVar18 * 0x10 + 8);
    if (lVar21 == 0) goto LAB_71019f5be4;
    puVar19 = (uint *)(lVar20 + uVar18 * 0x10);
    uVar12 = *puVar19;
    if (((uVar12 <= *(byte *)(param_1 + 8)) || (puVar19[1] <= (uint)*(byte *)(param_1 + 9))) ||
       (puVar14 = *(undefined **)
                   (lVar21 + (long)(int)((uint)*(byte *)(param_1 + 8) +
                                        uVar12 * *(byte *)(param_1 + 9)) * 8),
       puVar14 == (undefined *)0x0)) goto LAB_71019f5be4;
  }
  else {
    lVar20 = *(long *)(*(long *)(lVar20 + 0x818) + 0x20);
    if ((lVar20 == 0) || ((char)bVar4 < '\0')) {
LAB_71019f5af0:
      plVar13 = FUN_7100c83958();
    }
    else {
      uVar12 = *(uint *)(lVar20 + uVar18 * 4 + 8);
      if (uVar12 == 0xffffffff) goto LAB_71019f5af0;
      puVar19 = (uint *)(lVar20 + 0x208);
      if (uVar12 < 7) {
        puVar19 = puVar19 + (ulong)uVar12 * 4;
      }
      if (*(long *)(puVar19 + 2) == 0) goto LAB_71019f5af0;
      if (((*puVar19 <= (uint)bVar5) || (puVar19[1] <= (uint)bVar6)) ||
         (plVar13 = *(long **)(*(long *)(puVar19 + 2) +
                              (long)(int)((uint)bVar5 + *puVar19 * (uint)bVar6) * 8),
         plVar13 == (long *)0x0)) goto LAB_71019f5af0;
    }
    if ((int)plVar13[4] == 5) {
      return 0;
    }
    bVar4 = *(byte *)(param_1 + 10);
    if ((((ulong)bVar4 == 0xff) ||
        (lVar20 = *(long *)(*(long *)(*plVar9 + 0x818) + 0x20), lVar20 == 0)) ||
       ((char)bVar4 < '\0')) {
LAB_71019f5b74:
      plVar13 = FUN_7100c83958();
    }
    else {
      uVar12 = *(uint *)(lVar20 + (ulong)bVar4 * 4 + 8);
      if (uVar12 == 0xffffffff) goto LAB_71019f5b74;
      puVar19 = (uint *)(lVar20 + 0x208);
      if (uVar12 < 7) {
        puVar19 = puVar19 + (ulong)uVar12 * 4;
      }
      if (*(long *)(puVar19 + 2) == 0) goto LAB_71019f5b74;
      if (((*puVar19 <= (uint)*(byte *)(param_1 + 8)) ||
          (puVar19[1] <= (uint)*(byte *)(param_1 + 9))) ||
         (plVar13 = *(long **)(*(long *)(puVar19 + 2) +
                              (long)(int)((uint)*(byte *)(param_1 + 8) +
                                         *puVar19 * (uint)*(byte *)(param_1 + 9)) * 8),
         plVar13 == (long *)0x0)) goto LAB_71019f5b74;
    }
    if ((int)plVar13[4] == 8) {
      return 0;
    }
    uVar18 = (ulong)*(byte *)(param_1 + 10);
    if (*(byte *)(param_1 + 10) != 0xff) goto LAB_71019f5b90;
LAB_71019f5be4:
    puVar14 = FUN_7100bc46e0();
  }
  puVar19 = DAT_7103a673c0;
  uVar12 = *(uint *)(puVar14 + 8);
  uVar22 = *DAT_7103a673c0;
  if (*DAT_7103a673c0 == 0xffffffff) {
    uVar22 = 1000000;
    lVar20 = FUN_7101ceb0d0(*DAT_7103a59ec8);
    uVar2 = *(uint *)(lVar20 + 0x2c);
    if (uVar2 != 0) {
      uVar7 = 0;
      if (uVar2 != 0) {
        uVar7 = 0x495ff388 / uVar2;
      }
      uVar7 = 0x495ff388 - uVar7 * uVar2;
      uVar8 = uVar7;
      while (iVar3 = *(int *)(*(long *)(lVar20 + 0x20) +
                             (-(ulong)(uVar8 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar8 << 4)),
            iVar3 != 0) {
        if (iVar3 == 0x495ff388) {
          lVar20 = *(long *)(*(long *)(lVar20 + 0x20) + (long)(int)uVar8 * 0x10 + 8);
          uVar22 = 1000000;
          if (lVar20 != 0) {
            uVar22 = *(uint *)(lVar20 + 0x10);
            *puVar19 = uVar22;
          }
          break;
        }
        uVar1 = 0;
        if ((int)(uVar8 + 1) < (int)uVar2) {
          uVar1 = uVar8 + 1;
        }
        uVar8 = uVar1;
        if (uVar1 == uVar7) break;
      }
    }
  }
  if (uVar22 <= uVar12) {
    return 0;
  }
  bVar4 = *(byte *)(param_1 + 10);
  if ((param_4 & 1) == 0) {
    if ((bVar4 == 0xff) || (lVar20 = *(long *)(*(long *)(*plVar9 + 0x818) + 0x10), lVar20 == 0)) {
LAB_71019f5d3c:
      puVar16 = FUN_7100bc42c8();
    }
    else {
      puVar19 = (uint *)(lVar20 + 8 + (ulong)bVar4 * 0x10);
      if (*(long *)(puVar19 + 2) == 0) goto LAB_71019f5d3c;
      bVar4 = *(byte *)(param_1 + 9);
      bVar10 = false;
      bVar11 = false;
      if ((uint)*(byte *)(param_1 + 8) < *puVar19) {
        bVar11 = (uint)bVar4 <= puVar19[1];
        bVar10 = puVar19[1] == (uint)bVar4;
      }
      if ((!bVar11 || bVar10) ||
         (puVar16 = *(undefined8 **)
                     (*(long *)(puVar19 + 2) +
                     (long)(int)((uint)*(byte *)(param_1 + 8) + *puVar19 * (uint)bVar4) * 8),
         puVar16 == (undefined8 *)0x0)) goto LAB_71019f5d3c;
    }
    if (((((((*(byte *)(puVar16 + 2) >> 1 & 1) == 0) &&
           ((*(byte *)((long)puVar16 + 0x1c) >> 1 & 1) == 0)) &&
          ((*(byte *)(puVar16 + 5) >> 1 & 1) == 0)) &&
         (((*(byte *)((long)puVar16 + 0x34) >> 1 & 1) == 0 &&
          ((*(byte *)(puVar16 + 8) >> 1 & 1) == 0)))) &&
        (((*(byte *)((long)puVar16 + 0x4c) >> 1 & 1) == 0 &&
         (((*(byte *)(puVar16 + 0xb) >> 1 & 1) == 0 &&
          ((*(byte *)((long)puVar16 + 100) >> 1 & 1) == 0)))))) &&
       ((*(byte *)(puVar16 + 0xe) >> 1 & 1) == 0)) {
      return 1;
    }
    uVar12 = FUN_7101d0f560(param_1);
    if ((uVar12 & 1) != 0) {
      FUN_7101d340a4(&local_58,param_1);
      puVar16 = local_58;
      if (local_58 == (undefined8 *)0x0) {
        puVar16 = FUN_7100bc42c8();
      }
      piVar17 = (int *)FUN_7101d0cdf0(param_1,0);
      uVar12 = FUN_7101d16820((long)puVar16,piVar17);
      if ((uVar12 & 1) == 0) {
        return 1;
      }
    }
    goto LAB_71019f5dc4;
  }
  if ((bVar4 == 0xff) || (lVar20 = *(long *)(*(long *)(*plVar9 + 0x818) + 0x10), lVar20 == 0)) {
LAB_71019f5c50:
    puVar15 = FUN_7100bc42c8();
  }
  else {
    puVar19 = (uint *)(lVar20 + 8 + (ulong)bVar4 * 0x10);
    if (*(long *)(puVar19 + 2) == 0) goto LAB_71019f5c50;
    bVar4 = *(byte *)(param_1 + 9);
    bVar10 = false;
    bVar11 = false;
    if ((uint)*(byte *)(param_1 + 8) < *puVar19) {
      bVar11 = (uint)bVar4 <= puVar19[1];
      bVar10 = puVar19[1] == (uint)bVar4;
    }
    if ((!bVar11 || bVar10) ||
       (puVar15 = *(undefined8 **)
                   (*(long *)(puVar19 + 2) +
                   (long)(int)((uint)*(byte *)(param_1 + 8) + *puVar19 * (uint)bVar4) * 8),
       puVar15 == (undefined8 *)0x0)) goto LAB_71019f5c50;
  }
  uVar12 = *(uint *)((long)puVar15 + 0xc);
  if ((int)uVar12 < 0) {
    return 1;
  }
  lVar20 = *(long *)((uint *)*puVar16 + 2);
  if (lVar20 == 0) {
    return 1;
  }
  if (*(uint *)*puVar16 <= uVar12) {
    uVar12 = 0;
  }
  if (*(int *)(lVar20 + (ulong)uVar12 * 0x10 + 4) != *(int *)(puVar15 + 1)) {
    return 1;
  }
  uVar12 = FUN_7101d0f560(param_1);
  if ((uVar12 & 1) != 0) {
    return 1;
  }
LAB_71019f5dc4:
  bVar10 = FUN_71019f3f00(param_1);
  if ((!bVar10) && (((param_3 & 1) == 0 || (bVar10 = FUN_71019f5e60(param_1), !bVar10)))) {
    return 0;
  }
  return 1;
}



bool FUN_71019f5e60(long param_1)

{
  uint *puVar1;
  undefined *puVar2;
  uint uVar3;
  byte bVar4;
  long lVar5;
  long *plVar6;
  int iVar7;
  bool bVar8;
  bool bVar9;
  undefined8 *puVar10;
  long lVar11;
  long local_310;
  undefined1 auStack_308 [32];
  uint local_2e8;
  int local_1b4;
  undefined4 local_84;
  undefined8 local_80;
  undefined8 local_78;
  undefined8 local_70;
  undefined8 local_68;
  undefined8 local_60;
  undefined8 local_58;
  undefined1 uStack_31;
  
  if (((ulong)*(byte *)(param_1 + 10) != 0xff) &&
     (lVar11 = *(long *)(*(long *)(DAT_71041fd400 + 0x818) + 0x10), lVar11 != 0)) {
    puVar1 = (uint *)(lVar11 + 8 + (ulong)*(byte *)(param_1 + 10) * 0x10);
    if (*(long *)(puVar1 + 2) != 0) {
      bVar4 = *(byte *)(param_1 + 9);
      bVar8 = false;
      bVar9 = false;
      if ((uint)*(byte *)(param_1 + 8) < *puVar1) {
        bVar9 = (uint)bVar4 <= puVar1[1];
        bVar8 = puVar1[1] == (uint)bVar4;
      }
      if ((bVar9 && !bVar8) &&
         (puVar10 = *(undefined8 **)
                     (*(long *)(puVar1 + 2) +
                     (long)(int)((uint)*(byte *)(param_1 + 8) + *puVar1 * (uint)bVar4) * 8),
         puVar10 != (undefined8 *)0x0)) goto LAB_71019f5ecc;
    }
  }
  puVar10 = FUN_7100bc42c8();
LAB_71019f5ecc:
  uVar3 = *(uint *)((long)puVar10 + 0xc);
  if ((-1 < (int)uVar3) && (lVar11 = *(long *)(DAT_71040e7d48 + 2), lVar11 != 0)) {
    if (*DAT_71040e7d48 <= uVar3) {
      uVar3 = 0;
    }
    if (*(int *)(lVar11 + (ulong)uVar3 * 0x10 + 4) == *(int *)(puVar10 + 1)) {
      puVar10 = *(undefined8 **)(lVar11 + (ulong)uVar3 * 0x10 + 8);
      if (puVar10 == (undefined8 *)0x0) {
        puVar10 = FUN_7100baff84();
      }
      plVar6 = DAT_7103a5c098;
      lVar11 = (long)puVar10 + (long)*(int *)(puVar10 + 0x40) + 0x200;
      if (*(int *)(puVar10 + 0x40) != 0 && lVar11 != 0) {
        puVar2 = (undefined *)
                 (*(long *)(*DAT_7103a5c098 + 0x88) + (ulong)*(uint *)(lVar11 + 0x30) * 0x2c0 +
                 0xb5fb0);
        if (100 < *(uint *)(lVar11 + 0x30)) {
          puVar2 = &DAT_7104015420;
        }
        FUN_7100d23610(&local_310,(long)puVar2);
        iVar7 = local_1b4;
        lVar5 = DAT_7103a59ed8;
        local_80 = *(undefined8 *)(puVar2 + 0x290);
        local_78 = *(undefined8 *)(puVar2 + 0x298);
        local_84 = *(undefined4 *)(puVar2 + 0x28c);
        local_68 = *(undefined8 *)(puVar2 + 0x2a8);
        local_60 = *(undefined8 *)(puVar2 + 0x2b0);
        local_58 = *(undefined8 *)(puVar2 + 0x2b8);
        local_70 = *(undefined8 *)(puVar2 + 0x2a0);
        bVar8 = (int)local_80 == 0xd;
        local_310 = DAT_7103a59ed8 + 0x10;
        if (local_2e8 != 0xffffffff) {
          (**(code **)(&DAT_710398f918 + (ulong)local_2e8 * 8))(&uStack_31,auStack_308);
        }
        if (iVar7 != 0) {
          return bVar8;
        }
        puVar10 = (undefined8 *)
                  (*(long *)(*plVar6 + 0x88) + (ulong)*(uint *)(lVar11 + 0x90) * 0x2b8 + 0x11a478);
        if (100 < *(uint *)(lVar11 + 0x90)) {
          puVar10 = &DAT_7104015c28;
        }
        FUN_7100d23610(&local_310,(long)puVar10);
        local_80 = puVar10[0x52];
        local_84 = *(undefined4 *)((long)puVar10 + 0x28c);
        local_68 = puVar10[0x55];
        local_70 = puVar10[0x54];
        local_60 = puVar10[0x56];
        local_78 = puVar10[0x53];
        bVar8 = local_1b4 != 0 && (int)local_80 == 0xd;
        local_310 = lVar5 + 0x10;
        if (local_2e8 == 0xffffffff) {
          return bVar8;
        }
        (**(code **)(&DAT_710398f918 + (ulong)local_2e8 * 8))(&uStack_31,auStack_308);
        return bVar8;
      }
    }
  }
  return false;
}



undefined8 FUN_71019f60e0(long param_1,uint *param_2,int *param_3)

{
  undefined4 *puVar1;
  uint uVar2;
  char cVar3;
  undefined8 *puVar4;
  long *plVar5;
  bool bVar6;
  uint uVar7;
  int iVar8;
  int *piVar9;
  char *pcVar10;
  int *piVar11;
  uint uVar12;
  long lVar13;
  long lVar14;
  int iVar15;
  int iVar16;
  ulong uVar17;
  uint *puVar18;
  int iVar19;
  long lVar20;
  uint uVar21;
  int iVar22;
  int iVar23;
  int local_a4;
  int local_a0;
  long local_88;
  byte local_80;
  byte local_7f;
  byte local_7e;
  long lStack_78;
  byte local_70;
  byte local_6f;
  byte local_6e;
  byte abStack_68 [8];
  
  plVar5 = DAT_7103a5a160;
  puVar4 = DAT_7103a59c40;
  if ((ulong)*(byte *)(param_1 + 10) == 0xff) {
    return 0;
  }
  piVar9 = DAT_7103a5c420;
  if ((*DAT_7103a5a160 != 0) &&
     (lVar13 = *(long *)(*DAT_7103a5a160 + (ulong)*(byte *)(param_1 + 10) * 8 + 8), lVar13 != 0)) {
    piVar9 = (int *)(lVar13 + 0x150);
  }
  uVar12 = piVar9[1];
  if (-1 < (int)uVar12) {
    lVar13 = *(long *)((uint *)*DAT_7103a59c40 + 2);
    if (*(uint *)*DAT_7103a59c40 <= uVar12) {
      uVar12 = 0;
    }
    if ((((lVar13 != 0) && (lVar13 = lVar13 + (ulong)uVar12 * 0x10, *(int *)(lVar13 + 4) == *piVar9)
         ) && (lVar13 = *(long *)(lVar13 + 8), lVar13 != 0)) &&
       ((*(byte *)(param_1 + 8) < *(byte *)(lVar13 + 0x24) &&
        (*(byte *)(param_1 + 9) < *(byte *)(lVar13 + 0x25))))) {
      uVar12 = *param_2;
      if (uVar12 < 0x54) {
        pcVar10 = *(char **)(DAT_7103a5b098 + (ulong)uVar12 * 8 + 0x600);
      }
      else {
        pcVar10 = "";
      }
      if (((*pcVar10 == 'I') && (pcVar10[1] == 's')) &&
         ((pcVar10[2] == 'l' &&
          (((pcVar10[3] == 'a' && (pcVar10[4] == 'n')) && (pcVar10[5] == 'd')))))) {
        FUN_71019f3b88(abStack_68,param_1);
        uVar7 = FUN_71019fc360(*param_2);
        if (uVar7 < 0x19) {
          puVar1 = &DAT_71040e58d8 + (ulong)uVar7 * 8;
          cVar3 = (&DAT_71040e58e4)[(ulong)uVar7 * 0x20];
        }
        else {
          puVar1 = &DAT_71040e58d8;
          cVar3 = DAT_71040e58e4;
        }
        if (cVar3 != '\0') {
          FUN_71019e8b20(&lStack_78,param_1,puVar1,param_3);
          piVar9 = DAT_7103a5c420;
          if ((ulong)local_6e != 0xff) {
            piVar11 = DAT_7103a5c420;
            if (*plVar5 == 0) {
              uVar7 = DAT_7103a5c420[1];
            }
            else {
              lVar13 = *(long *)(*plVar5 + (ulong)local_6e * 8 + 8);
              if (lVar13 != 0) {
                piVar11 = (int *)(lVar13 + 0x150);
              }
              uVar7 = piVar11[1];
            }
            if (-1 < (int)uVar7) {
              lVar13 = *(long *)((uint *)*puVar4 + 2);
              if (*(uint *)*puVar4 <= uVar7) {
                uVar7 = 0;
              }
              if (((lVar13 != 0) &&
                  (lVar13 = lVar13 + (ulong)uVar7 * 0x10, *(int *)(lVar13 + 4) == *piVar11)) &&
                 ((lVar13 = *(long *)(lVar13 + 8), lVar13 != 0 &&
                  ((local_70 < *(byte *)(lVar13 + 0x24) && (local_6f < *(byte *)(lVar13 + 0x25))))))
                 ) {
                uVar7 = puVar1[2] - 2;
                if (uVar7 < 0x10) {
                  uVar17 = -(ulong)(uVar7 >> 0x1f) & 0xfffffffc00000000 | (ulong)uVar7 << 2;
                  iVar8 = *(int *)(&DAT_71032b4978 + uVar17);
                  local_a4 = *(int *)(&DAT_71032b49b8 + uVar17);
                }
                else {
                  iVar8 = 0;
                  local_a4 = 0;
                }
                iVar15 = 0;
                lVar13 = DAT_7103a5a2a8 + 0x10;
                do {
                  iVar23 = 0;
                  do {
                    uVar17 = (ulong)local_6e;
                    if (local_6e == 0xff) {
                      return 0;
                    }
                    piVar11 = piVar9;
                    if ((*plVar5 != 0) &&
                       (lVar14 = *(long *)(*plVar5 + uVar17 * 8 + 8), lVar14 != 0)) {
                      piVar11 = (int *)(lVar14 + 0x150);
                    }
                    uVar7 = piVar11[1];
                    if ((int)uVar7 < 0) {
                      return 0;
                    }
                    puVar18 = (uint *)*puVar4;
                    if (uVar7 < *puVar18) {
                      lVar14 = *(long *)(puVar18 + 2);
                    }
                    else {
                      uVar7 = 0;
                      lVar14 = *(long *)(puVar18 + 2);
                    }
                    if (lVar14 == 0) {
                      return 0;
                    }
                    lVar14 = lVar14 + (ulong)uVar7 * 0x10;
                    if (*(int *)(lVar14 + 4) != *piVar11) {
                      return 0;
                    }
                    lVar14 = *(long *)(lVar14 + 8);
                    if (lVar14 == 0) {
                      return 0;
                    }
                    if (*(byte *)(lVar14 + 0x24) <= local_70) {
                      return 0;
                    }
                    if (*(byte *)(lVar14 + 0x25) <= local_6f) {
                      return 0;
                    }
                    iVar22 = *param_3;
                    iVar19 = -iVar15;
                    iVar16 = iVar23;
                    if (iVar22 != 1) {
                      if (iVar22 == 2) {
                        iVar19 = -iVar23;
                        iVar16 = -iVar15;
                      }
                      else {
                        iVar19 = iVar23;
                        iVar16 = iVar15;
                        if (iVar22 == 3) {
                          iVar19 = iVar15;
                          iVar16 = -iVar23;
                        }
                      }
                    }
                    uVar7 = (uint)local_70 + iVar16;
                    uVar2 = (uint)local_6f + iVar19;
                    lVar14 = *plVar5;
                    local_80 = (byte)uVar7;
                    local_7f = (byte)uVar2;
                    local_7e = local_6e;
                    piVar11 = piVar9;
                    if ((lVar14 != 0) && (lVar20 = *(long *)(lVar14 + uVar17 * 8 + 8), lVar20 != 0))
                    {
                      piVar11 = (int *)(lVar20 + 0x150);
                    }
                    uVar21 = piVar11[1];
                    if ((int)uVar21 < 0) {
                      return 0;
                    }
                    puVar18 = (uint *)*puVar4;
                    if (uVar21 < *puVar18) {
                      lVar20 = *(long *)(puVar18 + 2);
                    }
                    else {
                      uVar21 = 0;
                      lVar20 = *(long *)(puVar18 + 2);
                    }
                    if (lVar20 == 0) {
                      return 0;
                    }
                    lVar20 = lVar20 + (ulong)uVar21 * 0x10;
                    if (*(int *)(lVar20 + 4) != *piVar11) {
                      return 0;
                    }
                    lVar20 = *(long *)(lVar20 + 8);
                    if (lVar20 == 0) {
                      return 0;
                    }
                    if ((uint)*(byte *)(lVar20 + 0x24) <= (uVar7 & 0xff)) {
                      return 0;
                    }
                    if ((uint)*(byte *)(lVar20 + 0x25) <= (uVar2 & 0xff)) {
                      return 0;
                    }
                    local_88 = lVar13;
                    if (*param_2 - 0x14 < 3) {
LAB_71019f64e4:
                      iVar22 = 7;
LAB_71019f64e8:
                      lVar14 = *(long *)(*(long *)(lVar14 + 0x818) + 0x20);
                      if (lVar14 == 0) {
                        return 0;
                      }
                      if ((char)local_6e < '\0') {
                        return 0;
                      }
                      uVar21 = *(uint *)(lVar14 + uVar17 * 4 + 8);
                      if (uVar21 == 0xffffffff) {
                        return 0;
                      }
                      puVar18 = (uint *)(lVar14 + 0x208);
                      if (uVar21 < 7) {
                        puVar18 = puVar18 + (ulong)uVar21 * 4;
                      }
                      if (*(long *)(puVar18 + 2) == 0) {
                        return 0;
                      }
                      if (*puVar18 <= (uVar7 & 0xff)) {
                        return 0;
                      }
                      if (puVar18[1] <= (uVar2 & 0xff)) {
                        return 0;
                      }
                      lVar14 = *(long *)(*(long *)(puVar18 + 2) +
                                        (long)(int)((uVar7 & 0xff) + *puVar18 * (uVar2 & 0xff)) * 8)
                      ;
                      if (lVar14 == 0) {
                        return 0;
                      }
                      if (*(int *)(lVar14 + 0x20) != iVar22) {
                        return 0;
                      }
                      bVar6 = FUN_71019f3f00((long)&local_88);
                      if (bVar6) {
                        return 0;
                      }
                      uVar17 = (ulong)local_7e;
                      if (local_7e == 0xff) {
                        return 0;
                      }
                      lVar14 = *plVar5;
                    }
                    else {
                      if (*param_2 - 0x17 < 2) {
                        if (iVar23 + puVar1[1] == 0) {
                          iVar22 = 8;
                          goto LAB_71019f64e8;
                        }
                        if (iVar23 + puVar1[1] == 1) goto LAB_71019f64e4;
                      }
                      iVar22 = 0x1d;
                      lVar14 = *plVar5;
                    }
                    piVar11 = piVar9;
                    if ((lVar14 != 0) && (lVar14 = *(long *)(lVar14 + uVar17 * 8 + 8), lVar14 != 0))
                    {
                      piVar11 = (int *)(lVar14 + 0x150);
                    }
                    uVar7 = piVar11[1];
                    if ((int)uVar7 < 0) {
                      return 0;
                    }
                    puVar18 = (uint *)*puVar4;
                    if (uVar7 < *puVar18) {
                      lVar14 = *(long *)(puVar18 + 2);
                    }
                    else {
                      uVar7 = 0;
                      lVar14 = *(long *)(puVar18 + 2);
                    }
                    if (lVar14 == 0) {
                      return 0;
                    }
                    lVar14 = lVar14 + (ulong)uVar7 * 0x10;
                    if (*(int *)(lVar14 + 4) != *piVar11) {
                      return 0;
                    }
                    lVar14 = *(long *)(lVar14 + 8);
                    if (lVar14 == 0) {
                      return 0;
                    }
                    if (*(byte *)(lVar14 + 0x24) <= local_80) {
                      return 0;
                    }
                    if (*(byte *)(lVar14 + 0x25) <= local_7f) {
                      return 0;
                    }
                    uVar17 = FUN_71019f59c0((long)&local_88,(ulong)(iVar22 == 0x1d),
                                            (uint)(uVar12 == 0x11),0);
                    if ((uVar17 & 1) == 0) {
                      return 0;
                    }
                    bVar6 = FUN_71019f3d80(abStack_68,(long)&local_88);
                    if (!bVar6) {
                      return 0;
                    }
                    iVar23 = iVar23 + 1;
                  } while (iVar8 + 1 != iVar23);
                  bVar6 = iVar15 != local_a4;
                  iVar15 = iVar15 + 1;
                } while (bVar6);
                if (*(char *)(puVar1 + 7) == '\0') {
                  return 1;
                }
                FUN_71019e8b20(&lStack_78,param_1,puVar1 + 4,param_3);
                piVar9 = DAT_7103a5c420;
                if ((ulong)local_6e != 0xff) {
                  piVar11 = DAT_7103a5c420;
                  if ((*plVar5 != 0) &&
                     (lVar13 = *(long *)(*plVar5 + (ulong)local_6e * 8 + 8), lVar13 != 0)) {
                    piVar11 = (int *)(lVar13 + 0x150);
                  }
                  uVar7 = piVar11[1];
                  if (-1 < (int)uVar7) {
                    lVar13 = *(long *)((uint *)*puVar4 + 2);
                    if (*(uint *)*puVar4 <= uVar7) {
                      uVar7 = 0;
                    }
                    if ((((lVar13 != 0) &&
                         (lVar13 = lVar13 + (ulong)uVar7 * 0x10, *(int *)(lVar13 + 4) == *piVar11))
                        && (lVar13 = *(long *)(lVar13 + 8), lVar13 != 0)) &&
                       ((local_70 < *(byte *)(lVar13 + 0x24) &&
                        (local_6f < *(byte *)(lVar13 + 0x25))))) {
                      uVar7 = puVar1[6] - 2;
                      if (uVar7 < 0x10) {
                        uVar17 = -(ulong)(uVar7 >> 0x1f) & 0xfffffffc00000000 | (ulong)uVar7 << 2;
                        iVar8 = *(int *)(&DAT_71032b4978 + uVar17);
                        local_a0 = *(int *)(&DAT_71032b49b8 + uVar17);
                      }
                      else {
                        iVar8 = 0;
                        local_a0 = 0;
                      }
                      iVar15 = 0;
                      lVar13 = DAT_7103a5a2a8 + 0x10;
                      do {
                        iVar23 = 0;
                        do {
                          uVar17 = (ulong)local_6e;
                          if (local_6e == 0xff) {
                            return 0;
                          }
                          piVar11 = piVar9;
                          if ((*plVar5 != 0) &&
                             (lVar14 = *(long *)(*plVar5 + uVar17 * 8 + 8), lVar14 != 0)) {
                            piVar11 = (int *)(lVar14 + 0x150);
                          }
                          uVar7 = piVar11[1];
                          if ((int)uVar7 < 0) {
                            return 0;
                          }
                          puVar18 = (uint *)*puVar4;
                          if (uVar7 < *puVar18) {
                            lVar14 = *(long *)(puVar18 + 2);
                          }
                          else {
                            uVar7 = 0;
                            lVar14 = *(long *)(puVar18 + 2);
                          }
                          if (lVar14 == 0) {
                            return 0;
                          }
                          lVar14 = lVar14 + (ulong)uVar7 * 0x10;
                          if (*(int *)(lVar14 + 4) != *piVar11) {
                            return 0;
                          }
                          lVar14 = *(long *)(lVar14 + 8);
                          if (lVar14 == 0) {
                            return 0;
                          }
                          if (*(byte *)(lVar14 + 0x24) <= local_70) {
                            return 0;
                          }
                          if (*(byte *)(lVar14 + 0x25) <= local_6f) {
                            return 0;
                          }
                          iVar22 = *param_3;
                          iVar19 = -iVar15;
                          iVar16 = iVar23;
                          if (iVar22 != 1) {
                            if (iVar22 == 2) {
                              iVar19 = -iVar23;
                              iVar16 = -iVar15;
                            }
                            else {
                              iVar19 = iVar23;
                              iVar16 = iVar15;
                              if (iVar22 == 3) {
                                iVar19 = iVar15;
                                iVar16 = -iVar23;
                              }
                            }
                          }
                          uVar7 = (uint)local_70 + iVar16;
                          uVar2 = (uint)local_6f + iVar19;
                          lVar14 = *plVar5;
                          local_80 = (byte)uVar7;
                          local_7f = (byte)uVar2;
                          local_7e = local_6e;
                          piVar11 = piVar9;
                          if ((lVar14 != 0) &&
                             (lVar20 = *(long *)(lVar14 + uVar17 * 8 + 8), lVar20 != 0)) {
                            piVar11 = (int *)(lVar20 + 0x150);
                          }
                          uVar21 = piVar11[1];
                          if ((int)uVar21 < 0) {
                            return 0;
                          }
                          puVar18 = (uint *)*puVar4;
                          if (uVar21 < *puVar18) {
                            lVar20 = *(long *)(puVar18 + 2);
                          }
                          else {
                            uVar21 = 0;
                            lVar20 = *(long *)(puVar18 + 2);
                          }
                          if (lVar20 == 0) {
                            return 0;
                          }
                          lVar20 = lVar20 + (ulong)uVar21 * 0x10;
                          if (*(int *)(lVar20 + 4) != *piVar11) {
                            return 0;
                          }
                          lVar20 = *(long *)(lVar20 + 8);
                          if (lVar20 == 0) {
                            return 0;
                          }
                          if ((uint)*(byte *)(lVar20 + 0x24) <= (uVar7 & 0xff)) {
                            return 0;
                          }
                          if ((uint)*(byte *)(lVar20 + 0x25) <= (uVar2 & 0xff)) {
                            return 0;
                          }
                          local_88 = lVar13;
                          if (*param_2 - 0x14 < 3) {
LAB_71019f6974:
                            iVar22 = 7;
LAB_71019f6978:
                            lVar14 = *(long *)(*(long *)(lVar14 + 0x818) + 0x20);
                            if (lVar14 == 0) {
                              return 0;
                            }
                            if ((char)local_6e < '\0') {
                              return 0;
                            }
                            uVar21 = *(uint *)(lVar14 + uVar17 * 4 + 8);
                            if (uVar21 == 0xffffffff) {
                              return 0;
                            }
                            puVar18 = (uint *)(lVar14 + 0x208);
                            if (uVar21 < 7) {
                              puVar18 = puVar18 + (ulong)uVar21 * 4;
                            }
                            if (*(long *)(puVar18 + 2) == 0) {
                              return 0;
                            }
                            if (*puVar18 <= (uVar7 & 0xff)) {
                              return 0;
                            }
                            if (puVar18[1] <= (uVar2 & 0xff)) {
                              return 0;
                            }
                            lVar14 = *(long *)(*(long *)(puVar18 + 2) +
                                              (long)(int)((uVar7 & 0xff) + *puVar18 * (uVar2 & 0xff)
                                                         ) * 8);
                            if (lVar14 == 0) {
                              return 0;
                            }
                            if (*(int *)(lVar14 + 0x20) != iVar22) {
                              return 0;
                            }
                            bVar6 = FUN_71019f3f00((long)&local_88);
                            if (bVar6) {
                              return 0;
                            }
                            uVar17 = (ulong)local_7e;
                            if (local_7e == 0xff) {
                              return 0;
                            }
                          }
                          else {
                            if (*param_2 - 0x17 < 2) {
                              if (iVar23 + puVar1[5] == 0) {
                                iVar22 = 8;
                                goto LAB_71019f6978;
                              }
                              if (iVar23 + puVar1[5] == 1) goto LAB_71019f6974;
                            }
                            iVar22 = 0x1d;
                          }
                          piVar11 = piVar9;
                          if ((*plVar5 != 0) &&
                             (lVar14 = *(long *)(*plVar5 + uVar17 * 8 + 8), lVar14 != 0)) {
                            piVar11 = (int *)(lVar14 + 0x150);
                          }
                          uVar7 = piVar11[1];
                          if ((int)uVar7 < 0) {
                            return 0;
                          }
                          puVar18 = (uint *)*puVar4;
                          if (uVar7 < *puVar18) {
                            lVar14 = *(long *)(puVar18 + 2);
                          }
                          else {
                            uVar7 = 0;
                            lVar14 = *(long *)(puVar18 + 2);
                          }
                          if (lVar14 == 0) {
                            return 0;
                          }
                          lVar14 = lVar14 + (ulong)uVar7 * 0x10;
                          if (*(int *)(lVar14 + 4) != *piVar11) {
                            return 0;
                          }
                          lVar14 = *(long *)(lVar14 + 8);
                          if (lVar14 == 0) {
                            return 0;
                          }
                          if (*(byte *)(lVar14 + 0x24) <= local_80) {
                            return 0;
                          }
                          if (*(byte *)(lVar14 + 0x25) <= local_7f) {
                            return 0;
                          }
                          uVar17 = FUN_71019f59c0((long)&local_88,(ulong)(iVar22 == 0x1d),
                                                  (uint)(uVar12 == 0x11),0);
                          if ((uVar17 & 1) == 0) {
                            return 0;
                          }
                          bVar6 = FUN_71019f3d80(abStack_68,(long)&local_88);
                          if (!bVar6) {
                            return 0;
                          }
                          iVar23 = iVar23 + 1;
                        } while (iVar8 + 1 != iVar23);
                        bVar6 = iVar15 == local_a0;
                        iVar15 = iVar15 + 1;
                        if (bVar6) {
                          return 1;
                        }
                      } while( true );
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  return 0;
}



undefined8
FUN_71019f6b70(undefined1 param_1 [16],undefined1 param_2 [16],float param_3,long *param_4,
              long param_5,uint *param_6,uint *param_7)

{
  undefined4 *puVar1;
  int *piVar2;
  uint uVar3;
  undefined8 *puVar4;
  long *plVar5;
  int *piVar6;
  long *plVar7;
  long lVar8;
  char *pcVar9;
  ulong uVar10;
  long lVar11;
  long lVar12;
  uint *puVar13;
  long lVar14;
  long lStack_78;
  byte local_70;
  byte local_6f;
  byte local_6e;
  byte local_68 [8];
  
  piVar6 = DAT_7103a5c420;
  plVar5 = DAT_7103a5a160;
  puVar4 = DAT_7103a59c40;
  if ((ulong)*(byte *)(param_5 + 10) == 0xff) {
    return 0;
  }
  piVar2 = DAT_7103a5c420;
  if (*DAT_7103a5a160 == 0) {
    uVar3 = DAT_7103a5c420[1];
  }
  else {
    lVar8 = *(long *)(*DAT_7103a5a160 + (ulong)*(byte *)(param_5 + 10) * 8 + 8);
    if (lVar8 != 0) {
      piVar2 = (int *)(lVar8 + 0x150);
    }
    uVar3 = piVar2[1];
  }
  if (-1 < (int)uVar3) {
    lVar8 = *(long *)((uint *)*DAT_7103a59c40 + 2);
    if (*(uint *)*DAT_7103a59c40 <= uVar3) {
      uVar3 = 0;
    }
    if ((((lVar8 != 0) && (lVar8 = lVar8 + (ulong)uVar3 * 0x10, *(int *)(lVar8 + 4) == *piVar2)) &&
        (lVar8 = *(long *)(lVar8 + 8), lVar8 != 0)) &&
       ((*(byte *)(param_5 + 8) < *(byte *)(lVar8 + 0x24) &&
        (*(byte *)(param_5 + 9) < *(byte *)(lVar8 + 0x25))))) {
      if (*param_6 < 0x54) {
        pcVar9 = *(char **)(DAT_7103a5b098 + (ulong)*param_6 * 8 + 0x600);
      }
      else {
        pcVar9 = "";
      }
      if (((*pcVar9 == 'I') && (pcVar9[1] == 's')) &&
         ((pcVar9[2] == 'l' && (((pcVar9[3] == 'a' && (pcVar9[4] == 'n')) && (pcVar9[5] == 'd'))))))
      {
        FUN_71019f3b88(local_68,param_5);
        if (*param_6 - 3 < 0x16) {
          lVar8 = *(long *)(&DAT_71032b49f8 + (long)(int)(*param_6 - 3) * 8);
        }
        else {
          lVar8 = 0;
        }
        lVar14 = 0;
        do {
          puVar1 = (undefined4 *)(lVar8 * 0xf0 + 0x71040e3f88 + lVar14);
          if (*(char *)(puVar1 + 2) == '\0') {
            return 0;
          }
          FUN_71019e8b20(&lStack_78,param_5,puVar1,param_7);
          uVar10 = (ulong)local_6e;
          if (uVar10 != 0xff) {
            lVar11 = *plVar5;
            piVar2 = piVar6;
            if (lVar11 == 0) {
              uVar3 = piVar6[1];
            }
            else {
              lVar12 = *(long *)(lVar11 + uVar10 * 8 + 8);
              if (lVar12 != 0) {
                piVar2 = (int *)(lVar12 + 0x150);
              }
              uVar3 = piVar2[1];
            }
            if (-1 < (int)uVar3) {
              puVar13 = (uint *)*puVar4;
              if (uVar3 < *puVar13) {
                lVar12 = *(long *)(puVar13 + 2);
              }
              else {
                uVar3 = 0;
                lVar12 = *(long *)(puVar13 + 2);
              }
              if (((lVar12 != 0) &&
                  (lVar12 = lVar12 + (ulong)uVar3 * 0x10, *(int *)(lVar12 + 4) == *piVar2)) &&
                 ((lVar12 = *(long *)(lVar12 + 8), lVar12 != 0 &&
                  ((local_70 < *(byte *)(lVar12 + 0x24) && (local_6f < *(byte *)(lVar12 + 0x25))))))
                 ) {
                lVar11 = *(long *)(*(long *)(lVar11 + 0x818) + 0x20);
                if ((lVar11 == 0) || ((char)local_6e < '\0')) {
LAB_71019f6e30:
                  plVar7 = FUN_7100c83958();
                }
                else {
                  uVar3 = *(uint *)(lVar11 + uVar10 * 4 + 8);
                  if (uVar3 == 0xffffffff) goto LAB_71019f6e30;
                  puVar13 = (uint *)(lVar11 + 0x208);
                  if (uVar3 < 7) {
                    puVar13 = puVar13 + (ulong)uVar3 * 4;
                  }
                  if (*(long *)(puVar13 + 2) == 0) goto LAB_71019f6e30;
                  if (((*puVar13 <= (uint)local_70) || (puVar13[1] <= (uint)local_6f)) ||
                     (plVar7 = *(long **)(*(long *)(puVar13 + 2) +
                                         (long)(int)((uint)local_70 + *puVar13 * (uint)local_6f) * 8
                                         ), plVar7 == (long *)0x0)) goto LAB_71019f6e30;
                }
                if ((local_68[0] == (*(byte *)((long)plVar7 + 0x24) & 1)) &&
                   (uVar10 = FUN_71019f60e0((long)&lStack_78,param_6,(int *)param_7),
                   (uVar10 & 1) != 0)) {
                  if (param_4 != (long *)0x0) {
                    lVar8 = FUN_7101d33efc((long)&lStack_78);
                    FUN_71019f4540(*(undefined4 *)(lVar8 + 4),0.0,param_3,param_4,(long)&lStack_78,
                                   (int *)param_6,param_7);
                  }
                  return 1;
                }
              }
            }
          }
          lVar14 = lVar14 + 0xc;
        } while (lVar14 != 0xf0);
      }
    }
  }
  return 0;
}



uint FUN_71019f6ed0(undefined1 param_1 [16],undefined1 param_2 [16],float param_3,long *param_4,
                   long param_5,uint *param_6,uint *param_7)

{
  ulong uVar1;
  undefined8 uVar2;
  int *piVar3;
  char *pcVar4;
  uint uVar5;
  long lVar6;
  undefined1 extraout_q0 [16];
  undefined1 extraout_q0_00 [16];
  undefined1 extraout_q0_01 [16];
  uint local_28;
  uint local_24;
  
  if ((ulong)*(byte *)(param_5 + 10) == 0xff) {
    return 0;
  }
  piVar3 = DAT_7103a5c420;
  if ((*DAT_7103a5a160 != 0) &&
     (lVar6 = *(long *)(*DAT_7103a5a160 + (ulong)*(byte *)(param_5 + 10) * 8 + 8), lVar6 != 0)) {
    piVar3 = (int *)(lVar6 + 0x150);
  }
  uVar5 = piVar3[1];
  if (-1 < (int)uVar5) {
    if (*DAT_71040e7d48 <= uVar5) {
      uVar5 = 0;
    }
    if ((((*(long *)(DAT_71040e7d48 + 2) != 0) &&
         (lVar6 = *(long *)(DAT_71040e7d48 + 2) + (ulong)uVar5 * 0x10,
         *(int *)(lVar6 + 4) == *piVar3)) && (lVar6 = *(long *)(lVar6 + 8), lVar6 != 0)) &&
       ((*(byte *)(param_5 + 8) < *(byte *)(lVar6 + 0x24) &&
        (*(byte *)(param_5 + 9) < *(byte *)(lVar6 + 0x25))))) {
      if (*param_6 < 0x54) {
        pcVar4 = *(char **)(&DAT_7103872318 + (ulong)*param_6 * 8);
      }
      else {
        pcVar4 = "";
      }
      if (((*pcVar4 == 'I') && (pcVar4[1] == 's')) &&
         ((pcVar4[2] == 'l' && (((pcVar4[3] == 'a' && (pcVar4[4] == 'n')) && (pcVar4[5] == 'd'))))))
      {
        uVar1 = FUN_71019f6b70(param_1,param_2,param_3,param_4,param_5,param_6,param_7);
        if ((uVar1 & 1) == 0) {
          uVar1 = FUN_71019f6b70(extraout_q0,param_2,param_3,param_4,param_5,param_6,param_7 + 1);
          if ((uVar1 & 1) == 0) {
            uVar5 = param_7[1] - 1;
            if (uVar5 < 3) {
              local_24 = *(uint *)(&DAT_71032b4b8c + (long)(int)uVar5 * 4);
            }
            else {
              local_24 = 2;
            }
            uVar1 = FUN_71019f6b70(extraout_q0_00,param_2,param_3,param_4,param_5,param_6,&local_24)
            ;
            if ((uVar1 & 1) == 0) {
              if (*param_7 - 1 < 3) {
                local_28 = *(uint *)(&DAT_71032b4b8c + (long)(int)(*param_7 - 1) * 4);
              }
              else {
                local_28 = 2;
              }
              uVar2 = FUN_71019f6b70(extraout_q0_01,param_2,param_3,param_4,param_5,param_6,
                                     &local_28);
              uVar5 = (uint)uVar2;
              goto LAB_71019f707c;
            }
          }
        }
        uVar5 = 1;
        goto LAB_71019f707c;
      }
    }
  }
  uVar5 = 0;
LAB_71019f707c:
  return uVar5 & 1;
}



// WARNING: Type propagation algorithm not settling

undefined8
FUN_71019f70f0(undefined1 param_1 [16],undefined1 param_2 [16],float param_3,long *param_4,
              int *param_5,int *param_6,uint *param_7)

{
  int *piVar1;
  undefined8 *******pppppppuVar2;
  bool bVar3;
  bool bVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  undefined8 *puVar8;
  ulong uVar9;
  int *piVar10;
  long *plVar11;
  float *pfVar12;
  uint uVar13;
  undefined8 ******ppppppuVar14;
  int iVar15;
  char cVar16;
  long lVar17;
  ulong uVar18;
  undefined8 *puVar19;
  int *piVar20;
  char cVar21;
  undefined4 uVar22;
  char cVar23;
  uint uVar24;
  long lVar25;
  long lVar26;
  int iVar27;
  undefined8 uVar28;
  ulong uVar29;
  uint *puVar30;
  ulong uVar31;
  int iVar32;
  int iVar33;
  undefined4 *puVar34;
  int *piVar35;
  float fVar36;
  float fVar37;
  float fVar38;
  float fVar39;
  float fVar40;
  float unaff_s9;
  float fVar41;
  float fVar42;
  float unaff_s13;
  float fVar43;
  int *local_200;
  ulong local_1f0;
  byte abStack_1d8 [16];
  long local_1c8;
  undefined2 local_1c0;
  byte local_1be;
  undefined8 local_1b8;
  undefined8 local_1b0;
  undefined8 local_1a8;
  undefined4 local_1a0;
  int local_198;
  int iStack_194;
  undefined8 *local_190;
  undefined8 *******local_188;
  undefined8 *******local_180;
  undefined8 *******local_178 [2];
  undefined8 ******local_168 [2];
  undefined8 *****local_158 [2];
  undefined8 ****local_148 [2];
  undefined8 ***local_138 [2];
  undefined8 **local_128 [2];
  undefined8 *local_118 [2];
  undefined8 local_108 [2];
  undefined8 local_f8 [8];
  long lStack_b8;
  byte local_b0;
  byte local_af;
  byte local_ae;
  
  uVar5 = param_5[1];
  if ((int)uVar5 < 0) {
    return 0;
  }
  lVar17 = *(long *)((uint *)*DAT_7103a59c40 + 2);
  if (lVar17 == 0) {
    return 0;
  }
  if (*(uint *)*DAT_7103a59c40 <= uVar5) {
    uVar5 = 0;
  }
  if (*(int *)(lVar17 + (ulong)uVar5 * 0x10 + 4) != *param_5) {
    return 0;
  }
  puVar8 = *(undefined8 **)(lVar17 + (ulong)uVar5 * 0x10 + 8);
  if (puVar8 == (undefined8 *)0x0) {
    puVar8 = FUN_7100baff84();
  }
  iVar7 = *(int *)(puVar8 + 0x13);
  lVar17 = (long)iVar7 + (long)(puVar8 + 0x13);
  uVar5 = 0;
  if (iVar7 == 0 || lVar17 == 0) {
    return 0;
  }
  fVar36 = *(float *)(lVar17 + 0x30);
  uVar13 = 0;
  if (fVar36 != (float)(int)fVar36) {
    uVar13 = (uint)(fVar36 < 0.0);
  }
  iVar7 = (int)fVar36 - uVar13;
  if (iVar7 < 0xb4) {
    if ((int)fVar36 != uVar13) {
      if (iVar7 != 0x5a) {
        return 0;
      }
      uVar5 = 1;
    }
  }
  else if (iVar7 == 0xb4) {
    uVar5 = 2;
  }
  else if (iVar7 == 0x10e) {
    uVar5 = 3;
  }
  else if (iVar7 != 0x168) {
    return 0;
  }
  if (((*param_6 - 0x33U < 0x10) || (*param_6 - 0x50U < 2)) && (*param_7 != uVar5)) {
    return 0;
  }
  FUN_71019f85c0(&lStack_b8,param_5,param_6,(int *)param_7);
  if ((ulong)local_ae == 0xff) {
    return 0;
  }
  piVar20 = DAT_7103a5c420;
  if (*DAT_7103a5a160 == 0) {
    uVar5 = DAT_7103a5c420[1];
  }
  else {
    lVar17 = *(long *)(*DAT_7103a5a160 + (ulong)local_ae * 8 + 8);
    if (lVar17 != 0) {
      piVar20 = (int *)(lVar17 + 0x150);
    }
    uVar5 = piVar20[1];
  }
  if ((int)uVar5 < 0) {
    return 0;
  }
  lVar17 = *(long *)((uint *)*DAT_7103a59c40 + 2);
  if (*(uint *)*DAT_7103a59c40 <= uVar5) {
    uVar5 = 0;
  }
  if (lVar17 == 0) {
    return 0;
  }
  lVar17 = lVar17 + (ulong)uVar5 * 0x10;
  if (*(int *)(lVar17 + 4) != *piVar20) {
    return 0;
  }
  lVar17 = *(long *)(lVar17 + 8);
  if (lVar17 == 0) {
    return 0;
  }
  if (*(byte *)(lVar17 + 0x24) <= local_b0) {
    return 0;
  }
  if (*(byte *)(lVar17 + 0x25) <= local_af) {
    return 0;
  }
  FUN_71019f3b88(abStack_1d8,(long)&lStack_b8);
  FUN_7100eeed40((long *)&local_198,param_5);
  local_1a8 = 0x8000000080000000;
  local_1a0 = 0xffffffff;
  local_1b8 = DAT_7103a674a0 + 0x10;
  local_1b0 = 0x7fffffff7fffffff;
  FUN_7101d350d0((long)&local_1b8,(long)&local_198);
  iVar7 = *param_6;
  uVar5 = 0;
  uVar22 = 2;
  uVar31 = 3;
  uVar18 = 1;
  uVar9 = 0x10;
  uVar29 = 5;
  switch(iVar7) {
  case 0x22:
  case 0x23:
  case 0x33:
    goto switchD_71019f7360_caseD_22;
  case 0x24:
  case 0x34:
    break;
  case 0x25:
  case 0x35:
    uVar18 = 2;
    break;
  case 0x26:
    uVar18 = 3;
    break;
  case 0x27:
    goto switchD_71019f7360_caseD_27;
  case 0x28:
  case 0x36:
    uVar18 = 4;
    break;
  case 0x29:
  case 0x37:
    uVar18 = 5;
    break;
  case 0x2a:
    goto switchD_71019f7360_caseD_2a;
  case 0x2b:
  case 0x38:
    uVar18 = 6;
    break;
  case 0x2c:
    uVar18 = 7;
    break;
  case 0x2d:
    uVar18 = 8;
    break;
  case 0x2e:
    uVar18 = 9;
    break;
  case 0x2f:
    uVar18 = 10;
    break;
  case 0x30:
    uVar18 = 0xb;
    break;
  case 0x31:
  case 0x39:
    uVar18 = 0xc;
    break;
  case 0x32:
  case 0x3b:
    uVar18 = 0xd;
    break;
  case 0x3a:
    uVar22 = 5;
    uVar9 = 0xc;
    goto switchD_71019f7360_caseD_3f;
  case 0x3c:
    uVar18 = 0xe;
    break;
  case 0x3d:
    uVar18 = 0xf;
    break;
  case 0x3e:
    uVar18 = 0x10;
    break;
  case 0x3f:
    goto switchD_71019f7360_caseD_3f;
  case 0x40:
    uVar18 = 0x11;
    break;
  case 0x41:
    uVar18 = 0x12;
    break;
  case 0x42:
    uVar18 = 0x13;
    break;
  default:
    uVar5 = 1;
switchD_71019f7360_caseD_22:
    if (iVar7 == 0x23) {
      uVar22 = 1;
      uVar9 = (ulong)uVar5;
    }
    else if (iVar7 == 0x2a) {
      uVar29 = (ulong)uVar5;
switchD_71019f7360_caseD_2a:
      uVar9 = uVar29;
      uVar22 = 4;
    }
    else {
      uVar31 = (ulong)uVar5;
      uVar18 = (ulong)uVar5;
      if (iVar7 != 0x27) break;
switchD_71019f7360_caseD_27:
      uVar22 = 3;
      uVar9 = uVar31;
    }
    goto switchD_71019f7360_caseD_3f;
  }
  uVar22 = 0;
  uVar9 = uVar18;
switchD_71019f7360_caseD_3f:
  lVar17 = uVar9 * 0x78;
  piVar35 = (int *)(lVar17 + 0x71040e4f78);
  uVar9 = 0;
  piVar20 = piVar35;
  do {
    uVar29 = uVar9;
    if ((char)piVar35[uVar29 * 3 + 2] == '\0') break;
    FUN_71019e8b20(&local_1c8,(long)&lStack_b8,piVar20,param_7);
    if ((((int)(uint)(byte)local_1c0 < (int)local_1b0) ||
        ((int)local_1a8 < (int)(uint)(byte)local_1c0)) ||
       (((int)(uint)local_1c0._1_1_ < local_1b0._4_4_ ||
        (local_1a8._4_4_ < (int)(uint)local_1c0._1_1_)))) {
      if ((ulong)local_1be == 0xff) {
        return 0;
      }
      piVar1 = DAT_7103a5c420;
      if (*DAT_7103a5a160 == 0) {
        uVar5 = DAT_7103a5c420[1];
      }
      else {
        lVar25 = *(long *)(*DAT_7103a5a160 + (ulong)local_1be * 8 + 8);
        if (lVar25 != 0) {
          piVar1 = (int *)(lVar25 + 0x150);
        }
        uVar5 = piVar1[1];
      }
      if ((int)uVar5 < 0) {
        return 0;
      }
      puVar30 = (uint *)*DAT_7103a59c40;
      if (uVar5 < *puVar30) {
        lVar25 = *(long *)(puVar30 + 2);
      }
      else {
        uVar5 = 0;
        lVar25 = *(long *)(puVar30 + 2);
      }
      if (lVar25 == 0) {
        return 0;
      }
      lVar25 = lVar25 + (ulong)uVar5 * 0x10;
      if (*(int *)(lVar25 + 4) != *piVar1) {
        return 0;
      }
      lVar25 = *(long *)(lVar25 + 8);
      if (lVar25 == 0) {
        return 0;
      }
      if ((uint)*(byte *)(lVar25 + 0x24) <= (uint)(byte)local_1c0) {
        return 0;
      }
      if ((uint)*(byte *)(lVar25 + 0x25) <= (uint)local_1c0._1_1_) {
        return 0;
      }
      uVar9 = FUN_71019f59c0((long)&local_1c8,1,0,1);
      if ((uVar9 & 1) == 0) {
        return 0;
      }
      bVar4 = FUN_71019f3d80(abStack_1d8,(long)&local_1c8);
      if (!bVar4) {
        return 0;
      }
    }
    uVar9 = 0;
    do {
      uVar5 = (uint)uVar9;
      if ((char)piVar35[uVar29 * 3 + 2] == '\0') {
        uVar28 = 0;
        piVar20[0] = 0;
        piVar20[1] = 0;
      }
      else {
        uVar28 = *(undefined8 *)piVar20;
      }
      if (3 < uVar5) {
        return 0;
      }
      uVar24 = (uint)((ulong)uVar28 >> 0x20);
      iVar27 = (int)uVar28;
      uVar13 = uVar24;
      iVar7 = iVar27;
      switch(uVar9 & 0xffffffff) {
      case 0:
        uVar13 = uVar24 - 1;
        break;
      case 1:
        uVar13 = uVar24 + 1;
        break;
      case 2:
        iVar7 = iVar27 + -1;
        break;
      case 3:
        iVar7 = iVar27 + 1;
      }
      switch(uVar22) {
      case 1:
      case 3:
        if ((uVar5 != 0 || iVar27 != 0) || uVar24 != 0) break;
        goto LAB_71019f7810;
      case 2:
        if ((uVar5 == 3) && (iVar27 == 1)) {
LAB_71019f76a8:
          if (uVar24 == 1) goto LAB_71019f7810;
        }
        break;
      case 4:
        if ((uVar5 == 2) && ((iVar27 == -1 && (uVar24 < 2)))) goto LAB_71019f7810;
        break;
      case 5:
        if ((uVar5 == 0) && (iVar27 == -1 || iVar27 == 1)) goto LAB_71019f76a8;
      }
      if ((((((((*(char *)(lVar17 + 0x71040e4f80) != '\0') && (iVar7 == *piVar35)) &&
              (uVar13 == *(uint *)(lVar17 + 0x71040e4f7c))) ||
             (((*(char *)(lVar17 + 0x71040e4f8c) != '\0' &&
               (iVar7 == *(int *)(lVar17 + 0x71040e4f84))) &&
              (uVar13 == *(uint *)(lVar17 + 0x71040e4f88))))) ||
            ((((*(char *)(lVar17 + 0x71040e4f98) != '\0' &&
               (iVar7 == *(int *)(lVar17 + 0x71040e4f90))) &&
              (uVar13 == *(uint *)(lVar17 + 0x71040e4f94))) ||
             (((*(char *)(lVar17 + 0x71040e4fa4) != '\0' &&
               (iVar7 == *(int *)(lVar17 + 0x71040e4f9c))) &&
              (uVar13 == *(uint *)(lVar17 + 0x71040e4fa0))))))) ||
           (((*(char *)(lVar17 + 0x71040e4fb0) != '\0' && (iVar7 == *(int *)(lVar17 + 0x71040e4fa8))
             ) && (uVar13 == *(uint *)(lVar17 + 0x71040e4fac))))) ||
          (((((*(char *)(lVar17 + 0x71040e4fbc) != '\0' &&
              (iVar7 == *(int *)(lVar17 + 0x71040e4fb4))) &&
             (uVar13 == *(uint *)(lVar17 + 0x71040e4fb8))) ||
            (((*(char *)(lVar17 + 0x71040e4fc8) != '\0' &&
              (iVar7 == *(int *)(lVar17 + 0x71040e4fc0))) &&
             (uVar13 == *(uint *)(lVar17 + 0x71040e4fc4))))) ||
           (((*(char *)(lVar17 + 0x71040e4fd4) != '\0' && (iVar7 == *(int *)(lVar17 + 0x71040e4fcc))
             ) && (uVar13 == *(uint *)(lVar17 + 0x71040e4fd0))))))) ||
         ((((*(char *)(lVar17 + 0x71040e4fe0) != '\0' && (iVar7 == *(int *)(lVar17 + 0x71040e4fd8)))
           && (uVar13 == *(uint *)(lVar17 + 0x71040e4fdc))) ||
          (((*(char *)(lVar17 + 0x71040e4fec) != '\0' && (iVar7 == *(int *)(lVar17 + 0x71040e4fe4)))
           && (uVar13 == *(uint *)(lVar17 + 0x71040e4fe8))))))) {
LAB_71019f7810:
        if (((ulong)local_1be == 0xff) ||
           (lVar25 = *(long *)(*(long *)(*DAT_7103a5a160 + 0x818) + 0x10), lVar25 == 0)) {
LAB_71019f7860:
          puVar8 = FUN_7100bc42c8();
        }
        else {
          puVar30 = (uint *)(lVar25 + 8 + (ulong)local_1be * 0x10);
          if (*(long *)(puVar30 + 2) == 0) goto LAB_71019f7860;
          bVar4 = false;
          bVar3 = false;
          if ((uint)(byte)local_1c0 < *puVar30) {
            bVar3 = (uint)local_1c0._1_1_ <= puVar30[1];
            bVar4 = puVar30[1] == (uint)local_1c0._1_1_;
          }
          if ((!bVar3 || bVar4) ||
             (puVar8 = *(undefined8 **)
                        (*(long *)(puVar30 + 2) +
                        (long)(int)((uint)(byte)local_1c0 + *puVar30 * (uint)local_1c0._1_1_) * 8),
             puVar8 == (undefined8 *)0x0)) goto LAB_71019f7860;
        }
        switch(*param_7) {
        case 0:
          puVar19 = &DAT_71030bada0;
          break;
        case 1:
          puVar19 = &DAT_71030bab60;
          break;
        case 2:
          puVar19 = &DAT_71030bad20;
          break;
        case 3:
          puVar19 = &DAT_71030b9f80;
          break;
        default:
          goto switchD_71019f7880_default;
        }
        if (uVar5 < 4) {
          lVar25 = puVar19[uVar9];
        }
        else {
switchD_71019f7880_default:
          lVar25 = 1;
        }
        uVar5 = *(uint *)((long)puVar8 + lVar25 * 0xc + 0xc);
        if (-1 < (int)uVar5) {
          lVar26 = *(long *)((uint *)*DAT_7103a59c40 + 2);
          if (lVar26 != 0) {
            uVar13 = uVar5;
            if (*(uint *)*DAT_7103a59c40 <= uVar5) {
              uVar13 = 0;
            }
            piVar1 = (int *)((long)puVar8 + lVar25 * 0xc + 8);
            iVar7 = *(int *)(lVar26 + (ulong)uVar13 * 0x10 + 4);
            if ((iVar7 == *piVar1) && ((iVar7 != *param_5 || (uVar5 != param_5[1])))) {
              piVar10 = (int *)FUN_7101d0cdf0((long)&local_1c8,0);
              if (*(int *)((long)puVar8 + lVar25 * 0xc + 0xc) != piVar10[1]) {
                return 0;
              }
              if (*piVar1 != *piVar10) {
                return 0;
              }
              uVar5 = FUN_7101d0f560((long)&local_1c8);
              if ((uVar5 & 1) == 0) {
                return 0;
              }
            }
          }
        }
      }
      uVar9 = uVar9 + 1;
    } while ((int)uVar9 != 4);
    uVar9 = uVar29 + 1;
    piVar20 = piVar35 + uVar9 * 3;
    local_1f0 = uVar29;
  } while (uVar9 != 10);
  piVar20 = DAT_7103a5c420;
  if (*(long *)(*DAT_7103a5a160 + 8) != 0) {
    piVar20 = (int *)(*(long *)(*DAT_7103a5a160 + 8) + 0x150);
  }
  uVar5 = piVar20[1];
  if ((int)uVar5 < 0) {
LAB_71019f7b64:
    local_1c8 = DAT_7103a5a2a8 + 0x10;
    local_1c0 = *(undefined2 *)(DAT_7103a5ba30 + 8);
    local_1be = *(byte *)(DAT_7103a5ba30 + 10);
  }
  else {
    lVar17 = *(long *)((uint *)*DAT_7103a59c40 + 2);
    if (lVar17 == 0) goto LAB_71019f7b64;
    uVar13 = *(uint *)*DAT_7103a59c40;
    if (uVar13 <= uVar5) {
      uVar5 = 0;
    }
    if (*(int *)(lVar17 + (ulong)uVar5 * 0x10 + 4) != *piVar20) goto LAB_71019f7b64;
    if (*param_6 - 0x22U < 0x21) {
      iVar7 = *(int *)(&DAT_71032b4aa8 + (long)(int)(*param_6 - 0x22U) * 4);
    }
    else {
      iVar7 = 1;
    }
    uVar5 = param_5[1];
    if ((int)uVar5 < 0) {
LAB_71019f7a68:
      puVar8 = FUN_7100baff84();
    }
    else {
      if (uVar13 <= uVar5) {
        uVar5 = 0;
      }
      if ((*(int *)(lVar17 + (ulong)uVar5 * 0x10 + 4) != *param_5) ||
         (puVar8 = *(undefined8 **)(lVar17 + (ulong)uVar5 * 0x10 + 8), puVar8 == (undefined8 *)0x0))
      goto LAB_71019f7a68;
    }
    iVar27 = *(int *)(puVar8 + 0x13);
    if ((iVar27 == 0) || (lVar17 = (long)iVar27 + (long)(puVar8 + 0x13), lVar17 == 0))
    goto LAB_71019f7b64;
    fVar36 = *(float *)(lVar17 + 0x30);
    uVar13 = 0;
    uVar5 = 0;
    if (fVar36 != (float)(int)fVar36) {
      uVar5 = (uint)(fVar36 < 0.0);
    }
    iVar27 = (int)fVar36 - uVar5;
    if (iVar27 < 0xb4) {
      if ((int)fVar36 != uVar5) {
        if (iVar27 != 0x5a) goto LAB_71019f7b64;
        uVar13 = 1;
      }
    }
    else if (iVar27 == 0xb4) {
      uVar13 = 2;
    }
    else if (iVar27 == 0x10e) {
      uVar13 = 3;
    }
    else if (iVar27 != 0x168) goto LAB_71019f7b64;
    if ((((*param_6 - 0x33U < 0x10) || (*param_6 - 0x50U < 2)) && (*param_7 != uVar13)) ||
       (FUN_7101d12500((undefined8 *)&local_198,param_5), (char)local_190 == '\0'))
    goto LAB_71019f7b64;
    uVar5 = iVar7 - 3;
    if (uVar5 < 0xc) {
      uVar9 = -(ulong)(uVar5 >> 0x1f) & 0xfffffffc00000000 | (ulong)uVar5 << 2;
      cVar23 = (char)*(undefined4 *)(&DAT_71032b4b2c + uVar9);
      cVar21 = (char)*(undefined4 *)(&DAT_71032b4b5c + uVar9);
    }
    else {
      cVar23 = '\0';
      cVar21 = '\0';
    }
    uVar5 = *param_7;
    if (uVar5 == 1) {
      cVar16 = cVar23;
      cVar23 = -cVar21;
    }
    else if (uVar5 == 3) {
      cVar16 = -cVar23;
      cVar23 = cVar21;
    }
    else {
      cVar16 = cVar21;
      if (uVar5 == 2) {
        cVar16 = -cVar21;
        cVar23 = -cVar23;
      }
    }
    local_1c0 = 0;
    local_1c8 = DAT_7103a5a2a8 + 0x10;
    local_1be = 0xff;
    uVar5 = piVar20[1];
    if ((int)uVar5 < 0) {
LAB_71019f7cb4:
      plVar11 = FUN_7100bc6230();
    }
    else {
      lVar17 = *(long *)((uint *)*DAT_7103a59c40 + 2);
      if (*(uint *)*DAT_7103a59c40 <= uVar5) {
        uVar5 = 0;
        if (lVar17 != 0) goto LAB_71019f7c3c;
        goto LAB_71019f7cb4;
      }
      if (lVar17 == 0) goto LAB_71019f7cb4;
LAB_71019f7c3c:
      lVar17 = lVar17 + (ulong)uVar5 * 0x10;
      if ((*(int *)(lVar17 + 4) != *piVar20) ||
         (plVar11 = *(long **)(lVar17 + 8), plVar11 == (long *)0x0)) goto LAB_71019f7cb4;
    }
    local_1be = *(byte *)(plVar11 + 4);
    local_1c0 = CONCAT11((char)((ulong)_local_198 >> 0x20) + cVar23,(char)_local_198 + cVar16);
  }
  if (local_1be == 0xff) {
    return 1;
  }
  piVar20 = DAT_7103a5c420;
  if ((*DAT_7103a5a160 != 0) &&
     (lVar17 = *(long *)(*DAT_7103a5a160 + (ulong)(uint)local_1be * 8 + 8), lVar17 != 0)) {
    piVar20 = (int *)(lVar17 + 0x150);
  }
  uVar5 = piVar20[1];
  if ((int)uVar5 < 0) {
    return 1;
  }
  lVar17 = *(long *)((uint *)*DAT_7103a59c40 + 2);
  if (*(uint *)*DAT_7103a59c40 <= uVar5) {
    uVar5 = 0;
  }
  if (lVar17 == 0) {
    return 1;
  }
  lVar17 = lVar17 + (ulong)uVar5 * 0x10;
  if (*(int *)(lVar17 + 4) != *piVar20) {
    return 1;
  }
  lVar17 = *(long *)(lVar17 + 8);
  if (lVar17 == 0) {
    return 1;
  }
  if (*(byte *)(lVar17 + 0x24) <= (byte)local_1c0) {
    return 1;
  }
  if (param_4 == (long *)0x0) {
    return 1;
  }
  if (*(byte *)(lVar17 + 0x25) <= local_1c0._1_1_) {
    return 1;
  }
  FUN_71019f85c0((long *)abStack_1d8,param_5,param_6,(int *)param_7);
  lVar17 = FUN_7101d33efc((long)abStack_1d8);
  FUN_71019f4540(*(undefined4 *)(lVar17 + 4),-0.462,param_3,param_4,(long)&local_1c8,param_6,param_7
                );
  FUN_71019f85c0(&lStack_b8,param_5,param_6,(int *)param_7);
  piVar20 = DAT_7103a5c420;
  if ((ulong)local_ae == 0xff) {
    return 1;
  }
  piVar35 = DAT_7103a5c420;
  if ((*DAT_7103a5a160 != 0) &&
     (lVar17 = *(long *)(*DAT_7103a5a160 + (ulong)local_ae * 8 + 8), lVar17 != 0)) {
    piVar35 = (int *)(lVar17 + 0x150);
  }
  uVar5 = piVar35[1];
  if ((int)uVar5 < 0) {
    return 1;
  }
  lVar17 = *(long *)((uint *)*DAT_7103a59c40 + 2);
  if (*(uint *)*DAT_7103a59c40 <= uVar5) {
    uVar5 = 0;
  }
  if (lVar17 == 0) {
    return 1;
  }
  lVar17 = lVar17 + (ulong)uVar5 * 0x10;
  if (*(int *)(lVar17 + 4) != *piVar35) {
    return 1;
  }
  lVar17 = *(long *)(lVar17 + 8);
  if (lVar17 == 0) {
    return 1;
  }
  if (*(byte *)(lVar17 + 0x24) <= local_b0) {
    return 1;
  }
  if (*(byte *)(lVar17 + 0x25) <= local_af) {
    return 1;
  }
  iVar7 = *param_6;
  uVar13 = 0;
  bVar4 = false;
  iVar27 = 2;
  uVar5 = 1;
  uVar18 = 0x10;
  uVar9 = 5;
  uVar29 = 3;
  switch(iVar7) {
  case 0x22:
  case 0x23:
  case 0x33:
    goto switchD_71019f7eac_caseD_22;
  case 0x24:
  case 0x34:
    break;
  case 0x25:
  case 0x35:
    uVar5 = 2;
    break;
  case 0x26:
    uVar5 = 3;
    break;
  case 0x27:
    goto switchD_71019f7eac_caseD_27;
  case 0x28:
  case 0x36:
    uVar5 = 4;
    break;
  case 0x29:
  case 0x37:
    uVar5 = 5;
    break;
  case 0x2a:
    goto switchD_71019f7eac_caseD_2a;
  case 0x2b:
  case 0x38:
    uVar5 = 6;
    break;
  case 0x2c:
    uVar5 = 7;
    break;
  case 0x2d:
    uVar5 = 8;
    break;
  case 0x2e:
    uVar5 = 9;
    break;
  case 0x2f:
    uVar5 = 10;
    break;
  case 0x30:
    uVar5 = 0xb;
    break;
  case 0x31:
  case 0x39:
    uVar5 = 0xc;
    break;
  case 0x32:
  case 0x3b:
    uVar5 = 0xd;
    break;
  case 0x3a:
    bVar4 = false;
    uVar5 = 0;
    iVar27 = 5;
    uVar18 = 0xc;
    goto switchD_71019f7eac_caseD_3f;
  case 0x3c:
    uVar5 = 0xe;
    break;
  case 0x3d:
    uVar5 = 0xf;
    break;
  case 0x3e:
    uVar5 = 0x10;
    break;
  case 0x3f:
    goto switchD_71019f7eac_caseD_3f;
  case 0x40:
    uVar5 = 0x11;
    break;
  case 0x41:
    uVar5 = 0x12;
    break;
  case 0x42:
    uVar5 = 0x13;
    break;
  default:
    uVar13 = 1;
switchD_71019f7eac_caseD_22:
    if (iVar7 == 0x23) {
      bVar4 = false;
      uVar5 = 0;
      iVar27 = 1;
      uVar18 = (ulong)uVar13;
      goto switchD_71019f7eac_caseD_3f;
    }
    if (iVar7 == 0x2a) {
      uVar9 = (ulong)uVar13;
switchD_71019f7eac_caseD_2a:
      uVar18 = uVar9;
      uVar5 = 0;
      iVar27 = 4;
      bVar4 = true;
      goto switchD_71019f7eac_caseD_3f;
    }
    uVar29 = (ulong)uVar13;
    uVar5 = uVar13;
    if (iVar7 == 0x27) {
switchD_71019f7eac_caseD_27:
      uVar18 = uVar29;
      bVar4 = false;
      uVar5 = 0;
      iVar27 = 3;
      goto switchD_71019f7eac_caseD_3f;
    }
  }
  bVar4 = false;
  iVar27 = 0;
  uVar18 = (ulong)uVar5;
  uVar5 = 0;
switchD_71019f7eac_caseD_3f:
  iStack_194 = 0;
  local_190 = (undefined8 *)0x0;
  local_180 = local_178;
  local_178[0] = local_168;
  local_168[0] = local_158;
  local_158[0] = local_148;
  local_148[0] = local_138;
  local_138[0] = local_128;
  local_128[0] = local_118;
  local_118[0] = local_108;
  local_108[0] = 0;
  if (local_f8 != (undefined8 *)0x0) {
    iStack_194 = 8;
    local_190 = local_f8;
  }
  local_198 = 0;
  lVar17 = 0;
  iVar7 = 0;
  iVar32 = 0;
  iVar33 = 0;
  iVar6 = 0;
  local_188 = local_180;
  do {
    pppppppuVar2 = local_188;
    piVar35 = (int *)(uVar18 * 0x78 + 0x71040e4f78 + lVar17);
    if ((char)piVar35[2] != '\0') {
      iVar15 = *piVar35;
      if (iVar27 == 5) {
        if ((iVar15 == 1 || iVar15 == -1) && (piVar35[1] == 1)) goto LAB_71019f80b8;
      }
      else if (((iVar27 == 3) || (iVar27 == 1)) && (iVar15 == 0 && piVar35[1] == 0)) {
LAB_71019f80b8:
        if (iVar6 < iStack_194) {
          if (local_188 != (undefined8 *******)0x0) {
            local_188 = (undefined8 *******)*local_188;
          }
          ppppppuVar14 = *(undefined8 *******)piVar35;
          *(undefined4 *)(pppppppuVar2 + 1) = 0;
          *pppppppuVar2 = ppppppuVar14;
          iVar7 = local_198;
          iVar32 = local_198;
          iVar33 = local_198;
          iVar6 = local_198;
          if (local_198 < iStack_194) {
            local_190[local_198] = pppppppuVar2;
            local_198 = local_198 + 1;
            iVar7 = local_198;
            iVar32 = local_198;
            iVar33 = local_198;
            iVar6 = local_198;
          }
        }
      }
      pppppppuVar2 = local_188;
      if ((char)piVar35[2] == '\0') {
        iVar15 = 0;
        piVar35[0] = 0;
        piVar35[1] = 0;
        uVar13 = 0;
      }
      else {
        iVar15 = *piVar35;
        uVar13 = piVar35[1];
      }
      if (((bVar4) && (iVar15 == -1)) && (uVar13 < 2)) {
        if ((char)piVar35[2] == '\0') {
          ppppppuVar14 = (undefined8 ******)0x0;
          piVar35[0] = 0;
          piVar35[1] = 0;
        }
        else {
          ppppppuVar14 = *(undefined8 *******)piVar35;
        }
        iVar6 = iVar33;
        if (iStack_194 <= iVar33) goto LAB_71019f81ac;
        if (local_188 != (undefined8 *******)0x0) {
          local_188 = (undefined8 *******)*local_188;
        }
        *pppppppuVar2 = ppppppuVar14;
        *(undefined4 *)(pppppppuVar2 + 1) = 2;
        if (local_198 < iStack_194) {
          local_190[local_198] = pppppppuVar2;
          iVar7 = local_198 + 1;
          iVar32 = iVar7;
          iVar33 = iVar7;
          iVar6 = iVar7;
          local_198 = iVar7;
          goto LAB_71019f81ac;
        }
        uVar13 = 0;
        iVar7 = local_198;
        iVar32 = local_198;
        iVar33 = local_198;
        iVar6 = local_198;
        if ((char)piVar35[2] == '\0') goto LAB_71019f81e8;
LAB_71019f81b4:
        iVar15 = *piVar35;
        uVar13 = piVar35[1];
      }
      else {
LAB_71019f81ac:
        uVar13 = (uint)*(byte *)(piVar35 + 2);
        if (*(byte *)(piVar35 + 2) != 0) goto LAB_71019f81b4;
LAB_71019f81e8:
        iVar15 = 0;
        piVar35[0] = 0;
        piVar35[1] = 0;
      }
      pppppppuVar2 = local_188;
      if (((uVar5 != 0) && (iVar15 == 1)) && (uVar13 == 1)) {
        if ((char)piVar35[2] == '\0') {
          ppppppuVar14 = (undefined8 ******)0x0;
          piVar35[0] = 0;
          piVar35[1] = 0;
        }
        else {
          ppppppuVar14 = *(undefined8 *******)piVar35;
        }
        iVar33 = iVar32;
        iVar6 = iVar32;
        if (iVar32 < iStack_194) {
          if (local_188 != (undefined8 *******)0x0) {
            local_188 = (undefined8 *******)*local_188;
          }
          *pppppppuVar2 = ppppppuVar14;
          *(undefined4 *)(pppppppuVar2 + 1) = 3;
          iVar7 = local_198;
          iVar32 = local_198;
          iVar33 = local_198;
          iVar6 = local_198;
          if (local_198 < iStack_194) {
            local_190[local_198] = pppppppuVar2;
            local_198 = local_198 + 1;
            iVar7 = local_198;
            iVar32 = local_198;
            iVar33 = local_198;
            iVar6 = local_198;
          }
        }
      }
    }
    lVar17 = lVar17 + 0xc;
  } while (lVar17 != 0x78);
  if (iVar7 != 0) {
    fVar40 = NAN;
    lVar17 = (long)iVar7 << 3;
    puVar8 = local_190;
    fVar36 = fVar40;
    fVar38 = fVar40;
    local_200 = param_6;
    do {
      puVar34 = (undefined4 *)*puVar8;
      FUN_71019e8b20(&local_1b8,(long)&lStack_b8,puVar34,param_7);
      uVar9 = local_1b0 >> 0x10 & 0xff;
      if (uVar9 != 0xff) {
        piVar35 = piVar20;
        if ((*DAT_7103a5a160 != 0) &&
           (lVar25 = *(long *)(*DAT_7103a5a160 + uVar9 * 8 + 8), lVar25 != 0)) {
          piVar35 = (int *)(lVar25 + 0x150);
        }
        uVar5 = piVar35[1];
        if (-1 < (int)uVar5) {
          puVar30 = (uint *)*DAT_7103a59c40;
          if (uVar5 < *puVar30) {
            lVar25 = *(long *)(puVar30 + 2);
          }
          else {
            uVar5 = 0;
            lVar25 = *(long *)(puVar30 + 2);
          }
          if ((((lVar25 != 0) &&
               (lVar25 = lVar25 + (ulong)uVar5 * 0x10, *(int *)(lVar25 + 4) == *piVar35)) &&
              (lVar25 = *(long *)(lVar25 + 8), lVar25 != 0)) &&
             (((byte)local_1b0 < *(byte *)(lVar25 + 0x24) &&
              (local_1b0._1_1_ < *(byte *)(lVar25 + 0x25))))) {
            pfVar12 = (float *)FUN_7101d33efc((long)&local_1b8);
            fVar43 = pfVar12[1];
            fVar41 = *pfVar12 + -0.769;
            fVar42 = pfVar12[2] + -0.769;
            pfVar12 = (float *)FUN_7101d33efc((long)&local_1b8);
            fVar37 = *pfVar12 + 0.769;
            fVar39 = pfVar12[2] + 0.769;
            if (*param_7 < 4) {
              iVar7 = puVar34[2];
              switch(*param_7) {
              case 0:
                if (iVar7 == 0) {
LAB_71019f83e8:
                  fVar42 = fVar42 + -0.231;
                  goto LAB_71019f8428;
                }
                if (iVar7 == 2) goto LAB_71019f8414;
                if (iVar7 != 3) goto LAB_71019f8408;
                break;
              case 1:
                if (iVar7 == 0) {
LAB_71019f8414:
                  fVar41 = fVar41 + -0.231;
                  goto LAB_71019f8428;
                }
                if (iVar7 != 1) {
                  if (iVar7 == 3) goto LAB_71019f83e8;
                  goto LAB_71019f8408;
                }
                break;
              case 2:
                if (iVar7 == 1) goto LAB_71019f83e8;
                if (iVar7 != 2) {
                  if (iVar7 == 3) goto LAB_71019f8414;
                  goto LAB_71019f8408;
                }
                break;
              case 3:
                if (iVar7 != 0) {
                  if (iVar7 == 1) goto LAB_71019f8414;
                  if (iVar7 == 2) goto LAB_71019f83e8;
                  goto LAB_71019f8408;
                }
              }
              fVar37 = fVar37 + 0.231;
            }
            else {
LAB_71019f8408:
              fVar39 = fVar39 + 0.231;
            }
LAB_71019f8428:
            if (fVar41 < fVar36) {
LAB_71019f8448:
              local_200 = (int *)(ulong)(uint)fVar43;
              fVar36 = fVar41;
              unaff_s13 = fVar42;
            }
            else if (NAN(fVar36)) {
              fVar36 = 0.0;
              local_200 = (int *)0x0;
              unaff_s13 = 0.0;
              if (fVar42 < 0.0) goto LAB_71019f8448;
            }
            else if (fVar42 < unaff_s13) goto LAB_71019f8448;
            if ((!NAN(fVar38)) && (fVar37 <= fVar40)) {
              fVar38 = fVar40;
              if (NAN(fVar40)) {
                local_1f0 = 0;
                unaff_s9 = 0.0;
                fVar38 = 0.0;
              }
              fVar40 = fVar38;
              if (fVar39 <= unaff_s9) goto LAB_71019f84d8;
            }
            local_1f0 = (ulong)(uint)(pfVar12[1] + 0.0);
            fVar38 = fVar37;
            fVar40 = fVar37;
            unaff_s9 = fVar39;
          }
        }
      }
LAB_71019f84d8:
      puVar8 = puVar8 + 1;
      lVar17 = lVar17 + -8;
    } while (lVar17 != 0);
    if ((!NAN(fVar36)) && (!NAN(fVar40))) {
      local_1b8 = CONCAT44(((float)local_1f0 + local_200._0_4_) * 0.5,(fVar40 + fVar36) * 0.5);
      fVar36 = fVar36 - fVar40;
      local_1b0 = CONCAT44(*param_7,(unaff_s9 + unaff_s13) * 0.5);
      fVar38 = -fVar36;
      if (0.0 <= fVar36) {
        fVar38 = fVar36;
      }
      fVar40 = unaff_s13 - unaff_s9;
      fVar36 = -fVar40;
      if (0.0 <= fVar40) {
        fVar36 = fVar40;
      }
      local_1a8 = CONCAT44(fVar36,fVar38);
      iVar7 = FUN_7100ee8db0(param_5);
      FUN_71019f42b8(param_4,&local_1b8,iVar7);
    }
  }
  return 1;
}



void FUN_71019f85c0(long *param_1,int *param_2,int *param_3,int *param_4)

{
  int *piVar1;
  int iVar2;
  undefined8 *puVar3;
  undefined8 *puVar4;
  long *plVar5;
  undefined1 uVar6;
  int iVar7;
  long lVar8;
  uint uVar9;
  float fVar10;
  undefined1 local_50 [4];
  undefined1 uStack_4c;
  char local_48;
  
  puVar3 = DAT_7103a59c40;
  uVar9 = param_2[1];
  if ((int)uVar9 < 0) {
LAB_71019f863c:
    puVar4 = FUN_7100baff84();
  }
  else {
    lVar8 = *(long *)((uint *)*DAT_7103a59c40 + 2);
    if (*(uint *)*DAT_7103a59c40 <= uVar9) {
      uVar9 = 0;
      if (lVar8 != 0) goto LAB_71019f8610;
      goto LAB_71019f863c;
    }
    if (lVar8 == 0) goto LAB_71019f863c;
LAB_71019f8610:
    lVar8 = lVar8 + (ulong)uVar9 * 0x10;
    if ((*(int *)(lVar8 + 4) != *param_2) ||
       (puVar4 = *(undefined8 **)(lVar8 + 8), puVar4 == (undefined8 *)0x0)) goto LAB_71019f863c;
  }
  iVar7 = *(int *)(puVar4 + 0x13);
  if ((iVar7 != 0) && (lVar8 = (long)iVar7 + (long)(puVar4 + 0x13), lVar8 != 0)) {
    fVar10 = *(float *)(lVar8 + 0x30);
    iVar7 = 0;
    uVar9 = 0;
    if (fVar10 != (float)(int)fVar10) {
      uVar9 = (uint)(fVar10 < 0.0);
    }
    iVar2 = (int)fVar10 - uVar9;
    if (iVar2 < 0xb4) {
      if ((int)fVar10 != uVar9) {
        if (iVar2 != 0x5a) goto LAB_71019f8790;
        iVar7 = 1;
      }
    }
    else if (iVar2 == 0xb4) {
      iVar7 = 2;
    }
    else if (iVar2 == 0x10e) {
      iVar7 = 3;
    }
    else if (iVar2 != 0x168) goto LAB_71019f8790;
    if ((((0xf < *param_3 - 0x33U) && (1 < *param_3 - 0x50U)) || (*param_4 == iVar7)) &&
       (FUN_7101d12500((undefined8 *)local_50,param_2), local_48 != '\0')) {
      piVar1 = DAT_7103a5c420;
      if (*(long *)(*DAT_7103a5a160 + 8) != 0) {
        piVar1 = (int *)(*(long *)(*DAT_7103a5a160 + 8) + 0x150);
      }
      uVar9 = piVar1[1];
      if (-1 < (int)uVar9) {
        lVar8 = *(long *)((uint *)*puVar3 + 2);
        if (lVar8 != 0) {
          if (*(uint *)*puVar3 <= uVar9) {
            uVar9 = 0;
          }
          if (*(int *)(lVar8 + (ulong)uVar9 * 0x10 + 4) == *piVar1) {
            plVar5 = *(long **)(lVar8 + (ulong)uVar9 * 0x10 + 8);
            *param_1 = DAT_7103a5a2a8 + 0x10;
            if (plVar5 == (long *)0x0) {
              plVar5 = FUN_7100bc6230();
            }
            uVar6 = (undefined1)(int)plVar5[4];
            *(undefined1 *)(param_1 + 1) = local_50[0];
            *(undefined1 *)((long)param_1 + 9) = uStack_4c;
            goto LAB_71019f8774;
          }
        }
      }
    }
  }
LAB_71019f8790:
  lVar8 = DAT_7103a5a2a8;
  *(undefined2 *)(param_1 + 1) = 0;
  *param_1 = lVar8 + 0x10;
  uVar6 = 0xff;
LAB_71019f8774:
  *(undefined1 *)((long)param_1 + 10) = uVar6;
  return;
}



uint FUN_71019f87d0(undefined1 param_1 [16],undefined1 param_2 [16],float param_3,long *param_4,
                   int *param_5,int *param_6,uint *param_7)

{
  uint uVar1;
  ulong uVar2;
  undefined8 uVar3;
  undefined1 extraout_q0 [16];
  undefined1 extraout_q0_00 [16];
  undefined1 extraout_q0_01 [16];
  uint local_28;
  uint local_24;
  
  uVar1 = param_5[1];
  if ((int)uVar1 < 0) {
    return 0;
  }
  if (*(long *)(DAT_71040e7d48 + 2) != 0) {
    if (*DAT_71040e7d48 <= uVar1) {
      uVar1 = 0;
    }
    if (*(int *)(*(long *)(DAT_71040e7d48 + 2) + (ulong)uVar1 * 0x10 + 4) == *param_5) {
      uVar2 = FUN_71019f70f0(param_1,param_2,param_3,param_4,param_5,param_6,param_7);
      if ((uVar2 & 1) == 0) {
        uVar2 = FUN_71019f70f0(extraout_q0,param_2,param_3,param_4,param_5,param_6,param_7 + 1);
        if ((uVar2 & 1) == 0) {
          uVar1 = param_7[1] - 1;
          if (uVar1 < 3) {
            local_24 = *(uint *)(&DAT_71032b4b8c + (long)(int)uVar1 * 4);
          }
          else {
            local_24 = 2;
          }
          uVar2 = FUN_71019f70f0(extraout_q0_00,param_2,param_3,param_4,param_5,param_6,&local_24);
          if ((uVar2 & 1) == 0) {
            if (*param_7 - 1 < 3) {
              local_28 = *(uint *)(&DAT_71032b4b8c + (long)(int)(*param_7 - 1) * 4);
            }
            else {
              local_28 = 2;
            }
            uVar3 = FUN_71019f70f0(extraout_q0_01,param_2,param_3,param_4,param_5,param_6,&local_28)
            ;
            uVar1 = (uint)uVar3;
            goto LAB_71019f889c;
          }
        }
      }
      uVar1 = 1;
      goto LAB_71019f889c;
    }
  }
  uVar1 = 0;
LAB_71019f889c:
  return uVar1 & 1;
}



// WARNING: Type propagation algorithm not settling

undefined8 FUN_71019f8910(long *param_1,int *param_2,int *param_3,uint *param_4)

{
  undefined8 *******pppppppuVar1;
  int iVar2;
  long *plVar3;
  bool bVar4;
  bool bVar5;
  uint uVar6;
  undefined8 *puVar7;
  float *pfVar8;
  float *pfVar9;
  int *piVar10;
  int *piVar11;
  undefined4 uVar12;
  long lVar13;
  ulong uVar14;
  undefined8 *puVar15;
  undefined8 *******pppppppuVar16;
  long *plVar17;
  uint uVar18;
  uint uVar19;
  int iVar20;
  long lVar21;
  uint *puVar22;
  char cVar23;
  int iVar24;
  long lVar25;
  char cVar26;
  undefined8 ******ppppppuVar27;
  undefined8 *******pppppppuVar28;
  float fVar29;
  float fVar30;
  undefined4 uVar31;
  float fVar32;
  float fVar33;
  undefined4 uVar34;
  long local_178;
  undefined2 local_170;
  byte local_16e;
  long local_168;
  undefined4 local_160;
  uint local_15c;
  int local_158;
  int local_154;
  undefined8 local_148;
  undefined8 local_140;
  undefined8 local_138;
  undefined8 *******pppppppuStack_130;
  undefined8 *******local_128;
  undefined8 ******local_120;
  undefined8 *****local_118;
  undefined8 ****local_110;
  undefined8 ***local_108;
  undefined8 **local_100;
  undefined8 *local_f8;
  undefined8 local_f0;
  undefined8 *******local_e8 [8];
  long local_a8;
  undefined2 local_a0;
  byte local_9e;
  byte abStack_88 [8];
  
  uVar6 = param_2[1];
  if ((int)uVar6 < 0) {
    return 0;
  }
  lVar13 = *(long *)((uint *)*DAT_7103a59c40 + 2);
  if (lVar13 == 0) {
    return 0;
  }
  if (*(uint *)*DAT_7103a59c40 <= uVar6) {
    uVar6 = 0;
  }
  if (*(int *)(lVar13 + (ulong)uVar6 * 0x10 + 4) != *param_2) {
    return 0;
  }
  puVar7 = *(undefined8 **)(lVar13 + (ulong)uVar6 * 0x10 + 8);
  if (puVar7 == (undefined8 *)0x0) {
    puVar7 = FUN_7100baff84();
  }
  iVar20 = *(int *)(puVar7 + 0x13);
  lVar13 = (long)iVar20 + (long)(puVar7 + 0x13);
  uVar6 = 0;
  if (iVar20 == 0 || lVar13 == 0) {
    return 0;
  }
  fVar29 = *(float *)(lVar13 + 0x30);
  uVar18 = 0;
  if (fVar29 != (float)(int)fVar29) {
    uVar18 = (uint)(fVar29 < 0.0);
  }
  iVar20 = (int)fVar29 - uVar18;
  if (iVar20 < 0xb4) {
    if ((int)fVar29 != uVar18) {
      if (iVar20 != 0x5a) {
        return 0;
      }
      uVar6 = 1;
    }
  }
  else if (iVar20 == 0xb4) {
    uVar6 = 2;
  }
  else if (iVar20 == 0x10e) {
    uVar6 = 3;
  }
  else if (iVar20 != 0x168) {
    return 0;
  }
  if (((*param_3 - 0x33U < 0x10) || (*param_3 - 0x50U < 2)) && (*param_4 != uVar6)) {
    return 0;
  }
  uVar6 = param_2[1];
  if ((int)uVar6 < 0) {
LAB_71019f8a9c:
    puVar7 = FUN_7100baff84();
  }
  else {
    lVar13 = *(long *)((uint *)*DAT_7103a59c40 + 2);
    if (*(uint *)*DAT_7103a59c40 <= uVar6) {
      uVar6 = 0;
      if (lVar13 != 0) goto LAB_71019f8a58;
      goto LAB_71019f8a9c;
    }
    if (lVar13 == 0) goto LAB_71019f8a9c;
LAB_71019f8a58:
    lVar13 = lVar13 + (ulong)uVar6 * 0x10;
    if ((*(int *)(lVar13 + 4) != *param_2) ||
       (puVar7 = *(undefined8 **)(lVar13 + 8), puVar7 == (undefined8 *)0x0)) goto LAB_71019f8a9c;
  }
  iVar20 = *(int *)((long)puVar7 + 0x84);
  if (iVar20 == 0) {
    return 0;
  }
  plVar17 = (long *)((long)iVar20 + (long)puVar7 + 0x84);
  if (plVar17 == (long *)0x0) {
    return 0;
  }
  pfVar8 = (float *)(**(code **)(*plVar17 + 0xa8))(plVar17);
  if (((*(float *)((long)plVar17 + 0x11c) == *pfVar8) && (*(float *)(plVar17 + 0x24) == pfVar8[1]))
     && (*(float *)((long)plVar17 + 0x124) == pfVar8[2])) {
    cVar26 = '\x01';
  }
  else {
    cVar26 = '\0';
  }
  pfVar8 = (float *)(**(code **)(*plVar17 + 0xa8))(plVar17);
  plVar3 = DAT_7103a5a160;
  piVar10 = DAT_7103a5c420;
  if (((*(uint *)(plVar17 + 0x29) < 0x100) && (*DAT_7103a5a160 != 0)) &&
     (lVar13 = *(long *)(*DAT_7103a5a160 + (ulong)*(uint *)(plVar17 + 0x29) * 8 + 8), lVar13 != 0))
  {
    piVar10 = (int *)(lVar13 + 0x150);
  }
  FUN_7101d0c8e0(&local_148,pfVar8,piVar10);
  lVar13 = DAT_7103a5a2a8;
  if ((ulong)local_140._2_1_ == 0xff) {
LAB_71019f8c60:
    local_a0 = 0;
    local_9e = 0xff;
    goto LAB_71019f8c74;
  }
  piVar10 = DAT_7103a5c420;
  if ((*plVar3 != 0) && (lVar21 = *(long *)(*plVar3 + (ulong)local_140._2_1_ * 8 + 8), lVar21 != 0))
  {
    piVar10 = (int *)(lVar21 + 0x150);
  }
  uVar6 = piVar10[1];
  if ((int)uVar6 < 0) goto LAB_71019f8c60;
  lVar21 = *(long *)((uint *)*DAT_7103a59c40 + 2);
  if (*(uint *)*DAT_7103a59c40 <= uVar6) {
    uVar6 = 0;
    if (lVar21 != 0) goto LAB_71019f8bb4;
    goto LAB_71019f8c60;
  }
  if (lVar21 == 0) goto LAB_71019f8c60;
LAB_71019f8bb4:
  lVar21 = lVar21 + (ulong)uVar6 * 0x10;
  if (((*(int *)(lVar21 + 4) != *piVar10) || (lVar21 = *(long *)(lVar21 + 8), lVar21 == 0)) ||
     ((*(byte *)(lVar21 + 0x24) <= (byte)local_140 || (*(byte *)(lVar21 + 0x25) <= local_140._1_1_))
     )) goto LAB_71019f8c60;
  cVar23 = '\0';
  switch(*param_4) {
  default:
    cVar23 = cVar26;
    goto LAB_71019f8c28;
  case 1:
    break;
  case 2:
    cVar23 = -cVar26;
LAB_71019f8c28:
    cVar26 = '\0';
    break;
  case 3:
    cVar23 = '\0';
    cVar26 = -cVar26;
  }
  local_9e = local_140._2_1_;
  local_a0 = CONCAT11(local_140._1_1_ + cVar23,(byte)local_140 + cVar26);
LAB_71019f8c74:
  local_a8 = DAT_7103a5a2a8 + 0x10;
  local_148._4_4_ = 0;
  local_140 = (undefined8 *******)0x0;
  local_120 = &local_118;
  local_110 = &local_108;
  local_118 = &local_110;
  pppppppuStack_130 = &local_128;
  local_108 = &local_100;
  local_100 = &local_f8;
  local_f8 = &local_f0;
  pppppppuVar28 = local_e8;
  local_f0 = 0;
  local_138 = pppppppuStack_130;
  local_128 = &local_120;
  if (pppppppuVar28 != (undefined8 *******)0x0) {
    local_128 = (undefined8 *******)0x0;
    local_148._4_4_ = 8;
    local_140 = pppppppuVar28;
    local_138 = &local_120;
    local_e8[0] = pppppppuStack_130;
  }
  local_148._0_4_ = (uint)(pppppppuVar28 != (undefined8 *******)0x0);
  FUN_7101d34c40(&local_168,param_2);
  pppppppuVar28 = local_138;
  switch(*param_4) {
  case 0:
  case 2:
    local_154 = local_158;
    local_15c = local_160;
    break;
  case 1:
  case 3:
    break;
  default:
    uVar6 = 0;
    goto LAB_71019f8d20;
  }
  uVar6 = (local_154 - local_15c) + 1;
LAB_71019f8d20:
  if (*param_3 == 0x50) {
    if ((uVar6 & 1) == 0) {
      if ((int)(uint)local_148 < local_148._4_4_) {
        if (local_138 != (undefined8 *******)0x0) {
          local_138 = (undefined8 *******)*local_138;
        }
        *pppppppuVar28 = (undefined8 ******)0xffffffff;
        if ((int)(uint)local_148 < local_148._4_4_) {
          local_140[(int)(uint)local_148] = pppppppuVar28;
          local_148._0_4_ = (uint)local_148 + 1;
        }
      }
      uVar14 = (ulong)local_9e;
      if (uVar14 == 0xff) {
        local_160 = CONCAT13(local_160._3_1_,0xff0000);
LAB_71019f9698:
        local_170 = 0;
        local_16e = 0xff;
      }
      else {
        lVar21 = *plVar3;
        piVar10 = DAT_7103a5c420;
        if ((lVar21 != 0) && (lVar25 = *(long *)(lVar21 + uVar14 * 8 + 8), lVar25 != 0)) {
          piVar10 = (int *)(lVar25 + 0x150);
        }
        uVar18 = piVar10[1];
        if ((int)uVar18 < 0) {
LAB_71019f946c:
          local_160 = CONCAT13(local_160._3_1_,0xff0000);
        }
        else {
          lVar25 = *(long *)((uint *)*DAT_7103a59c40 + 2);
          if (*(uint *)*DAT_7103a59c40 <= uVar18) {
            uVar18 = 0;
            if (lVar25 != 0) goto LAB_71019f9070;
            goto LAB_71019f946c;
          }
          if (lVar25 == 0) goto LAB_71019f946c;
LAB_71019f9070:
          lVar25 = lVar25 + (ulong)uVar18 * 0x10;
          if ((((*(int *)(lVar25 + 4) != *piVar10) || (lVar25 = *(long *)(lVar25 + 8), lVar25 == 0))
              || (*(byte *)(lVar25 + 0x24) <= (byte)local_a0)) ||
             (*(byte *)(lVar25 + 0x25) <= local_a0._1_1_)) goto LAB_71019f946c;
          local_160._0_3_ = CONCAT12(local_9e,local_a0);
        }
        piVar10 = DAT_7103a5c420;
        if ((lVar21 != 0) && (lVar21 = *(long *)(lVar21 + uVar14 * 8 + 8), lVar21 != 0)) {
          piVar10 = (int *)(lVar21 + 0x150);
        }
        uVar18 = piVar10[1];
        if ((int)uVar18 < 0) goto LAB_71019f9698;
        lVar21 = *(long *)((uint *)*DAT_7103a59c40 + 2);
        if (*(uint *)*DAT_7103a59c40 <= uVar18) {
          uVar18 = 0;
          if (lVar21 != 0) goto LAB_71019f94c8;
          goto LAB_71019f9698;
        }
        if (lVar21 == 0) goto LAB_71019f9698;
LAB_71019f94c8:
        lVar21 = lVar21 + (ulong)uVar18 * 0x10;
        if (((*(int *)(lVar21 + 4) != *piVar10) || (lVar21 = *(long *)(lVar21 + 8), lVar21 == 0)) ||
           ((*(byte *)(lVar21 + 0x24) <= (byte)local_a0 ||
            (*(byte *)(lVar21 + 0x25) <= local_a0._1_1_)))) goto LAB_71019f9698;
        uVar18 = *param_4;
        local_16e = local_9e;
        cVar23 = (char)(0x100ff >> (ulong)(uVar18 << 3 & 0x1f));
        cVar26 = (char)(0xff000100 >> (ulong)(uVar18 << 3 & 0x1f));
        if (3 < uVar18) {
          cVar23 = -1;
        }
        if (3 < uVar18) {
          cVar26 = '\0';
        }
        local_170 = CONCAT11(cVar26 + local_a0._1_1_,cVar23 + (byte)local_a0);
      }
      local_178 = lVar13 + 0x10;
      local_168 = lVar13 + 0x10;
      pfVar8 = (float *)FUN_7101d33efc((long)&local_168);
      pfVar9 = (float *)FUN_7101d33efc((long)&local_178);
      fVar29 = *pfVar8;
      fVar30 = pfVar8[1];
      uVar34 = 0x3fc4dd2f;
      fVar32 = *pfVar9;
      fVar33 = pfVar9[1];
      uVar12 = 0x40626e98;
      goto LAB_71019f96dc;
    }
    if ((int)(uint)local_148 < local_148._4_4_) {
      if (local_138 != (undefined8 *******)0x0) {
        local_138 = (undefined8 *******)*local_138;
      }
      *pppppppuVar28 = (undefined8 ******)0x1;
      if ((int)(uint)local_148 < local_148._4_4_) {
        local_140[(int)(uint)local_148] = pppppppuVar28;
        local_148._0_4_ = (uint)local_148 + 1;
      }
    }
    pppppppuVar28 = local_138;
    if ((int)(uint)local_148 < local_148._4_4_) {
      if (local_138 != (undefined8 *******)0x0) {
        local_138 = (undefined8 *******)*local_138;
      }
      *pppppppuVar28 = (undefined8 ******)0xffffffff;
      if ((int)(uint)local_148 < local_148._4_4_) {
        local_140[(int)(uint)local_148] = pppppppuVar28;
        local_148._0_4_ = (uint)local_148 + 1;
      }
    }
    pfVar8 = (float *)FUN_7101d33efc((long)&local_a8);
    fVar29 = *pfVar8;
    fVar30 = pfVar8[1];
    uVar34 = 0x3fc4dd2f;
    fVar32 = pfVar8[2];
    uVar12 = 0x40626e98;
  }
  else {
    if (*param_3 != 0x51) {
      return 0;
    }
    if ((uVar6 & 1) == 0) {
      if ((int)(uint)local_148 < local_148._4_4_) {
        if (local_138 != (undefined8 *******)0x0) {
          local_138 = (undefined8 *******)*local_138;
        }
        *pppppppuVar28 = (undefined8 ******)0xffffffff;
        if ((int)(uint)local_148 < local_148._4_4_) {
          local_140[(int)(uint)local_148] = pppppppuVar28;
          local_148._0_4_ = (uint)local_148 + 1;
        }
      }
      pppppppuVar1 = local_138;
      pppppppuVar28 = local_138;
      if ((int)(uint)local_148 < local_148._4_4_) {
        if (local_138 != (undefined8 *******)0x0) {
          local_138 = (undefined8 *******)*local_138;
        }
        *pppppppuVar1 = (undefined8 ******)0x1;
        pppppppuVar28 = local_138;
        if ((int)(uint)local_148 < local_148._4_4_) {
          local_140[(int)(uint)local_148] = pppppppuVar1;
          local_148._0_4_ = (uint)local_148 + 1;
        }
      }
      local_138 = pppppppuVar28;
      if ((int)(uint)local_148 < local_148._4_4_) {
        if (pppppppuVar28 != (undefined8 *******)0x0) {
          local_138 = (undefined8 *******)*pppppppuVar28;
        }
        *pppppppuVar28 = (undefined8 ******)0x2;
        if ((int)(uint)local_148 < local_148._4_4_) {
          local_140[(int)(uint)local_148] = pppppppuVar28;
          local_148._0_4_ = (uint)local_148 + 1;
        }
      }
      pppppppuVar1 = local_138;
      pppppppuVar28 = local_138;
      if ((int)(uint)local_148 < local_148._4_4_) {
        if (local_138 != (undefined8 *******)0x0) {
          local_138 = (undefined8 *******)*local_138;
        }
        *pppppppuVar1 = (undefined8 ******)0x1ffffffff;
        pppppppuVar28 = local_138;
        if ((int)(uint)local_148 < local_148._4_4_) {
          local_140[(int)(uint)local_148] = pppppppuVar1;
          local_148._0_4_ = (uint)local_148 + 1;
        }
      }
      local_138 = pppppppuVar28;
      if ((int)(uint)local_148 < local_148._4_4_) {
        if (pppppppuVar28 != (undefined8 *******)0x0) {
          local_138 = (undefined8 *******)*pppppppuVar28;
        }
        *pppppppuVar28 = (undefined8 ******)0x100000000;
        if ((int)(uint)local_148 < local_148._4_4_) {
          local_140[(int)(uint)local_148] = pppppppuVar28;
          local_148._0_4_ = (uint)local_148 + 1;
        }
      }
      pppppppuVar1 = local_138;
      pppppppuVar28 = local_138;
      if ((int)(uint)local_148 < local_148._4_4_) {
        if (local_138 != (undefined8 *******)0x0) {
          local_138 = (undefined8 *******)*local_138;
        }
        *pppppppuVar1 = (undefined8 ******)0x100000001;
        pppppppuVar28 = local_138;
        if ((int)(uint)local_148 < local_148._4_4_) {
          local_140[(int)(uint)local_148] = pppppppuVar1;
          local_148._0_4_ = (uint)local_148 + 1;
        }
      }
      local_138 = pppppppuVar28;
      if ((int)(uint)local_148 < local_148._4_4_) {
        if (pppppppuVar28 != (undefined8 *******)0x0) {
          local_138 = (undefined8 *******)*pppppppuVar28;
        }
        *pppppppuVar28 = (undefined8 ******)0x100000002;
        if ((int)(uint)local_148 < local_148._4_4_) {
          local_140[(int)(uint)local_148] = pppppppuVar28;
          local_148._0_4_ = (uint)local_148 + 1;
        }
      }
      uVar14 = (ulong)local_9e;
      if (uVar14 == 0xff) goto LAB_71019f93b8;
      lVar21 = *plVar3;
      piVar10 = DAT_7103a5c420;
      if ((lVar21 != 0) && (lVar25 = *(long *)(lVar21 + uVar14 * 8 + 8), lVar25 != 0)) {
        piVar10 = (int *)(lVar25 + 0x150);
      }
      uVar18 = piVar10[1];
      if ((int)uVar18 < 0) {
LAB_71019f955c:
        local_160 = CONCAT13(local_160._3_1_,0xff0000);
      }
      else {
        lVar25 = *(long *)((uint *)*DAT_7103a59c40 + 2);
        if (*(uint *)*DAT_7103a59c40 <= uVar18) {
          uVar18 = 0;
        }
        if ((((lVar25 == 0) ||
             (lVar25 = lVar25 + (ulong)uVar18 * 0x10, *(int *)(lVar25 + 4) != *piVar10)) ||
            (lVar25 = *(long *)(lVar25 + 8), lVar25 == 0)) ||
           ((*(byte *)(lVar25 + 0x24) <= (byte)local_a0 ||
            (*(byte *)(lVar25 + 0x25) <= local_a0._1_1_)))) goto LAB_71019f955c;
        local_160._0_3_ = CONCAT12(local_9e,local_a0);
      }
LAB_71019f9570:
      piVar10 = DAT_7103a5c420;
      if ((lVar21 != 0) && (lVar21 = *(long *)(lVar21 + uVar14 * 8 + 8), lVar21 != 0)) {
        piVar10 = (int *)(lVar21 + 0x150);
      }
      uVar18 = piVar10[1];
      if ((int)uVar18 < 0) goto LAB_71019f9648;
      lVar21 = *(long *)((uint *)*DAT_7103a59c40 + 2);
      if (*(uint *)*DAT_7103a59c40 <= uVar18) {
        uVar18 = 0;
        if (lVar21 != 0) goto LAB_71019f95b8;
        goto LAB_71019f9648;
      }
      if (lVar21 == 0) goto LAB_71019f9648;
LAB_71019f95b8:
      lVar21 = lVar21 + (ulong)uVar18 * 0x10;
      if ((((*(int *)(lVar21 + 4) != *piVar10) || (lVar21 = *(long *)(lVar21 + 8), lVar21 == 0)) ||
          (*(byte *)(lVar21 + 0x24) <= (byte)local_a0)) ||
         (*(byte *)(lVar21 + 0x25) <= local_a0._1_1_)) goto LAB_71019f9648;
      uVar18 = *param_4;
      local_16e = (byte)uVar14;
      cVar26 = (char)(0xffff0101 >> (ulong)(uVar18 << 3 & 0x1f));
      cVar23 = (char)(0x1ffff01 >> (ulong)(uVar18 << 3 & 0x1f));
      if (3 < uVar18) {
        cVar26 = '\x01';
      }
      if (3 < uVar18) {
        cVar23 = '\x01';
      }
      local_170 = CONCAT11(cVar23 + local_a0._1_1_,cVar26 + (byte)local_a0);
    }
    else {
      pppppppuVar1 = local_138;
      if ((int)(uint)local_148 < local_148._4_4_) {
        if (local_138 != (undefined8 *******)0x0) {
          local_138 = (undefined8 *******)*local_138;
        }
        *pppppppuVar28 = (undefined8 ******)0x1;
        pppppppuVar1 = local_138;
        if ((int)(uint)local_148 < local_148._4_4_) {
          local_140[(int)(uint)local_148] = pppppppuVar28;
          local_148._0_4_ = (uint)local_148 + 1;
        }
      }
      local_138 = pppppppuVar1;
      if ((int)(uint)local_148 < local_148._4_4_) {
        if (pppppppuVar1 != (undefined8 *******)0x0) {
          local_138 = (undefined8 *******)*pppppppuVar1;
        }
        *pppppppuVar1 = (undefined8 ******)0x2;
        if ((int)(uint)local_148 < local_148._4_4_) {
          local_140[(int)(uint)local_148] = pppppppuVar1;
          local_148._0_4_ = (uint)local_148 + 1;
        }
      }
      pppppppuVar1 = local_138;
      pppppppuVar28 = local_138;
      if ((int)(uint)local_148 < local_148._4_4_) {
        if (local_138 != (undefined8 *******)0x0) {
          local_138 = (undefined8 *******)*local_138;
        }
        *pppppppuVar1 = (undefined8 ******)0x100000000;
        pppppppuVar28 = local_138;
        if ((int)(uint)local_148 < local_148._4_4_) {
          local_140[(int)(uint)local_148] = pppppppuVar1;
          local_148._0_4_ = (uint)local_148 + 1;
        }
      }
      local_138 = pppppppuVar28;
      if ((int)(uint)local_148 < local_148._4_4_) {
        if (pppppppuVar28 != (undefined8 *******)0x0) {
          local_138 = (undefined8 *******)*pppppppuVar28;
        }
        *pppppppuVar28 = (undefined8 ******)0x100000001;
        if ((int)(uint)local_148 < local_148._4_4_) {
          local_140[(int)(uint)local_148] = pppppppuVar28;
          local_148._0_4_ = (uint)local_148 + 1;
        }
      }
      pppppppuVar28 = local_138;
      if ((int)(uint)local_148 < local_148._4_4_) {
        if (local_138 != (undefined8 *******)0x0) {
          local_138 = (undefined8 *******)*local_138;
        }
        *pppppppuVar28 = (undefined8 ******)0x100000002;
        if ((int)(uint)local_148 < local_148._4_4_) {
          local_140[(int)(uint)local_148] = pppppppuVar28;
          local_148._0_4_ = (uint)local_148 + 1;
        }
      }
      uVar14 = (ulong)local_9e;
      if (uVar14 != 0xff) {
        lVar21 = *plVar3;
        piVar10 = DAT_7103a5c420;
        if ((lVar21 != 0) && (lVar25 = *(long *)(lVar21 + uVar14 * 8 + 8), lVar25 != 0)) {
          piVar10 = (int *)(lVar25 + 0x150);
        }
        uVar18 = piVar10[1];
        if (-1 < (int)uVar18) {
          lVar25 = *(long *)((uint *)*DAT_7103a59c40 + 2);
          if (*(uint *)*DAT_7103a59c40 <= uVar18) {
            uVar18 = 0;
          }
          if ((((lVar25 != 0) &&
               (lVar25 = lVar25 + (ulong)uVar18 * 0x10, *(int *)(lVar25 + 4) == *piVar10)) &&
              (lVar25 = *(long *)(lVar25 + 8), lVar25 != 0)) &&
             (((byte)local_a0 < *(byte *)(lVar25 + 0x24) &&
              (local_a0._1_1_ < *(byte *)(lVar25 + 0x25))))) {
            uVar18 = *param_4;
            cVar23 = (char)(0xff0001 >> (ulong)(uVar18 << 3 & 0x1f));
            cVar26 = (char)(0x100ff00 >> (ulong)(uVar18 << 3 & 0x1f));
            if (3 < uVar18) {
              cVar23 = '\x01';
            }
            if (3 < uVar18) {
              cVar26 = '\0';
            }
            local_160._0_2_ = CONCAT11(cVar26 + local_a0._1_1_,cVar23 + (byte)local_a0);
            local_160 = CONCAT22(CONCAT11(local_160._3_1_,local_9e),(undefined2)local_160);
            goto LAB_71019f9570;
          }
        }
        goto LAB_71019f955c;
      }
LAB_71019f93b8:
      local_160 = CONCAT13(local_160._3_1_,0xff0000);
LAB_71019f9648:
      local_170 = 0;
      local_16e = 0xff;
    }
    local_168 = lVar13 + 0x10;
    local_178 = lVar13 + 0x10;
    pfVar8 = (float *)FUN_7101d33efc((long)&local_168);
    pfVar9 = (float *)FUN_7101d33efc((long)&local_178);
    fVar29 = *pfVar8;
    fVar30 = pfVar8[1];
    uVar34 = 0x40626e98;
    fVar32 = *pfVar9;
    fVar33 = pfVar9[1];
    uVar12 = 0x40b1374c;
LAB_71019f96dc:
    fVar29 = (fVar29 + fVar32) * 0.5;
    fVar30 = (fVar30 + fVar33) * 0.5;
    fVar32 = (pfVar8[2] + pfVar9[2]) * 0.5;
  }
  piVar10 = DAT_7103a5c420;
  piVar11 = DAT_7103a5c420;
  if (((*(uint *)(plVar17 + 0x29) < 0x100) && (*plVar3 != 0)) &&
     (lVar21 = *(long *)(*plVar3 + (ulong)*(uint *)(plVar17 + 0x29) * 8 + 8), lVar21 != 0)) {
    piVar11 = (int *)(lVar21 + 0x150);
  }
  FUN_7101d0c8e0(&local_168,(float *)((long)plVar17 + 0x11c),piVar11);
  local_178 = lVar13 + 0x10;
  local_170 = (undefined2)local_160;
  local_16e = local_160._2_1_;
  FUN_71019f3b88(abStack_88,(long)&local_178);
  if ((uint)local_148 != 0) {
    pppppppuVar1 = local_140 + (int)(uint)local_148;
    pppppppuVar28 = local_140;
    do {
      ppppppuVar27 = *pppppppuVar28;
      FUN_71019e8b20(&local_168,(long)&local_a8,(undefined4 *)ppppppuVar27,param_4);
      if ((ulong)local_160._2_1_ == 0xff) {
        return 0;
      }
      if (*plVar3 == 0) {
        uVar18 = piVar10[1];
      }
      else {
        lVar13 = *(long *)(*plVar3 + (ulong)local_160._2_1_ * 8 + 8);
        if (lVar13 != 0) {
          piVar10 = (int *)(lVar13 + 0x150);
        }
        uVar18 = piVar10[1];
      }
      if ((int)uVar18 < 0) {
        return 0;
      }
      puVar22 = (uint *)*DAT_7103a59c40;
      if (uVar18 < *puVar22) {
        lVar13 = *(long *)(puVar22 + 2);
      }
      else {
        uVar18 = 0;
        lVar13 = *(long *)(puVar22 + 2);
      }
      if (lVar13 == 0) {
        return 0;
      }
      lVar13 = lVar13 + (ulong)uVar18 * 0x10;
      if (*(int *)(lVar13 + 4) != *piVar10) {
        return 0;
      }
      lVar13 = *(long *)(lVar13 + 8);
      if (lVar13 == 0) {
        return 0;
      }
      if ((uint)*(byte *)(lVar13 + 0x24) <= (local_160 & 0xff)) {
        return 0;
      }
      if (*(byte *)(lVar13 + 0x25) <= local_160._1_1_) {
        return 0;
      }
      uVar14 = FUN_71019f59c0((long)&local_168,1,0,1);
      if ((uVar14 & 1) == 0) {
        return 0;
      }
      bVar5 = FUN_71019f3d80(abStack_88,(long)&local_168);
      if (!bVar5) {
        return 0;
      }
      uVar18 = 0;
LAB_71019f989c:
      do {
        if ((uVar6 & 1) == 0) {
          if (*(int *)ppppppuVar27 + 1U < 2 &&
              (*(int *)((long)ppppppuVar27 + 4) == 0 && uVar18 == 0)) goto LAB_71019f98e0;
LAB_71019f9960:
          if (3 < uVar18) {
            return 0;
          }
          iVar20 = *(int *)ppppppuVar27;
          iVar24 = *(int *)((long)ppppppuVar27 + 4);
          switch(uVar18) {
          case 0:
            iVar24 = iVar24 + -1;
            if ((uint)local_148 != 0) goto LAB_71019f9a1c;
            goto LAB_71019f9a4c;
          case 1:
            iVar24 = iVar24 + 1;
            break;
          case 2:
            iVar20 = iVar20 + -1;
            break;
          case 3:
            iVar20 = iVar20 + 1;
          }
          if ((uint)local_148 == 0) {
LAB_71019f9a4c:
            uVar18 = uVar18 + 1;
            if (uVar18 == 4) break;
            goto LAB_71019f989c;
          }
LAB_71019f9a1c:
          lVar13 = (long)(int)(uint)local_148 << 3;
          pppppppuVar16 = local_140;
          do {
            if (iVar20 == *(int *)*pppppppuVar16 && iVar24 == *(int *)((long)*pppppppuVar16 + 4))
            goto LAB_71019f98e0;
            pppppppuVar16 = pppppppuVar16 + 1;
            lVar13 = lVar13 + -8;
          } while (lVar13 != 0);
        }
        else {
          if (*(int *)ppppppuVar27 != 0 || (*(int *)((long)ppppppuVar27 + 4) != 0 || uVar18 != 0))
          goto LAB_71019f9960;
LAB_71019f98e0:
          if (((ulong)local_160._2_1_ == 0xff) ||
             (lVar13 = *(long *)(*(long *)(*plVar3 + 0x818) + 0x10), lVar13 == 0)) {
LAB_71019f9924:
            puVar7 = FUN_7100bc42c8();
          }
          else {
            puVar22 = (uint *)(lVar13 + 8 + (ulong)local_160._2_1_ * 0x10);
            if (*(long *)(puVar22 + 2) == 0) goto LAB_71019f9924;
            bVar5 = false;
            bVar4 = false;
            if ((local_160 & 0xff) < *puVar22) {
              bVar4 = (uint)local_160._1_1_ <= puVar22[1];
              bVar5 = puVar22[1] == (uint)local_160._1_1_;
            }
            if ((!bVar4 || bVar5) ||
               (puVar7 = *(undefined8 **)
                          (*(long *)(puVar22 + 2) +
                          (long)(int)((local_160 & 0xff) + *puVar22 * (uint)local_160._1_1_) * 8),
               puVar7 == (undefined8 *)0x0)) goto LAB_71019f9924;
          }
          switch(*param_4) {
          case 0:
            puVar15 = &DAT_71030bada0;
            break;
          case 1:
            puVar15 = &DAT_71030bab60;
            break;
          case 2:
            puVar15 = &DAT_71030bad20;
            break;
          case 3:
            puVar15 = &DAT_71030b9f80;
            break;
          default:
            goto switchD_71019f9940_default;
          }
          if (uVar18 < 4) {
            lVar13 = puVar15[(int)uVar18];
          }
          else {
switchD_71019f9940_default:
            lVar13 = 1;
          }
          uVar19 = *(uint *)((long)puVar7 + lVar13 * 0xc + 0xc);
          if (-1 < (int)uVar19) {
            lVar21 = *(long *)((uint *)*DAT_7103a59c40 + 2);
            if (lVar21 != 0) {
              if (*(uint *)*DAT_7103a59c40 <= uVar19) {
                uVar19 = 0;
              }
              if (*(int *)(lVar21 + (ulong)uVar19 * 0x10 + 4) ==
                  *(int *)((long)puVar7 + lVar13 * 0xc + 8)) {
                return 0;
              }
            }
          }
        }
        bVar5 = (int)uVar18 < 3;
        uVar18 = uVar18 + 1;
      } while (bVar5);
      pppppppuVar28 = pppppppuVar28 + 1;
      piVar10 = DAT_7103a5c420;
    } while (pppppppuVar28 != pppppppuVar1);
  }
  local_148 = CONCAT44(fVar30,fVar29);
  uVar6 = param_2[1];
  local_140 = (undefined8 *******)CONCAT44(*param_4,fVar32);
  uVar31 = uVar34;
  if ((*param_4 & 0xfffffffd) != 0) {
    uVar31 = uVar12;
    uVar12 = uVar34;
  }
  local_138 = (undefined8 *******)CONCAT44(uVar31,uVar12);
  if (-1 < (int)uVar6) {
    lVar13 = *(long *)((uint *)*DAT_7103a59c40 + 2);
    if (lVar13 != 0) {
      if (*(uint *)*DAT_7103a59c40 <= uVar6) {
        uVar6 = 0;
      }
      if (*(int *)(lVar13 + (ulong)uVar6 * 0x10 + 4) == *param_2) {
        puVar7 = *(undefined8 **)(lVar13 + (ulong)uVar6 * 0x10 + 8);
        if (puVar7 == (undefined8 *)0x0) {
          puVar7 = FUN_7100baff84();
        }
        iVar20 = *(int *)((long)puVar7 + 0x84);
        lVar13 = (long)iVar20 + (long)puVar7 + 0x84;
        if (iVar20 != 0 && lVar13 != 0) {
          iVar20 = *(int *)(lVar13 + 0x148);
          goto LAB_71019f9b6c;
        }
      }
    }
  }
  iVar20 = -1;
LAB_71019f9b6c:
  if ((int)param_1[0x26] < (int)param_1[0x25]) {
    FUN_71019f42b8(param_1,&local_148,iVar20);
    iVar20 = (int)param_1[0x26];
    iVar24 = (int)param_1[0x25];
    if (iVar20 < iVar24) {
      *(int *)(param_1 + 0x26) = iVar20 + 1;
      iVar20 = *(int *)((long)param_1 + 300) + iVar20;
      iVar2 = 0;
      if (iVar24 <= iVar20) {
        iVar2 = iVar24;
      }
      plVar17 = (long *)(param_1[0x24] + (long)(iVar20 - iVar2) * 0x18);
      *plVar17 = local_148;
      plVar17[1] = (long)local_140;
      plVar17[2] = (long)local_138;
    }
  }
  return 1;
}



uint FUN_71019f9bf0(long *param_1,int *param_2,int *param_3,uint *param_4)

{
  uint uVar1;
  ulong uVar2;
  undefined8 uVar3;
  uint local_28;
  uint local_24;
  
  uVar1 = param_2[1];
  if ((int)uVar1 < 0) {
    return 0;
  }
  if (*(long *)(DAT_71040e7d48 + 2) != 0) {
    if (*DAT_71040e7d48 <= uVar1) {
      uVar1 = 0;
    }
    if (*(int *)(*(long *)(DAT_71040e7d48 + 2) + (ulong)uVar1 * 0x10 + 4) == *param_2) {
      uVar2 = FUN_71019f8910(param_1,param_2,param_3,param_4);
      if ((uVar2 & 1) == 0) {
        uVar2 = FUN_71019f8910(param_1,param_2,param_3,param_4 + 1);
        if ((uVar2 & 1) == 0) {
          uVar1 = param_4[1] - 1;
          if (uVar1 < 3) {
            local_24 = *(uint *)(&DAT_71032b4b8c + (long)(int)uVar1 * 4);
          }
          else {
            local_24 = 2;
          }
          uVar2 = FUN_71019f8910(param_1,param_2,param_3,&local_24);
          if ((uVar2 & 1) == 0) {
            if (*param_4 - 1 < 3) {
              local_28 = *(uint *)(&DAT_71032b4b8c + (long)(int)(*param_4 - 1) * 4);
            }
            else {
              local_28 = 2;
            }
            uVar3 = FUN_71019f8910(param_1,param_2,param_3,&local_28);
            uVar1 = (uint)uVar3;
            goto LAB_71019f9cbc;
          }
        }
      }
      uVar1 = 1;
      goto LAB_71019f9cbc;
    }
  }
  uVar1 = 0;
LAB_71019f9cbc:
  return uVar1 & 1;
}



undefined8 FUN_71019f9d30(long *param_1,int *param_2,int *param_3)

{
  int iVar1;
  int *piVar2;
  undefined4 uVar3;
  int iVar4;
  int iVar5;
  undefined8 *puVar6;
  bool bVar7;
  uint uVar8;
  undefined8 *puVar9;
  float *pfVar10;
  long *plVar11;
  int *piVar12;
  long lVar13;
  ulong uVar14;
  uint uVar15;
  uint *puVar16;
  long lVar17;
  float fVar18;
  undefined4 uVar19;
  long local_68;
  byte local_60;
  byte bStack_5f;
  byte bStack_5e;
  undefined1 uStack_5d;
  uint uStack_5c;
  undefined4 local_58;
  undefined4 uStack_54;
  long local_50;
  byte local_48;
  byte local_47;
  byte local_46;
  
  puVar6 = DAT_7103a59c40;
  if (param_1 == (long *)0x0) {
    return 0;
  }
  uVar15 = param_2[1];
  if ((int)uVar15 < 0) {
    return 0;
  }
  lVar13 = *(long *)((uint *)*DAT_7103a59c40 + 2);
  if (lVar13 == 0) {
    return 0;
  }
  if (*(uint *)*DAT_7103a59c40 <= uVar15) {
    uVar15 = 0;
  }
  if (*(int *)(lVar13 + (ulong)uVar15 * 0x10 + 4) != *param_2) {
    return 0;
  }
  puVar9 = *(undefined8 **)(lVar13 + (ulong)uVar15 * 0x10 + 8);
  if (puVar9 == (undefined8 *)0x0) {
    puVar9 = FUN_7100baff84();
  }
  iVar5 = *(int *)((long)puVar9 + 0x84);
  plVar11 = (long *)((long)iVar5 + (long)puVar9 + 0x84);
  if (iVar5 == 0 || plVar11 == (long *)0x0) {
    return 0;
  }
  pfVar10 = (float *)(**(code **)(*plVar11 + 0xa8))();
  plVar11 = DAT_7103a5a160;
  piVar12 = DAT_7103a5c420;
  if ((*DAT_7103a5a160 != 0) && (lVar13 = *(long *)(*DAT_7103a5a160 + 8), lVar13 != 0)) {
    piVar12 = (int *)(lVar13 + 0x150);
  }
  FUN_7101d0c8e0(&local_68,pfVar10,piVar12);
  piVar12 = DAT_7103a5c420;
  local_50 = DAT_7103a5a2a8 + 0x10;
  local_48 = local_60;
  local_46 = bStack_5e;
  local_47 = bStack_5f;
  if ((ulong)bStack_5e == 0xff) {
    return 0;
  }
  lVar13 = *plVar11;
  piVar2 = DAT_7103a5c420;
  if (lVar13 == 0) {
    uVar15 = DAT_7103a5c420[1];
  }
  else {
    lVar13 = *(long *)(lVar13 + (ulong)bStack_5e * 8 + 8);
    if (lVar13 != 0) {
      piVar2 = (int *)(lVar13 + 0x150);
    }
    uVar15 = piVar2[1];
  }
  if ((int)uVar15 < 0) {
    return 0;
  }
  puVar16 = (uint *)*puVar6;
  uVar8 = *puVar16;
  lVar13 = *(long *)(puVar16 + 2);
  if (uVar8 <= uVar15) {
    uVar15 = 0;
  }
  if (lVar13 == 0) {
    return 0;
  }
  lVar17 = lVar13 + (ulong)uVar15 * 0x10;
  if (*(int *)(lVar17 + 4) != *piVar2) {
    return 0;
  }
  lVar17 = *(long *)(lVar17 + 8);
  if (lVar17 == 0) {
    return 0;
  }
  if (*(byte *)(lVar17 + 0x24) <= local_60) {
    return 0;
  }
  if (*(byte *)(lVar17 + 0x25) <= bStack_5f) {
    return 0;
  }
  uVar15 = param_2[1];
  if (-1 < (int)uVar15) {
    if (uVar8 <= uVar15) {
      uVar15 = 0;
    }
    if ((*(int *)(lVar13 + (ulong)uVar15 * 0x10 + 4) == *param_2) &&
       (puVar9 = *(undefined8 **)(lVar13 + (ulong)uVar15 * 0x10 + 8), puVar9 != (undefined8 *)0x0))
    goto LAB_71019f9ee8;
  }
  puVar9 = FUN_7100baff84();
LAB_71019f9ee8:
  iVar5 = *(int *)(puVar9 + 0x13);
  if (iVar5 == 0) {
    return 0;
  }
  lVar13 = (long)iVar5 + (long)(puVar9 + 0x13);
  if (lVar13 == 0) {
    return 0;
  }
  fVar18 = *(float *)(lVar13 + 0x30);
  uVar15 = 0;
  if (fVar18 != (float)(int)fVar18) {
    uVar15 = (uint)(fVar18 < 0.0);
  }
  iVar5 = (int)fVar18 - uVar15;
  if (iVar5 < 0xb4) {
    if ((int)fVar18 == uVar15) {
      uVar15 = 0;
    }
    else {
      if (iVar5 != 0x5a) {
        return 0;
      }
      uVar15 = 1;
    }
  }
  else if (iVar5 == 0xb4) {
    uVar15 = 2;
  }
  else if (iVar5 == 0x10e) {
    uVar15 = 3;
  }
  else {
    uVar15 = 0;
    if (iVar5 != 0x168) {
      return 0;
    }
  }
  lVar13 = *(long *)(*plVar11 + 8);
  if (lVar13 != 0) {
    piVar12 = (int *)(lVar13 + 0x150);
  }
  uVar8 = piVar12[1];
  if (-1 < (int)uVar8) {
    puVar16 = (uint *)*puVar6;
    lVar13 = *(long *)(puVar16 + 2);
    if (lVar13 != 0) {
      if (*puVar16 <= uVar8) {
        uVar8 = 0;
      }
      if (*(int *)(lVar13 + (ulong)uVar8 * 0x10 + 4) == *piVar12) {
        uVar8 = FUN_71019fc360(*param_3);
        if (uVar8 < 0x19) {
          piVar12 = &DAT_71040e58d8 + (ulong)uVar8 * 8;
        }
        else {
          piVar12 = &DAT_71040e58d8;
        }
        if ((char)piVar12[3] == '\0') {
          return 0;
        }
        if ((char)piVar12[7] != '\0') {
          return 0;
        }
        if ((*piVar12 == 0 && piVar12[1] == 0) && ((piVar12[2] == 9 || (piVar12[2] == 4)))) {
          plVar11 = (long *)FUN_7101d33efc((long)&local_50);
          uVar8 = piVar12[2] - 2;
          if (uVar8 < 0x10) {
            uVar14 = -(ulong)(uVar8 >> 0x1f) & 0xfffffffc00000000 | (ulong)uVar8 << 2;
            uVar19 = *(undefined4 *)(&DAT_71032b4b98 + uVar14);
            uStack_54 = *(undefined4 *)(&DAT_71032b4bd8 + uVar14);
          }
          else {
            uVar19 = 0x40000000;
            uStack_54 = 0x40000000;
          }
          local_68 = *plVar11;
          bVar7 = (uVar15 & 1) != 0;
          local_58 = uVar19;
          if (bVar7) {
            local_58 = uStack_54;
          }
          uVar3 = (undefined4)plVar11[1];
          if (bVar7) {
            uStack_54 = uVar19;
          }
          local_60 = (byte)uVar3;
          bStack_5f = (byte)((uint)uVar3 >> 8);
          bStack_5e = (byte)((uint)uVar3 >> 0x10);
          uStack_5d = (undefined1)((uint)uVar3 >> 0x18);
          if ((int)param_1[0x26] < (int)param_1[0x25]) {
            uStack_5c = uVar15;
            FUN_71019f42b8(param_1,&local_68,0);
            iVar5 = (int)param_1[0x26];
            iVar4 = (int)param_1[0x25];
            if (iVar5 < iVar4) {
              *(int *)(param_1 + 0x26) = iVar5 + 1;
              iVar5 = *(int *)((long)param_1 + 300) + iVar5;
              iVar1 = 0;
              if (iVar4 <= iVar5) {
                iVar1 = iVar4;
              }
              plVar11 = (long *)(param_1[0x24] + (long)(iVar5 - iVar1) * 0x18);
              *plVar11 = local_68;
              plVar11[1] = CONCAT44(uStack_5c,
                                    CONCAT13(uStack_5d,
                                             CONCAT12(bStack_5e,CONCAT11(bStack_5f,local_60))));
              plVar11[2] = CONCAT44(uStack_54,local_58);
            }
          }
          return 1;
        }
      }
    }
  }
  return 0;
}



void FUN_71019fa128(long param_1)

{
  if (*(char *)(param_1 + 0xec) != '\0') {
    *(undefined1 *)(param_1 + 0xec) = 0;
  }
  if (*(char *)(param_1 + 0xe0) != '\0') {
    *(undefined1 *)(param_1 + 0xe0) = 0;
  }
  if (*(char *)(param_1 + 0xd4) != '\0') {
    *(undefined1 *)(param_1 + 0xd4) = 0;
  }
  if (*(char *)(param_1 + 200) != '\0') {
    *(undefined1 *)(param_1 + 200) = 0;
  }
  if (*(char *)(param_1 + 0xbc) != '\0') {
    *(undefined1 *)(param_1 + 0xbc) = 0;
  }
  if (*(char *)(param_1 + 0xb0) != '\0') {
    *(undefined1 *)(param_1 + 0xb0) = 0;
  }
  if (*(char *)(param_1 + 0xa4) != '\0') {
    *(undefined1 *)(param_1 + 0xa4) = 0;
  }
  if (*(char *)(param_1 + 0x98) != '\0') {
    *(undefined1 *)(param_1 + 0x98) = 0;
  }
  if (*(char *)(param_1 + 0x8c) != '\0') {
    *(undefined1 *)(param_1 + 0x8c) = 0;
  }
  if (*(char *)(param_1 + 0x80) != '\0') {
    *(undefined1 *)(param_1 + 0x80) = 0;
  }
  if (*(char *)(param_1 + 0x74) != '\0') {
    *(undefined1 *)(param_1 + 0x74) = 0;
  }
  if (*(char *)(param_1 + 0x68) != '\0') {
    *(undefined1 *)(param_1 + 0x68) = 0;
  }
  if (*(char *)(param_1 + 0x5c) != '\0') {
    *(undefined1 *)(param_1 + 0x5c) = 0;
  }
  if (*(char *)(param_1 + 0x50) != '\0') {
    *(undefined1 *)(param_1 + 0x50) = 0;
  }
  if (*(char *)(param_1 + 0x44) != '\0') {
    *(undefined1 *)(param_1 + 0x44) = 0;
  }
  if (*(char *)(param_1 + 0x38) != '\0') {
    *(undefined1 *)(param_1 + 0x38) = 0;
  }
  if (*(char *)(param_1 + 0x2c) != '\0') {
    *(undefined1 *)(param_1 + 0x2c) = 0;
  }
  if (*(char *)(param_1 + 0x20) != '\0') {
    *(undefined1 *)(param_1 + 0x20) = 0;
  }
  if (*(char *)(param_1 + 0x14) != '\0') {
    *(undefined1 *)(param_1 + 0x14) = 0;
  }
  if (*(char *)(param_1 + 8) != '\0') {
    *(undefined1 *)(param_1 + 8) = 0;
  }
  return;
}



undefined4 FUN_71019fc360(int param_1)

{
  if (param_1 - 2U < 0x4e) {
    return *(undefined4 *)(&DAT_71032b4c18 + (long)(int)(param_1 - 2U) * 4);
  }
  return 0;
}



void FUN_71019fc62c(undefined8 *param_1,undefined8 *param_2,long *param_3)

{
  undefined4 uVar1;
  undefined4 *puVar2;
  
  puVar2 = DAT_7103a59b30;
  if (*(char *)((long)param_3 + 0x224) != '\0' || (int)param_3[2] != 0) {
    *param_1 = *param_2;
    uVar1 = *puVar2;
    *(undefined4 *)((long)param_1 + 0xc) = puVar2[1];
    *(undefined4 *)(param_1 + 2) = 5;
    *(undefined4 *)(param_1 + 1) = uVar1;
    FUN_7100bec0b0(param_1 + 4,param_3);
    return;
  }
  return;
}



bool FUN_71019fc670(int *param_1,int *param_2,int *param_3,int *param_4)

{
  uint uVar1;
  int iVar2;
  undefined8 *puVar3;
  bool bVar4;
  
  uVar1 = param_2[1];
  if (-1 < (int)uVar1) {
    if (*(long *)(DAT_71040e7d48 + 2) != 0) {
      if (*DAT_71040e7d48 <= uVar1) {
        uVar1 = 0;
      }
      if (*(int *)(*(long *)(DAT_71040e7d48 + 2) + (ulong)uVar1 * 0x10 + 4) == *param_2) {
        *(undefined8 *)param_1 = *(undefined8 *)param_2;
        iVar2 = DAT_71040104c4;
        param_1[2] = DAT_71040104c0;
        param_1[3] = iVar2;
        puVar3 = DAT_7103a5ba00;
        iVar2 = *param_4;
        param_1[0xb] = 0;
        param_1[0xc] = 0;
        param_1[0x2f] = 0;
        param_1[0x30] = 0;
        param_1[0x74] = 0;
        param_1[0x75] = 0;
        *(undefined8 *)(param_1 + 0x77) = *puVar3;
        param_1[0x53] = 0;
        param_1[0x54] = 0;
        param_1[0x79] = *(int *)(puVar3 + 1);
        param_1[0x76] = 0;
        param_1[4] = iVar2;
        param_1[0x8e] = 0;
        param_1[0x8f] = 0;
        param_1[0x8c] = 0;
        param_1[0x8d] = 0;
        *(undefined1 *)(param_1 + 0x91) = 0;
        param_1[0x7a] = 0;
        param_1[0x7b] = 0;
        param_1[0x7c] = 0x3f800000;
        param_1[0x82] = 0;
        param_1[0x83] = 0;
        param_1[0x80] = 0x3f800000;
        param_1[0x81] = 0;
        param_1[0x86] = 0;
        param_1[0x87] = 0;
        param_1[0x84] = 0;
        param_1[0x85] = 0x3f800000;
        param_1[0x90] = -1;
        param_1[0x8a] = 0x3f800000;
        param_1[0x8b] = 0;
        param_1[0x88] = 0;
        param_1[0x89] = 0;
        bVar4 = FUN_71019fcad4(param_1,param_2,param_3);
        return bVar4;
      }
    }
  }
  return false;
}



bool FUN_71019fc760(int *param_1,int *param_2,int *param_3,int *param_4,int *param_5)

{
  int iVar1;
  uint uVar2;
  int *piVar3;
  bool bVar4;
  long lVar5;
  undefined8 *puVar6;
  
  piVar3 = DAT_7103a59b30;
  uVar2 = param_2[1];
  if ((int)uVar2 < 0) {
    return false;
  }
  if (*(long *)(DAT_71040e7d48 + 2) != 0) {
    if (*DAT_71040e7d48 <= uVar2) {
      uVar2 = 0;
    }
    if (*(int *)(*(long *)(DAT_71040e7d48 + 2) + (ulong)uVar2 * 0x10 + 4) == *param_2) {
      *(undefined8 *)param_1 = *(undefined8 *)param_2;
      iVar1 = piVar3[1];
      param_1[2] = *piVar3;
      param_1[3] = iVar1;
      puVar6 = DAT_7103a5ba00;
      iVar1 = *param_5;
      param_1[0xb] = 0;
      param_1[0xc] = 0;
      param_1[0x2f] = 0;
      param_1[0x30] = 0;
      param_1[0x74] = 0;
      param_1[0x75] = 0;
      *(undefined8 *)(param_1 + 0x77) = *puVar6;
      param_1[0x53] = 0;
      param_1[0x54] = 0;
      param_1[0x79] = *(int *)(puVar6 + 1);
      param_1[0x76] = 0;
      param_1[4] = iVar1;
      param_1[0x8e] = 0;
      param_1[0x8f] = 0;
      param_1[0x8c] = 0;
      param_1[0x8d] = 0;
      *(undefined1 *)(param_1 + 0x91) = 0;
      param_1[0x7a] = 0;
      param_1[0x7b] = 0;
      param_1[0x7c] = 0x3f800000;
      param_1[0x82] = 0;
      param_1[0x83] = 0;
      param_1[0x80] = 0x3f800000;
      param_1[0x81] = 0;
      param_1[0x86] = 0;
      param_1[0x87] = 0;
      param_1[0x84] = 0;
      param_1[0x85] = 0x3f800000;
      param_1[0x90] = -1;
      param_1[0x8a] = 0x3f800000;
      param_1[0x8b] = 0;
      param_1[0x88] = 0;
      param_1[0x89] = 0;
      bVar4 = FUN_71019fcad4(param_1,param_2,param_3);
      if (!bVar4) {
        return false;
      }
      if (*param_4 != 0) {
        lVar5 = (long)*param_4 * 8;
        puVar6 = *(undefined8 **)(param_4 + 2);
        do {
          lVar5 = lVar5 + -8;
          bVar4 = FUN_71019fc8cc(param_1,param_2,(int *)*puVar6);
          if (!bVar4) {
            return bVar4;
          }
          puVar6 = puVar6 + 1;
        } while (lVar5 != 0);
        return bVar4;
      }
      return true;
    }
  }
  return false;
}



bool FUN_71019fc8cc(int *param_1,int *param_2,int *param_3)

{
  int iVar1;
  undefined8 *puVar2;
  long *plVar3;
  uint uVar4;
  long lVar5;
  long alStack_4c [3];
  char local_34;
  
  FUN_71019fcbf0(alStack_4c,param_1,param_2,param_3);
  if (local_34 == '\0') goto LAB_71019fc970;
  uVar4 = param_1[1];
  if ((int)uVar4 < 0) {
LAB_71019fc94c:
    puVar2 = FUN_7100baff84();
  }
  else {
    lVar5 = *(long *)(DAT_71040e7d48 + 2);
    if (*DAT_71040e7d48 <= uVar4) {
      uVar4 = 0;
      if (lVar5 != 0) goto LAB_71019fc920;
      goto LAB_71019fc94c;
    }
    if (lVar5 == 0) goto LAB_71019fc94c;
LAB_71019fc920:
    lVar5 = lVar5 + (ulong)uVar4 * 0x10;
    if ((*(int *)(lVar5 + 4) != *param_1) ||
       (puVar2 = *(undefined8 **)(lVar5 + 8), puVar2 == (undefined8 *)0x0)) goto LAB_71019fc94c;
  }
  iVar1 = *(int *)((long)puVar2 + 0x84);
  if ((iVar1 == 0) || (plVar3 = (long *)((long)iVar1 + (long)puVar2 + 0x84), plVar3 == (long *)0x0))
  {
    plVar3 = FUN_7100bbfd30();
  }
  FUN_71019f42b8((long *)(param_1 + 8),alStack_4c,(int)plVar3[0x29]);
LAB_71019fc970:
  return local_34 != '\0';
}



bool FUN_71019fc994(int *param_1,int *param_2,int *param_3,int *param_4,int *param_5,int *param_6)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  undefined8 *puVar4;
  bool bVar5;
  long lVar6;
  uint uVar7;
  
  uVar7 = param_2[1];
  if (-1 < (int)uVar7) {
    lVar6 = *(long *)(DAT_71040e7d48 + 2);
    if (lVar6 != 0) {
      uVar1 = *DAT_71040e7d48;
      if (uVar1 <= uVar7) {
        uVar7 = 0;
      }
      if ((*(int *)(lVar6 + (ulong)uVar7 * 0x10 + 4) == *param_2) &&
         (uVar7 = param_3[1], -1 < (int)uVar7)) {
        if (uVar1 <= uVar7) {
          uVar7 = 0;
        }
        if ((*(int *)(lVar6 + (ulong)uVar7 * 0x10 + 4) == *param_3) &&
           (uVar7 = param_4[1], -1 < (int)uVar7)) {
          if (uVar1 <= uVar7) {
            uVar7 = 0;
          }
          if (*(int *)(lVar6 + (ulong)uVar7 * 0x10 + 4) == *param_4) {
            *(undefined8 *)param_1 = *(undefined8 *)param_2;
            *(undefined8 *)(param_1 + 2) = *(undefined8 *)param_3;
            puVar4 = DAT_7103a5ba00;
            iVar2 = *param_6;
            param_1[0xb] = 0;
            param_1[0xc] = 0;
            param_1[0x2f] = 0;
            param_1[0x30] = 0;
            iVar3 = *(int *)(puVar4 + 1);
            *(undefined8 *)(param_1 + 0x77) = *puVar4;
            param_1[0x53] = 0;
            param_1[0x54] = 0;
            param_1[0x79] = iVar3;
            param_1[0x74] = 0;
            param_1[0x75] = 0;
            param_1[0x76] = 0;
            param_1[4] = iVar2;
            param_1[0x8e] = 0;
            param_1[0x8f] = 0;
            param_1[0x8c] = 0;
            param_1[0x8d] = 0;
            *(undefined1 *)(param_1 + 0x91) = 0;
            param_1[0x7a] = 0;
            param_1[0x7b] = 0;
            param_1[0x7c] = 0x3f800000;
            param_1[0x82] = 0;
            param_1[0x83] = 0;
            param_1[0x80] = 0x3f800000;
            param_1[0x81] = 0;
            param_1[0x86] = 0;
            param_1[0x87] = 0;
            param_1[0x84] = 0;
            param_1[0x85] = 0x3f800000;
            param_1[0x90] = -1;
            param_1[0x8a] = 0x3f800000;
            param_1[0x8b] = 0;
            param_1[0x88] = 0;
            param_1[0x89] = 0;
            bVar5 = FUN_71019fcad4(param_1,param_4,param_5);
            return bVar5;
          }
        }
      }
    }
  }
  return false;
}



bool FUN_71019fcad4(int *param_1,int *param_2,int *param_3)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined8 *puVar4;
  uint uVar5;
  long *plVar6;
  long lVar7;
  long local_3c;
  long local_34;
  long local_2c;
  char local_24;
  
  FUN_71019fcbf0(&local_3c,param_1,param_2,param_3);
  if (local_24 == '\0') goto LAB_71019fcbd0;
  uVar5 = param_1[1];
  if ((int)uVar5 < 0) {
LAB_71019fcb4c:
    puVar4 = FUN_7100baff84();
  }
  else {
    lVar7 = *(long *)(DAT_71040e7d48 + 2);
    if (*DAT_71040e7d48 <= uVar5) {
      uVar5 = 0;
      if (lVar7 != 0) goto LAB_71019fcb20;
      goto LAB_71019fcb4c;
    }
    if (lVar7 == 0) goto LAB_71019fcb4c;
LAB_71019fcb20:
    lVar7 = lVar7 + (ulong)uVar5 * 0x10;
    if ((*(int *)(lVar7 + 4) != *param_1) ||
       (puVar4 = *(undefined8 **)(lVar7 + 8), puVar4 == (undefined8 *)0x0)) goto LAB_71019fcb4c;
  }
  iVar3 = *(int *)((long)puVar4 + 0x84);
  if ((iVar3 == 0) || (plVar6 = (long *)((long)iVar3 + (long)puVar4 + 0x84), plVar6 == (long *)0x0))
  {
    plVar6 = FUN_7100bbfd30();
  }
  if (param_1[0x54] < param_1[0x52]) {
    FUN_71019f42b8((long *)(param_1 + 8),&local_3c,(int)plVar6[0x29]);
    iVar3 = param_1[0x54];
    iVar2 = param_1[0x52];
    if (iVar3 < iVar2) {
      param_1[0x54] = iVar3 + 1;
      iVar1 = 0;
      if (iVar2 <= param_1[0x53] + iVar3) {
        iVar1 = iVar2;
      }
      plVar6 = (long *)(*(long *)(param_1 + 0x50) + (long)((param_1[0x53] + iVar3) - iVar1) * 0x18);
      plVar6[1] = local_34;
      plVar6[2] = local_2c;
      *plVar6 = local_3c;
    }
  }
LAB_71019fcbd0:
  return local_24 != '\0';
}



void FUN_71019fcbf0(undefined8 *param_1,undefined8 param_2,int *param_3,int *param_4)

{
  int iVar1;
  long lVar2;
  undefined8 *puVar3;
  uint uVar4;
  uint uVar5;
  float fVar6;
  float fVar7;
  float fVar8;
  undefined8 local_50;
  undefined4 local_48;
  
  uVar5 = param_3[1];
  if (((int)uVar5 < 0) || (*(long *)(DAT_71040e7d48 + 2) == 0)) goto LAB_71019fcd44;
  if (*DAT_71040e7d48 <= uVar5) {
    uVar5 = 0;
  }
  if (((*(int *)(*(long *)(DAT_71040e7d48 + 2) + (ulong)uVar5 * 0x10 + 4) != *param_3) ||
      (*param_4 == 0)) || (lVar2 = FUN_7101227350(param_3,*param_4), lVar2 == 0))
  goto LAB_71019fcd44;
  local_50 = *(undefined8 *)(lVar2 + 0x10);
  local_48 = *(undefined4 *)(lVar2 + 0x18);
  FUN_7100bc84d0((float *)&local_50,param_3);
  fVar7 = *(float *)(lVar2 + 0x20);
  fVar8 = *(float *)(lVar2 + 0x24);
  uVar5 = param_3[1];
  if ((int)uVar5 < 0) {
LAB_71019fccd0:
    puVar3 = FUN_7100baff84();
  }
  else {
    lVar2 = *(long *)(DAT_71040e7d48 + 2);
    if (*DAT_71040e7d48 <= uVar5) {
      uVar5 = 0;
      if (lVar2 != 0) goto LAB_71019fcca4;
      goto LAB_71019fccd0;
    }
    if (lVar2 == 0) goto LAB_71019fccd0;
LAB_71019fcca4:
    lVar2 = lVar2 + (ulong)uVar5 * 0x10;
    if ((*(int *)(lVar2 + 4) != *param_3) ||
       (puVar3 = *(undefined8 **)(lVar2 + 8), puVar3 == (undefined8 *)0x0)) goto LAB_71019fccd0;
  }
  iVar1 = *(int *)(puVar3 + 0x13);
  if ((iVar1 != 0) && (lVar2 = (long)iVar1 + (long)(puVar3 + 0x13), lVar2 != 0)) {
    fVar6 = *(float *)(lVar2 + 0x30);
    uVar4 = 0;
    uVar5 = 0;
    if (fVar6 != (float)(int)fVar6) {
      uVar5 = (uint)(fVar6 < 0.0);
    }
    iVar1 = (int)fVar6 - uVar5;
    if (iVar1 < 0xb4) {
      if ((int)fVar6 != uVar5) {
        if (iVar1 != 0x5a) goto LAB_71019fcd44;
        uVar4 = 1;
      }
    }
    else if (iVar1 == 0xb4) {
      uVar4 = 2;
    }
    else if (iVar1 == 0x10e) {
      uVar4 = 3;
    }
    else if (iVar1 != 0x168) goto LAB_71019fcd44;
    param_1[1] = 0;
    param_1[2] = 0;
    *param_1 = 0;
    if ((0.0 <= fVar7) && (0.0 <= fVar8)) {
      fVar6 = fVar8;
      if ((uVar4 & 1) != 0) {
        fVar6 = fVar7;
        fVar7 = fVar8;
      }
      *param_1 = local_50;
      *(undefined4 *)(param_1 + 1) = local_48;
      *(uint *)((long)param_1 + 0xc) = uVar4;
      *(float *)(param_1 + 2) = fVar7;
      *(float *)((long)param_1 + 0x14) = fVar6;
    }
    *(undefined1 *)(param_1 + 3) = 1;
    return;
  }
LAB_71019fcd44:
  *(undefined1 *)(param_1 + 3) = 0;
  *param_1 = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  return;
}



void FUN_71019fcdb8(int *param_1,int *param_2,int *param_3)

{
  int iVar1;
  int *piVar2;
  undefined8 *puVar3;
  undefined8 *puVar4;
  undefined8 *puVar5;
  long *plVar6;
  uint uVar7;
  long lVar8;
  undefined8 uVar9;
  undefined8 local_a0;
  undefined4 local_98;
  undefined4 local_94;
  undefined4 uStack_90;
  int local_8c;
  undefined8 local_88;
  int local_80;
  undefined4 uStack_7c;
  undefined8 uStack_78;
  undefined8 local_70;
  undefined8 uStack_68;
  undefined8 local_60;
  undefined8 uStack_58;
  undefined8 local_50;
  undefined8 uStack_48;
  undefined8 local_40;
  undefined8 uStack_38;
  
  puVar5 = DAT_7103a59c40;
  uVar7 = param_2[1];
  if ((int)uVar7 < 0) {
    return;
  }
  lVar8 = *(long *)((uint *)*DAT_7103a59c40 + 2);
  if (lVar8 == 0) {
    return;
  }
  if (*(uint *)*DAT_7103a59c40 <= uVar7) {
    uVar7 = 0;
  }
  if (*(int *)(lVar8 + (ulong)uVar7 * 0x10 + 4) != *param_2) {
    return;
  }
  puVar4 = *(undefined8 **)(lVar8 + (ulong)uVar7 * 0x10 + 8);
  if (puVar4 == (undefined8 *)0x0) {
    puVar4 = FUN_7100baff84();
  }
  piVar2 = DAT_7103a59b30;
  if (*(int *)((long)puVar4 + 0x84) == 0 ||
      (long)*(int *)((long)puVar4 + 0x84) == -0x84 - (long)puVar4) {
    return;
  }
  *(undefined8 *)param_1 = *(undefined8 *)param_2;
  iVar1 = piVar2[1];
  param_1[2] = *piVar2;
  param_1[3] = iVar1;
  iVar1 = *param_3;
  param_1[0xb] = 0;
  param_1[0xc] = 0;
  param_1[0x2f] = 0;
  param_1[0x30] = 0;
  param_1[0x53] = 0;
  puVar3 = DAT_7103a5ba00;
  param_1[0x54] = 0;
  param_1[0x74] = 0;
  puVar4 = DAT_7103a5a248;
  param_1[0x75] = 0;
  param_1[0x82] = 0;
  param_1[0x83] = 0;
  param_1[0x80] = 0x3f800000;
  param_1[0x81] = 0;
  param_1[0x86] = 0;
  param_1[0x87] = 0;
  param_1[0x84] = 0;
  param_1[0x85] = 0x3f800000;
  param_1[0x76] = 0;
  param_1[0x8e] = 0;
  param_1[0x8f] = 0;
  param_1[0x8c] = 0;
  param_1[0x8d] = 0;
  uVar9 = *puVar3;
  local_8c = *(int *)(puVar3 + 1);
  param_1[4] = iVar1;
  param_1[0x90] = -1;
  *(undefined1 *)(param_1 + 0x91) = 0;
  local_88 = *puVar4;
  local_80 = *(int *)(puVar4 + 1);
  local_98 = 0;
  local_a0 = 0;
  *(undefined8 *)(param_1 + 0x77) = uVar9;
  param_1[0x79] = local_8c;
  local_94 = (undefined4)uVar9;
  uStack_90 = (undefined4)((ulong)uVar9 >> 0x20);
  *(undefined8 *)(param_1 + 0x7a) = local_88;
  param_1[0x7c] = local_80;
  param_1[0x8a] = 0x3f800000;
  param_1[0x8b] = 0;
  param_1[0x88] = 0;
  param_1[0x89] = 0;
  FUN_71019f324c(&local_a0,param_2);
  uVar7 = param_1[1];
  if (-1 < (int)uVar7) {
    lVar8 = *(long *)((uint *)*puVar5 + 2);
    if (*(uint *)*puVar5 <= uVar7) {
      uVar7 = 0;
    }
    if (((lVar8 != 0) && (lVar8 = lVar8 + (ulong)uVar7 * 0x10, *(int *)(lVar8 + 4) == *param_1)) &&
       (puVar5 = *(undefined8 **)(lVar8 + 8), puVar5 != (undefined8 *)0x0)) goto LAB_71019fcf40;
  }
  puVar5 = FUN_7100baff84();
LAB_71019fcf40:
  iVar1 = *(int *)((long)puVar5 + 0x84);
  if ((iVar1 == 0) || (plVar6 = (long *)((long)iVar1 + (long)puVar5 + 0x84), plVar6 == (long *)0x0))
  {
    plVar6 = FUN_7100bbfd30();
  }
  if ((int)plVar6[0x29] != -1) {
    param_1[0x90] = (int)plVar6[0x29];
    *(undefined8 *)(param_1 + 0x88) = local_50;
    *(undefined8 *)(param_1 + 0x8a) = uStack_48;
    *(undefined8 *)(param_1 + 0x8c) = local_40;
    *(undefined8 *)(param_1 + 0x8e) = uStack_38;
    *(undefined8 *)(param_1 + 0x80) = local_70;
    *(undefined8 *)(param_1 + 0x82) = uStack_68;
    *(undefined8 *)(param_1 + 0x84) = local_60;
    *(undefined8 *)(param_1 + 0x86) = uStack_58;
    *(ulong *)(param_1 + 0x78) = CONCAT44(local_8c,uStack_90);
    *(undefined8 *)(param_1 + 0x7a) = local_88;
    *(ulong *)(param_1 + 0x7c) = CONCAT44(uStack_7c,local_80);
    *(undefined8 *)(param_1 + 0x7e) = uStack_78;
    *(undefined8 *)(param_1 + 0x74) = local_a0;
    *(ulong *)(param_1 + 0x76) = CONCAT44(local_94,local_98);
    *(undefined1 *)(param_1 + 0x91) = 1;
  }
  return;
}



void FUN_71019fcfd4(undefined8 *param_1,int *param_2)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined8 *puVar4;
  long *plVar5;
  uint uVar6;
  long lVar7;
  undefined8 uVar8;
  undefined8 local_a0;
  undefined4 local_98;
  undefined4 local_94;
  undefined4 uStack_90;
  undefined4 local_8c;
  undefined8 local_88;
  undefined4 local_80;
  undefined4 uStack_7c;
  undefined8 uStack_78;
  undefined8 local_70;
  undefined8 uStack_68;
  undefined8 local_60;
  undefined8 uStack_58;
  undefined8 local_50;
  undefined8 uStack_48;
  undefined8 local_40;
  undefined8 uStack_38;
  
  uVar6 = param_2[1];
  if ((int)uVar6 < 0) {
    return;
  }
  lVar7 = *(long *)(DAT_71040e7d48 + 2);
  if (lVar7 == 0) {
    return;
  }
  if (*DAT_71040e7d48 <= uVar6) {
    uVar6 = 0;
  }
  if (*(int *)(lVar7 + (ulong)uVar6 * 0x10 + 4) != *param_2) {
    return;
  }
  puVar4 = *(undefined8 **)(lVar7 + (ulong)uVar6 * 0x10 + 8);
  if (puVar4 == (undefined8 *)0x0) {
    puVar4 = FUN_7100baff84();
  }
  if (*(int *)((long)puVar4 + 0x84) == 0 ||
      (long)*(int *)((long)puVar4 + 0x84) == -0x84 - (long)puVar4) {
    return;
  }
  uVar8 = *(undefined8 *)param_2;
  *(undefined8 *)((long)param_1 + 0x2c) = 0;
  *(undefined8 *)((long)param_1 + 0xbc) = 0;
  param_1[0x3a] = 0;
  *(undefined4 *)(param_1 + 0x3b) = 0;
  puVar4 = DAT_7103a5ba00;
  *(undefined4 *)(param_1 + 2) = 5;
  *param_1 = uVar8;
  uVar3 = DAT_71040104c4;
  uVar2 = DAT_71040104c0;
  *(undefined8 *)((long)param_1 + 0x14c) = 0;
  uVar8 = *puVar4;
  local_8c = *(undefined4 *)(puVar4 + 1);
  param_1[0x47] = 0;
  param_1[0x46] = 0;
  *(undefined1 *)((long)param_1 + 0x244) = 0;
  local_98 = 0;
  *(undefined4 *)(param_1 + 1) = uVar2;
  *(undefined4 *)((long)param_1 + 0xc) = uVar3;
  *(undefined8 *)((long)param_1 + 0x1dc) = uVar8;
  *(undefined4 *)((long)param_1 + 0x1e4) = local_8c;
  local_a0 = 0;
  local_94 = (undefined4)uVar8;
  uStack_90 = (undefined4)((ulong)uVar8 >> 0x20);
  param_1[0x3d] = 0;
  *(undefined4 *)(param_1 + 0x3e) = 0x3f800000;
  local_88 = 0;
  local_80 = 0x3f800000;
  param_1[0x41] = 0;
  param_1[0x40] = 0x3f800000;
  param_1[0x43] = 0;
  param_1[0x42] = 0x3f80000000000000;
  *(undefined4 *)(param_1 + 0x48) = 0xffffffff;
  param_1[0x45] = 0x3f800000;
  param_1[0x44] = 0;
  FUN_71019f324c(&local_a0,param_2);
  uVar6 = param_2[1];
  if (-1 < (int)uVar6) {
    if (*DAT_71040e7d48 <= uVar6) {
      uVar6 = 0;
    }
    if (((*(long *)(DAT_71040e7d48 + 2) != 0) &&
        (lVar7 = *(long *)(DAT_71040e7d48 + 2) + (ulong)uVar6 * 0x10,
        *(int *)(lVar7 + 4) == *param_2)) &&
       (puVar4 = *(undefined8 **)(lVar7 + 8), puVar4 != (undefined8 *)0x0)) goto LAB_71019fd164;
  }
  puVar4 = FUN_7100baff84();
LAB_71019fd164:
  iVar1 = *(int *)((long)puVar4 + 0x84);
  if ((iVar1 == 0) || (plVar5 = (long *)((long)iVar1 + (long)puVar4 + 0x84), plVar5 == (long *)0x0))
  {
    plVar5 = FUN_7100bbfd30();
  }
  if ((int)plVar5[0x29] != -1) {
    *(int *)(param_1 + 0x48) = (int)plVar5[0x29];
    param_1[0x44] = local_50;
    param_1[0x45] = uStack_48;
    param_1[0x46] = local_40;
    param_1[0x47] = uStack_38;
    param_1[0x40] = local_70;
    param_1[0x41] = uStack_68;
    param_1[0x42] = local_60;
    param_1[0x43] = uStack_58;
    param_1[0x3c] = CONCAT44(local_8c,uStack_90);
    param_1[0x3d] = local_88;
    param_1[0x3e] = CONCAT44(uStack_7c,local_80);
    param_1[0x3f] = uStack_78;
    param_1[0x3a] = local_a0;
    param_1[0x3b] = CONCAT44(local_94,local_98);
    *(undefined1 *)((long)param_1 + 0x244) = 1;
  }
  return;
}



void FUN_71019fd1e8(undefined4 *param_1,int *param_2)

{
  int iVar1;
  undefined8 uVar2;
  undefined4 *puVar3;
  long lVar4;
  undefined8 *puVar5;
  undefined1 auVar6 [16];
  undefined4 uVar7;
  uint uVar8;
  undefined4 uVar9;
  
  uVar8 = param_2[1];
  if ((-1 < (int)uVar8) && (lVar4 = *(long *)(DAT_71040e7d48 + 2), lVar4 != 0)) {
    if (*DAT_71040e7d48 <= uVar8) {
      uVar8 = 0;
    }
    if (*(int *)(lVar4 + (ulong)uVar8 * 0x10 + 4) == *param_2) {
      puVar5 = *(undefined8 **)(lVar4 + (ulong)uVar8 * 0x10 + 8);
      if (puVar5 == (undefined8 *)0x0) {
        puVar5 = FUN_7100baff84();
      }
      iVar1 = *(int *)((long)puVar5 + 0x84);
      lVar4 = (long)iVar1 + (long)puVar5 + 0x84;
      if (iVar1 != 0 && lVar4 != 0) {
        *(undefined8 *)(param_1 + 0xb) = 0;
        uVar7 = *(undefined4 *)(DAT_7103a5ba00 + 1);
        *(undefined8 *)(param_1 + 0x77) = *DAT_7103a5ba00;
        puVar3 = DAT_7103a59b30;
        *(undefined8 *)(param_1 + 0x2f) = 0;
        *(undefined8 *)(param_1 + 0x74) = 0;
        *(undefined8 *)(param_1 + 0x53) = 0;
        param_1[0x79] = uVar7;
        param_1[0x76] = 0;
        *(undefined8 *)(param_1 + 0x8e) = 0;
        *(undefined8 *)(param_1 + 0x8c) = 0;
        *(undefined1 *)(param_1 + 0x91) = 0;
        param_1[0x7c] = 0x3f800000;
        *(undefined8 *)(param_1 + 0x7a) = 0;
        uVar7 = *puVar3;
        *param_1 = uVar7;
        uVar9 = puVar3[1];
        param_1[1] = uVar9;
        param_1[2] = uVar7;
        param_1[3] = uVar9;
        param_1[4] = 7;
        param_1[0x90] = 0xffffffff;
        *(undefined8 *)(param_1 + 0x82) = 0;
        *(undefined8 *)(param_1 + 0x80) = 0x3f800000;
        *(undefined8 *)(param_1 + 0x86) = 0;
        *(undefined8 *)(param_1 + 0x84) = 0x3f80000000000000;
        *(undefined8 *)(param_1 + 0x8a) = 0x3f800000;
        *(undefined8 *)(param_1 + 0x88) = 0;
        if (*(int *)(lVar4 + 0x148) != -1) {
          uVar7 = *(undefined4 *)(lVar4 + 0x11c);
          uVar8 = *(uint *)(lVar4 + 0x124);
          uVar9 = *(undefined4 *)(lVar4 + 0x120);
          uVar2 = *(undefined8 *)(lVar4 + 0x11c);
          param_1[0x90] = *(int *)(lVar4 + 0x148);
          *(undefined8 *)(param_1 + 0x82) = 0;
          *(undefined8 *)(param_1 + 0x80) = 0x3f800000;
          *(undefined8 *)(param_1 + 0x86) = 0;
          *(undefined8 *)(param_1 + 0x84) = 0x3f80000000000000;
          auVar6 = NEON_fmov(0x3f800000,4);
          param_1[0x77] = 0x3f800000;
          param_1[0x7c] = 0x3f800000;
          *(undefined8 *)(param_1 + 0x78) = 0;
          *(undefined8 *)(param_1 + 0x7a) = 0;
          param_1[0x74] = uVar7;
          param_1[0x75] = uVar9;
          param_1[0x76] = uVar8;
          *(undefined1 *)(param_1 + 0x91) = 1;
          param_1[0x88] = 0;
          param_1[0x89] = 0;
          param_1[0x8a] = auVar6._8_4_;
          param_1[0x8b] = 0;
          *(ulong *)(param_1 + 0x8e) = (ulong)uVar8;
          *(undefined8 *)(param_1 + 0x8c) = uVar2;
        }
      }
    }
  }
  return;
}



void FUN_71019fd390(ulong *param_1,ulong *param_2)

{
  int iVar1;
  uint *puVar2;
  undefined8 *puVar3;
  long lVar4;
  long *plVar5;
  long lVar6;
  ulong uVar7;
  ulong *puVar8;
  ulong uVar9;
  ulong uVar10;
  long lVar11;
  float fVar12;
  float fVar13;
  float fVar14;
  float fVar15;
  float fVar16;
  float fVar17;
  float fVar18;
  float fVar19;
  undefined4 uVar20;
  float fVar21;
  float fVar22;
  undefined4 uVar23;
  uint uVar24;
  
  uVar24 = *(uint *)((long)param_2 + 4);
  if ((int)uVar24 < 0) {
    return;
  }
  lVar4 = *(long *)(DAT_71040e7d48 + 2);
  if (lVar4 == 0) {
    return;
  }
  if (*DAT_71040e7d48 <= uVar24) {
    uVar24 = 0;
  }
  if (*(int *)(lVar4 + (ulong)uVar24 * 0x10 + 4) != (int)*param_2) {
    return;
  }
  puVar3 = *(undefined8 **)(lVar4 + (ulong)uVar24 * 0x10 + 8);
  if (puVar3 == (undefined8 *)0x0) {
    puVar3 = FUN_7100baff84();
  }
  iVar1 = *(int *)((long)puVar3 + 0x84);
  lVar4 = (long)iVar1 + (long)puVar3 + 0x84;
  if (iVar1 == 0 || lVar4 == 0) {
    return;
  }
  uVar24 = *(uint *)((long)param_2 + 4);
  if ((int)uVar24 < 0) {
LAB_71019fd454:
    puVar3 = FUN_7100baff84();
  }
  else {
    lVar6 = *(long *)(DAT_71040e7d48 + 2);
    if (*DAT_71040e7d48 <= uVar24) {
      uVar24 = 0;
      if (lVar6 != 0) goto LAB_71019fd428;
      goto LAB_71019fd454;
    }
    if (lVar6 == 0) goto LAB_71019fd454;
LAB_71019fd428:
    lVar6 = lVar6 + (ulong)uVar24 * 0x10;
    if ((*(int *)(lVar6 + 4) != (int)*param_2) ||
       (puVar3 = *(undefined8 **)(lVar6 + 8), puVar3 == (undefined8 *)0x0)) goto LAB_71019fd454;
  }
  puVar2 = DAT_71040e7d48;
  if (*(int *)(puVar3 + 0x30) == 0) {
    return;
  }
  lVar6 = (long)puVar3 + (long)*(int *)(puVar3 + 0x30) + 0x180;
  if (lVar6 == 0) {
    return;
  }
  if (*(int *)(lVar6 + 0x30) == 0) {
    puVar8 = (ulong *)&DAT_71040104c0;
  }
  else {
    plVar5 = *(long **)(lVar6 + 0x38);
    lVar6 = (long)*(int *)(lVar6 + 0x30) << 3;
    do {
      lVar11 = *plVar5;
      if (*(int *)(lVar11 + 4) == -0x5bba2d9a) {
        puVar8 = (ulong *)(lVar11 + 0x20);
        uVar24 = *(uint *)(lVar11 + 0x24);
        if ((int)uVar24 < 0) {
          return;
        }
        goto LAB_71019fd4d0;
      }
      plVar5 = plVar5 + 1;
      lVar6 = lVar6 + -8;
      puVar8 = DAT_7103a59b30;
    } while (lVar6 != 0);
  }
  uVar24 = *(uint *)((long)puVar8 + 4);
  if ((int)uVar24 < 0) {
    return;
  }
LAB_71019fd4d0:
  if (*(long *)(DAT_71040e7d48 + 2) == 0) {
    return;
  }
  if (*DAT_71040e7d48 <= uVar24) {
    uVar24 = 0;
  }
  if (*(int *)(*(long *)(DAT_71040e7d48 + 2) + (ulong)uVar24 * 0x10 + 4) != (int)*puVar8) {
    return;
  }
  uVar7 = *param_2;
  *param_1 = uVar7;
  uVar9 = *puVar8;
  *(undefined8 *)((long)param_1 + 0x2c) = 0;
  *(undefined8 *)((long)param_1 + 0xbc) = 0;
  param_1[0x3a] = 0;
  *(undefined4 *)(param_1 + 0x3b) = 0;
  param_1[1] = uVar9;
  *(undefined4 *)(param_1 + 2) = 4;
  *(undefined8 *)((long)param_1 + 0x14c) = 0;
  puVar3 = DAT_7103a5ba00;
  *(undefined8 *)((long)param_1 + 0x1dc) = *DAT_7103a5ba00;
  *(undefined4 *)((long)param_1 + 0x1e4) = *(undefined4 *)(puVar3 + 1);
  param_1[0x47] = 0;
  param_1[0x46] = 0;
  *(undefined1 *)((long)param_1 + 0x244) = 0;
  *(undefined4 *)(param_1 + 0x3e) = 0x3f800000;
  param_1[0x3d] = 0;
  param_1[0x41] = 0;
  param_1[0x40] = 0x3f800000;
  param_1[0x43] = 0;
  param_1[0x42] = 0x3f80000000000000;
  *(undefined4 *)(param_1 + 0x48) = 0xffffffff;
  param_1[0x45] = 0x3f800000;
  param_1[0x44] = 0;
  fVar13 = *(float *)(lVar4 + 0x134);
  fVar15 = *(float *)(lVar4 + 0x138);
  fVar17 = *(float *)(lVar4 + 0x13c);
  fVar12 = SQRT(fVar15 * fVar15 + fVar13 * fVar13 + fVar17 * fVar17);
  if (fVar12 <= 9.094947e-14) {
LAB_71019fd654:
    fVar15 = 0.0;
    fVar17 = 1.0;
    fVar13 = 0.0;
  }
  else {
    fVar21 = 1.0 / fVar12;
    fVar14 = fVar13 * -3.1298223e-20;
    fVar16 = fVar15 * -3.1298223e-20;
    fVar18 = fVar17 * -3.1298223e-20;
    fVar22 = SQRT(fVar16 * fVar16 + fVar14 * fVar14 + fVar18 * fVar18);
    fVar19 = 1.0 / fVar22;
    fVar17 = fVar21 * -fVar17;
    fVar15 = fVar21 * -fVar15;
    fVar13 = fVar21 * -fVar13;
    if (fVar12 == INFINITY) {
      fVar12 = fVar22 * 3.1950695e+19;
      fVar17 = fVar18 * fVar19;
      fVar15 = fVar16 * fVar19;
      fVar13 = fVar14 * fVar19;
    }
    if (fVar12 <= 0.0) goto LAB_71019fd654;
  }
  uVar20 = *(undefined4 *)(lVar4 + 0x11c);
  uVar23 = *(undefined4 *)(lVar4 + 0x120);
  uVar9 = *(ulong *)(lVar4 + 0x11c);
  uVar24 = *(uint *)(lVar4 + 0x124);
  if (-1 < (long)uVar7) {
    uVar10 = uVar7 >> 0x20;
    lVar4 = *(long *)(puVar2 + 2);
    if (*puVar2 <= (uint)(uVar7 >> 0x20)) {
      uVar10 = 0;
    }
    if (((lVar4 != 0) && (lVar4 = lVar4 + uVar10 * 0x10, *(int *)(lVar4 + 4) == (int)uVar7)) &&
       (puVar3 = *(undefined8 **)(lVar4 + 8), puVar3 != (undefined8 *)0x0)) goto LAB_71019fd6c0;
  }
  puVar3 = FUN_7100baff84();
LAB_71019fd6c0:
  iVar1 = *(int *)((long)puVar3 + 0x84);
  if ((iVar1 == 0) || (plVar5 = (long *)((long)iVar1 + (long)puVar3 + 0x84), plVar5 == (long *)0x0))
  {
    plVar5 = FUN_7100bbfd30();
  }
  if ((int)plVar5[0x29] != -1) {
    *(int *)(param_1 + 0x48) = (int)plVar5[0x29];
    *(undefined4 *)(param_1 + 0x3a) = uVar20;
    fVar16 = fVar17 * -0.0 + fVar13 * 0.0;
    fVar14 = fVar15 * 0.0 - fVar13;
    *(undefined4 *)((long)param_1 + 0x1d4) = uVar23;
    *(uint *)(param_1 + 0x3b) = uVar24;
    *(float *)(param_1 + 0x3d) = fVar13;
    *(float *)((long)param_1 + 0x1ec) = fVar15;
    *(float *)(param_1 + 0x3e) = fVar17;
    *(undefined1 *)((long)param_1 + 0x244) = 1;
    fVar12 = fVar17 + fVar15 * -0.0;
    *(float *)(param_1 + 0x3c) = fVar16;
    *(float *)((long)param_1 + 0x1e4) = fVar14;
    *(float *)((long)param_1 + 0x1dc) = fVar12;
    *(float *)(param_1 + 0x44) = fVar13;
    *(float *)((long)param_1 + 0x224) = fVar15;
    *(float *)(param_1 + 0x45) = fVar17;
    *(undefined4 *)((long)param_1 + 0x22c) = 0;
    param_1[0x47] = (ulong)uVar24;
    param_1[0x46] = uVar9;
    *(float *)(param_1 + 0x40) = fVar12;
    *(float *)((long)param_1 + 0x204) = fVar16;
    *(float *)(param_1 + 0x41) = fVar14;
    *(undefined4 *)((long)param_1 + 0x20c) = 0;
    param_1[0x43] = 0;
    param_1[0x42] = 0x3f80000000000000;
  }
  return;
}



void FUN_71019fd7d0(long param_1,int param_2,int param_3)

{
  int *piVar1;
  long lVar2;
  char cVar3;
  bool bVar4;
  int iVar5;
  long *plVar6;
  byte *pbVar7;
  int iVar8;
  long lVar9;
  long lVar10;
  undefined8 *puVar11;
  long lVar12;
  long *plVar13;
  uint uVar14;
  
  *(undefined4 *)(param_1 + 0x10) = 5;
  lVar12 = *DAT_7103a5ba40;
  if (lVar12 != 0) {
    if (param_3 == 1) {
      lVar12 = *(long *)(lVar12 + 8);
      if (lVar12 == 0) {
        lVar9 = 0;
      }
      else {
        piVar1 = (int *)(lVar12 + 0x164);
        do {
          cVar3 = '\x01';
          bVar4 = (bool)ExclusiveMonitorPass(piVar1,0x10);
          if (bVar4) {
            *piVar1 = *piVar1 + 1;
            cVar3 = ExclusiveMonitorsStatus();
          }
        } while (cVar3 != '\0');
        lVar9 = *(long *)(lVar12 + 0x150);
      }
      pbVar7 = DAT_7103a5ba10;
      plVar6 = DAT_7103a5ba08;
      lVar2 = DAT_7103a59c60 + 0x10;
      do {
        lVar10 = lVar9;
        if (((((*(byte *)(lVar10 + 0x116) & 1) != 0) || (*(long *)(lVar10 + 0x10) == 0)) ||
            (plVar13 = *(long **)(lVar10 + 0x18), plVar13 == (long *)0x0)) ||
           ((*(int *)((long)plVar13 + 0xc) != *(int *)(lVar10 + 0x20) ||
            (puVar11 = (undefined8 *)*plVar13, puVar11 == (undefined8 *)0x0)))) break;
        if (((*pbVar7 & 1) == 0) && (iVar8 = thunk_EXT_FUN_02e95df0(pbVar7), iVar8 != 0)) {
          *plVar6 = lVar2;
          thunk_EXT_FUN_02e95df0(pbVar7);
        }
        lVar9 = (**(code **)*puVar11)(puVar11,plVar6);
      } while (lVar9 != 0);
      plVar6 = DAT_7103a59d28;
      uVar14 = *(uint *)(lVar10 + 0xdc);
      if (lVar12 != 0) {
        piVar1 = (int *)(lVar12 + 0x164);
        do {
          while( true ) {
            iVar8 = *piVar1;
            iVar5 = iVar8 + -1;
            if (iVar5 == 0) break;
            while (iVar8 == *piVar1) {
              cVar3 = '\x01';
              bVar4 = (bool)ExclusiveMonitorPass(piVar1,0x10);
              if (bVar4) {
                *piVar1 = iVar5;
                cVar3 = ExclusiveMonitorsStatus();
              }
              if (cVar3 == '\0') goto LAB_71019fda84;
            }
          }
          FUN_71028f1c50(*plVar6,lVar12);
          while (*piVar1 == 1) {
            cVar3 = '\x01';
            bVar4 = (bool)ExclusiveMonitorPass(piVar1,0x10);
            if (bVar4) {
              *piVar1 = 0;
              cVar3 = ExclusiveMonitorsStatus();
            }
            if (cVar3 == '\0') goto LAB_71019fda84;
          }
        } while( true );
      }
    }
    else {
      if (param_3 != 0) {
        return;
      }
      lVar12 = *(long *)(lVar12 + 8);
      if (lVar12 == 0) {
        lVar9 = 0;
      }
      else {
        piVar1 = (int *)(lVar12 + 0x164);
        do {
          cVar3 = '\x01';
          bVar4 = (bool)ExclusiveMonitorPass(piVar1,0x10);
          if (bVar4) {
            *piVar1 = *piVar1 + 1;
            cVar3 = ExclusiveMonitorsStatus();
          }
        } while (cVar3 != '\0');
        lVar9 = *(long *)(lVar12 + 0x150);
      }
      pbVar7 = DAT_7103a5ba10;
      plVar6 = DAT_7103a5ba08;
      lVar2 = DAT_7103a59c60 + 0x10;
      do {
        lVar10 = lVar9;
        if ((((*(byte *)(lVar10 + 0x117) & 1) != 0) || (*(long *)(lVar10 + 0x10) == 0)) ||
           ((plVar13 = *(long **)(lVar10 + 0x18), plVar13 == (long *)0x0 ||
            ((*(int *)((long)plVar13 + 0xc) != *(int *)(lVar10 + 0x20) ||
             (puVar11 = (undefined8 *)*plVar13, puVar11 == (undefined8 *)0x0)))))) break;
        if (((*pbVar7 & 1) == 0) && (iVar8 = thunk_EXT_FUN_02e95df0(pbVar7), iVar8 != 0)) {
          *plVar6 = lVar2;
          thunk_EXT_FUN_02e95df0(pbVar7);
        }
        lVar9 = (**(code **)*puVar11)(puVar11,plVar6);
      } while (lVar9 != 0);
      plVar6 = DAT_7103a59d28;
      uVar14 = *(uint *)(lVar10 + 0xd8);
      if (lVar12 != 0) {
        piVar1 = (int *)(lVar12 + 0x164);
        do {
          while( true ) {
            iVar8 = *piVar1;
            iVar5 = iVar8 + -1;
            if (iVar5 == 0) break;
            while (iVar8 == *piVar1) {
              cVar3 = '\x01';
              bVar4 = (bool)ExclusiveMonitorPass(piVar1,0x10);
              if (bVar4) {
                *piVar1 = iVar5;
                cVar3 = ExclusiveMonitorsStatus();
              }
              if (cVar3 == '\0') goto LAB_71019fda84;
            }
          }
          FUN_71028f1c50(*plVar6,lVar12);
          while (*piVar1 == 1) {
            cVar3 = '\x01';
            bVar4 = (bool)ExclusiveMonitorPass(piVar1,0x10);
            if (bVar4) {
              *piVar1 = 0;
              cVar3 = ExclusiveMonitorsStatus();
            }
            if (cVar3 == '\0') goto LAB_71019fda84;
          }
        } while( true );
      }
    }
LAB_71019fda84:
    if (param_2 != -1) {
      *(uint *)(param_1 + 0x1d4) = uVar14;
      *(int *)(param_1 + 0x240) = param_2;
      *(undefined4 *)(param_1 + 0x1d0) = 0;
      *(undefined8 *)(param_1 + 0x1e0) = 0;
      *(undefined8 *)(param_1 + 0x1e8) = 0;
      *(undefined8 *)(param_1 + 0x208) = 0;
      *(undefined8 *)(param_1 + 0x200) = 0x3f800000;
      *(undefined8 *)(param_1 + 0x218) = 0;
      *(undefined8 *)(param_1 + 0x210) = 0x3f80000000000000;
      *(undefined8 *)(param_1 + 0x1d8) = 0x3f80000000000000;
      *(undefined4 *)(param_1 + 0x1f0) = 0x3f800000;
      *(undefined1 *)(param_1 + 0x244) = 1;
      *(undefined4 *)(param_1 + 0x220) = 0;
      *(undefined4 *)(param_1 + 0x224) = 0;
      *(undefined4 *)(param_1 + 0x228) = 0x3f800000;
      *(undefined4 *)(param_1 + 0x22c) = 0;
      *(undefined8 *)(param_1 + 0x238) = 0;
      *(ulong *)(param_1 + 0x230) = (ulong)uVar14 << 0x20;
    }
  }
  return;
}



void FUN_71019fdb0c(undefined8 *param_1,int *param_2)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined8 *puVar4;
  long *plVar5;
  uint uVar6;
  long lVar7;
  undefined8 uVar8;
  undefined8 local_a0;
  undefined4 local_98;
  undefined4 local_94;
  undefined4 uStack_90;
  undefined4 local_8c;
  undefined8 local_88;
  undefined4 local_80;
  undefined4 uStack_7c;
  undefined8 uStack_78;
  undefined8 local_70;
  undefined8 uStack_68;
  undefined8 local_60;
  undefined8 uStack_58;
  undefined8 local_50;
  undefined8 uStack_48;
  undefined8 local_40;
  undefined8 uStack_38;
  
  uVar6 = param_2[1];
  if ((int)uVar6 < 0) {
    return;
  }
  lVar7 = *(long *)(DAT_71040e7d48 + 2);
  if (lVar7 == 0) {
    return;
  }
  if (*DAT_71040e7d48 <= uVar6) {
    uVar6 = 0;
  }
  if (*(int *)(lVar7 + (ulong)uVar6 * 0x10 + 4) != *param_2) {
    return;
  }
  puVar4 = *(undefined8 **)(lVar7 + (ulong)uVar6 * 0x10 + 8);
  if (puVar4 == (undefined8 *)0x0) {
    puVar4 = FUN_7100baff84();
  }
  if (*(int *)((long)puVar4 + 0x84) == 0 ||
      (long)*(int *)((long)puVar4 + 0x84) == -0x84 - (long)puVar4) {
    return;
  }
  uVar8 = *(undefined8 *)param_2;
  *(undefined8 *)((long)param_1 + 0x2c) = 0;
  *(undefined8 *)((long)param_1 + 0xbc) = 0;
  param_1[0x3a] = 0;
  *(undefined4 *)(param_1 + 0x3b) = 0;
  puVar4 = DAT_7103a5ba00;
  *(undefined4 *)(param_1 + 2) = 5;
  *param_1 = uVar8;
  uVar3 = DAT_71040104c4;
  uVar2 = DAT_71040104c0;
  *(undefined8 *)((long)param_1 + 0x14c) = 0;
  uVar8 = *puVar4;
  local_8c = *(undefined4 *)(puVar4 + 1);
  param_1[0x47] = 0;
  param_1[0x46] = 0;
  *(undefined1 *)((long)param_1 + 0x244) = 0;
  local_98 = 0;
  *(undefined4 *)(param_1 + 1) = uVar2;
  *(undefined4 *)((long)param_1 + 0xc) = uVar3;
  *(undefined8 *)((long)param_1 + 0x1dc) = uVar8;
  *(undefined4 *)((long)param_1 + 0x1e4) = local_8c;
  local_a0 = 0;
  local_94 = (undefined4)uVar8;
  uStack_90 = (undefined4)((ulong)uVar8 >> 0x20);
  param_1[0x3d] = 0;
  *(undefined4 *)(param_1 + 0x3e) = 0x3f800000;
  local_88 = 0;
  local_80 = 0x3f800000;
  param_1[0x41] = 0;
  param_1[0x40] = 0x3f800000;
  param_1[0x43] = 0;
  param_1[0x42] = 0x3f80000000000000;
  *(undefined4 *)(param_1 + 0x48) = 0xffffffff;
  param_1[0x45] = 0x3f800000;
  param_1[0x44] = 0;
  FUN_71019f324c(&local_a0,param_2);
  uVar6 = param_2[1];
  if (-1 < (int)uVar6) {
    if (*DAT_71040e7d48 <= uVar6) {
      uVar6 = 0;
    }
    if (((*(long *)(DAT_71040e7d48 + 2) != 0) &&
        (lVar7 = *(long *)(DAT_71040e7d48 + 2) + (ulong)uVar6 * 0x10,
        *(int *)(lVar7 + 4) == *param_2)) &&
       (puVar4 = *(undefined8 **)(lVar7 + 8), puVar4 != (undefined8 *)0x0)) goto LAB_71019fdc9c;
  }
  puVar4 = FUN_7100baff84();
LAB_71019fdc9c:
  iVar1 = *(int *)((long)puVar4 + 0x84);
  if ((iVar1 == 0) || (plVar5 = (long *)((long)iVar1 + (long)puVar4 + 0x84), plVar5 == (long *)0x0))
  {
    plVar5 = FUN_7100bbfd30();
  }
  if ((int)plVar5[0x29] != -1) {
    *(int *)(param_1 + 0x48) = (int)plVar5[0x29];
    param_1[0x44] = local_50;
    param_1[0x45] = uStack_48;
    param_1[0x46] = local_40;
    param_1[0x47] = uStack_38;
    param_1[0x40] = local_70;
    param_1[0x41] = uStack_68;
    param_1[0x42] = local_60;
    param_1[0x43] = uStack_58;
    param_1[0x3c] = CONCAT44(local_8c,uStack_90);
    param_1[0x3d] = local_88;
    param_1[0x3e] = CONCAT44(uStack_7c,local_80);
    param_1[0x3f] = uStack_78;
    param_1[0x3a] = local_a0;
    param_1[0x3b] = CONCAT44(local_94,local_98);
    *(undefined1 *)((long)param_1 + 0x244) = 1;
  }
  return;
}



void FUN_71019fdd20(undefined4 *param_1)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 *puVar3;
  
  *(undefined1 *)(param_1 + 0x94) = 1;
  *(undefined8 *)(param_1 + 0xb) = 0;
  *(undefined8 *)(param_1 + 0x77) = 0x3f800000;
  puVar3 = DAT_7103a59b30;
  *(undefined8 *)(param_1 + 0x2f) = 0;
  *(undefined8 *)(param_1 + 0x53) = 0;
  param_1[0x79] = 0;
  *(undefined8 *)(param_1 + 0x74) = 0;
  param_1[0x76] = 0;
  *(undefined8 *)(param_1 + 0x8e) = 0;
  *(undefined8 *)(param_1 + 0x8c) = 0;
  *(undefined1 *)(param_1 + 0x91) = 0;
  param_1[0x7c] = 0x3f800000;
  uVar1 = *puVar3;
  *(undefined8 *)(param_1 + 0x82) = 0;
  *(undefined8 *)(param_1 + 0x80) = 0x3f800000;
  *(undefined8 *)(param_1 + 0x86) = 0;
  *(undefined8 *)(param_1 + 0x84) = 0x3f80000000000000;
  *(undefined8 *)(param_1 + 0x7a) = 0;
  *param_1 = uVar1;
  uVar2 = puVar3[1];
  param_1[1] = uVar2;
  param_1[2] = uVar1;
  param_1[3] = uVar2;
  param_1[4] = 0;
  param_1[0x90] = 0xffffffff;
  *(undefined8 *)(param_1 + 0x8a) = 0x3f800000;
  *(undefined8 *)(param_1 + 0x88) = 0;
  return;
}



uint FUN_71019fdee0(float *param_1,undefined8 *param_2,uint *param_3,uint *param_4,byte param_5)

{
  float *pfVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  int iVar7;
  long lVar8;
  undefined8 *puVar9;
  undefined8 local_2e0;
  undefined8 uStack_2d8;
  undefined4 local_2d0;
  uint local_2c8;
  undefined8 local_2c0;
  uint local_2b8;
  byte local_2b4;
  float local_2b0 [4];
  undefined1 auStack_2a0 [16];
  undefined1 *local_290;
  undefined4 local_288;
  undefined4 local_280;
  undefined1 auStack_27c [124];
  undefined1 *local_200;
  undefined4 local_1f8;
  undefined4 local_1f0;
  undefined1 auStack_1ec [124];
  undefined1 *local_170;
  undefined4 local_168;
  undefined4 local_160;
  undefined1 auStack_15c [124];
  undefined8 local_e0;
  undefined4 local_d8;
  undefined8 local_d4;
  undefined4 local_cc;
  undefined8 local_c8;
  ulong local_c0;
  undefined8 local_b8;
  undefined8 local_b0;
  undefined8 uStack_a8;
  undefined8 uStack_a0;
  undefined8 uStack_98;
  undefined8 local_90;
  undefined8 uStack_88;
  undefined4 local_70;
  undefined1 local_60;
  
  if (*param_4 < 5 && (1 << (ulong)(*param_4 & 0x1f) & 0x19U) != 0) {
    thunk_EXT_FUN_02e95df0(auStack_2a0,0,0x250);
    local_290 = auStack_27c;
    local_200 = auStack_1ec;
    local_b8 = 0;
    local_d4 = *DAT_7103a5ba00;
    local_168 = 5;
    local_288 = 5;
    local_1f8 = 5;
    local_cc = *(undefined4 *)(DAT_7103a5ba00 + 1);
    local_170 = auStack_15c;
    local_2b0[0] = -NAN;
    local_2b0[1] = -NAN;
    local_2b0[2] = -NAN;
    local_2b0[3] = -NAN;
    local_280 = 0;
    local_1f0 = 0;
    local_160 = 0;
    local_e0 = 0;
    local_d8 = 0;
    local_60 = 0;
    local_2c0 = 0;
    local_2b8 = 0;
    local_2b4 = 1;
    local_2c8 = 0;
    local_2d0 = 0;
    local_c8 = *DAT_7103a5a248;
    local_c0 = (ulong)*(uint *)(DAT_7103a5a248 + 1);
    uStack_a8 = 0;
    local_b0 = 0x3f800000;
    uStack_98 = 0;
    uStack_a0 = 0x3f80000000000000;
    local_70 = 0xffffffff;
    local_2e0 = *param_2;
    uVar6 = *param_3;
    uStack_2d8 = 0xffffffffffffffff;
    uStack_88 = 0x3f800000;
    local_90 = 0;
    if (uVar6 != 0) {
      puVar9 = *(undefined8 **)(*DAT_7103a59ec8 + 0xa8);
      if (((*DAT_7103a61c30 & 1) == 0) &&
         (iVar7 = thunk_EXT_FUN_02e95df0(DAT_7103a61c30), iVar7 != 0)) {
        *DAT_7103a61c28 = DAT_7103a59e80 + 0x10;
        thunk_EXT_FUN_02e95df0(DAT_7103a61c30);
      }
      lVar8 = (**(code **)*puVar9)(puVar9,DAT_7103a61c28);
      uVar2 = *(uint *)(lVar8 + 0x2c);
      if (uVar2 != 0) {
        uVar4 = 0;
        if (uVar2 != 0) {
          uVar4 = uVar6 / uVar2;
        }
        uVar4 = uVar6 - uVar4 * uVar2;
        uVar5 = uVar4;
        do {
          uVar3 = *(uint *)(*(long *)(lVar8 + 0x20) +
                           (-(ulong)(uVar5 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar5 << 4));
          if (uVar3 == uVar6) {
            local_2c0 = *(undefined8 *)(*(long *)(lVar8 + 0x20) + (long)(int)uVar5 * 0x10 + 8);
            goto LAB_71019fe0a0;
          }
          if (uVar3 == 0) break;
          uVar3 = 0;
          if ((int)(uVar5 + 1) < (int)uVar2) {
            uVar3 = uVar5 + 1;
          }
          uVar5 = uVar3;
        } while (uVar3 != uVar4);
      }
    }
    local_2c0 = 0;
LAB_71019fe0a0:
    local_2b8 = *param_4;
    pfVar1 = local_2b0;
    if (param_1 != (float *)0x0) {
      pfVar1 = param_1;
    }
    local_2c8 = uVar6;
    local_2b4 = param_5 & 1;
    uVar6 = FUN_71019fe130(pfVar1,(float *)&local_2e0);
  }
  else {
    uVar6 = 0;
  }
  return uVar6 & 1;
}



// WARNING: Removing unreachable block (ram,0x007101a00d80)
// WARNING: Removing unreachable block (ram,0x007101a00d8c)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// WARNING: Restarted to delay deadcode elimination for space: stack

uint FUN_71019fe130(float *param_1,float *param_2)

{
  long *plVar1;
  uint uVar2;
  int iVar3;
  undefined1 auVar4 [12];
  int *piVar5;
  bool bVar6;
  bool bVar7;
  byte bVar8;
  uint uVar9;
  int iVar10;
  int iVar11;
  ulong uVar12;
  undefined8 *puVar13;
  long *plVar14;
  int *piVar15;
  ulong uVar16;
  undefined8 *puVar17;
  long *plVar18;
  ulong *puVar19;
  int *piVar20;
  float *pfVar21;
  undefined4 uVar22;
  long lVar23;
  undefined8 uVar24;
  long lVar25;
  char *pcVar26;
  undefined8 uVar27;
  long lVar28;
  float *pfVar29;
  float *pfVar30;
  uint *puVar31;
  uint uVar32;
  long lVar33;
  uint uVar34;
  float fVar35;
  float fVar36;
  float fVar37;
  float fVar38;
  float fVar39;
  long *local_428;
  uint local_420;
  uint local_41c;
  uint local_418 [3];
  float local_40c;
  undefined8 local_408;
  undefined8 local_400;
  float *local_3f8;
  uint *puStack_3f0;
  float *local_3e8;
  uint *local_3e0;
  float *pfStack_3d8;
  undefined8 *local_3d0;
  uint *local_3c8;
  float local_308;
  int local_304;
  undefined8 local_300;
  byte local_2f8;
  byte bStack_2f7;
  byte bStack_2f6;
  undefined1 uStack_2f5;
  undefined4 uStack_2f4;
  undefined8 local_2f0;
  undefined8 local_2e8;
  undefined8 local_2e0;
  undefined8 **local_2d8;
  undefined8 *local_2d0;
  undefined8 local_2c8;
  undefined8 *local_2c0;
  undefined8 ***pppuStack_2b8;
  undefined8 **ppuStack_2b0;
  long *plStack_2a8;
  undefined1 *local_270;
  undefined4 local_268;
  undefined8 local_264;
  undefined1 auStack_25c [124];
  undefined1 *local_1e0;
  undefined4 local_1d8;
  undefined8 local_1d4;
  undefined1 auStack_1cc [124];
  undefined8 local_150;
  undefined4 local_148;
  undefined8 local_144;
  undefined4 local_13c;
  long local_138;
  ulong local_130;
  undefined8 local_128;
  undefined8 local_120;
  undefined8 uStack_118;
  undefined8 uStack_110;
  undefined8 uStack_108;
  undefined8 local_100;
  undefined8 uStack_f8;
  undefined8 local_f0;
  undefined8 local_e8;
  undefined4 local_e0;
  char local_dc;
  undefined1 local_c8 [16];
  undefined4 local_b4 [5];
  
  uVar9 = local_2f0._4_4_;
  if ((param_1 == (float *)0x0) || (lVar23 = *(long *)(param_2 + 8), lVar23 == 0))
  goto switchD_7101a00174_default;
  local_2f0._0_4_ = 0;
  local_2f0._4_4_ = local_2f0._4_4_ & 0xffffff00;
  local_300 = (long *)(DAT_7103a62d48 + 0x10);
  local_2f8 = 0;
  bStack_2f7 = 0;
  bStack_2f6 = 0;
  uStack_2f5 = 0;
  uStack_2f4 = 0;
  if ((*(char *)(lVar23 + 0xf4) == -0x3c) || (*(char *)(lVar23 + 0xf4) == -0x3f)) {
    uVar27 = *(undefined8 *)(lVar23 + 0xe8);
    local_2f8 = (byte)uVar27;
    bStack_2f7 = (byte)((ulong)uVar27 >> 8);
    bStack_2f6 = (byte)((ulong)uVar27 >> 0x10);
    uStack_2f5 = (undefined1)((ulong)uVar27 >> 0x18);
    uVar24 = *(undefined8 *)(lVar23 + 0xed);
    uStack_2f4._0_1_ = (undefined1)((ulong)uVar27 >> 0x20);
    uStack_2f4._1_3_ = (undefined3)uVar24;
    local_2f0._0_4_ = (uint)((ulong)uVar24 >> 0x18);
    local_2f0._5_3_ = SUB43(uVar9,1);
    local_2f0._4_1_ = (undefined1)((ulong)uVar24 >> 0x38);
  }
  local_308 = 0.0;
  local_400 = &local_308;
  local_408 = (float *)(DAT_7103a62d50 + 0x10);
  local_c8 = FUN_7102813520((undefined8 *)&local_2f8,"DemoStageCategory");
  uVar12 = FUN_71015527d0((long)&local_408,(undefined8 *)local_c8);
  plVar18 = DAT_7103a5a160;
  uVar9 = 0;
  if ((uVar12 & 1) == 0) goto switchD_71019fe33c_caseD_1;
  if (6 < (int)local_308 - 1U) goto switchD_7101a00174_default;
  pfVar29 = param_2 + 6;
  switch(local_308) {
  case 1.4013e-45:
    uVar12 = FUN_71015513c0((long)pfVar29);
    puVar17 = DAT_7103a59c40;
    if ((uint)uVar12 < 0x54) {
      pcVar26 = *(char **)(DAT_7103a5b098 + (uVar12 & 0xffffffff) * 8 + 0x600);
    }
    else {
      pcVar26 = "";
    }
    if (((*pcVar26 == 'I') && (pcVar26[1] == 's')) &&
       ((pcVar26[2] == 'l' && ((pcVar26[3] == 'a' && (pcVar26[4] == 'n')))))) {
      uVar9 = 0;
      if ((pcVar26[5] != 'd') || (param_2[10] == 5.60519e-45)) goto switchD_71019fe33c_caseD_1;
      fVar37 = param_2[1];
      if ((int)fVar37 < 0) break;
      lVar23 = *(long *)((float *)*DAT_7103a59c40 + 2);
      if (lVar23 == 0) break;
      if ((uint)*(float *)*DAT_7103a59c40 <= (uint)fVar37) {
        fVar37 = 0.0;
      }
      if (*(float *)(lVar23 + (ulong)(uint)fVar37 * 0x10 + 4) != *param_2) break;
      puVar13 = *(undefined8 **)(lVar23 + (ulong)(uint)fVar37 * 0x10 + 8);
      if (puVar13 == (undefined8 *)0x0) {
        puVar13 = FUN_7100baff84();
      }
      pfVar21 = DAT_7103a59b30;
      iVar11 = *(int *)((long)puVar13 + 0x84);
      uVar9 = 0;
      if ((iVar11 == 0) || (lVar23 = (long)iVar11 + (long)puVar13 + 0x84, lVar23 == 0))
      goto switchD_71019fe33c_caseD_1;
      if (*(int *)(lVar23 + 0x148) != 0) break;
      fVar37 = param_2[1];
      pfVar30 = DAT_7103a59b30 + 1;
      if (-1 < (int)fVar37) {
        lVar23 = *(long *)((float *)*puVar17 + 2);
        if (lVar23 != 0) {
          if ((uint)*(float *)*puVar17 <= (uint)fVar37) {
            fVar37 = 0.0;
          }
          if (*(float *)(lVar23 + (ulong)(uint)fVar37 * 0x10 + 4) == *param_2) {
            puVar13 = *(undefined8 **)(lVar23 + (ulong)(uint)fVar37 * 0x10 + 8);
            if (puVar13 == (undefined8 *)0x0) {
              puVar13 = FUN_7100baff84();
            }
            pfVar30 = pfVar21 + 1;
            if ((*(int *)(puVar13 + 0x45) != 0) &&
               (lVar23 = (long)puVar13 + (long)*(int *)(puVar13 + 0x45) + 0x228, lVar23 != 0)) {
              pfVar21 = (float *)(lVar23 + 0x28);
              pfVar30 = (float *)(lVar23 + 0x2c);
            }
          }
          else {
            pfVar30 = DAT_7103a59b30 + 1;
          }
        }
      }
      fVar37 = *pfVar30;
      if (-1 < (int)fVar37) {
        lVar23 = *(long *)((float *)*puVar17 + 2);
        if (lVar23 != 0) {
          if ((uint)*(float *)*puVar17 <= (uint)fVar37) {
            fVar37 = 0.0;
          }
          if (*(float *)(lVar23 + (ulong)(uint)fVar37 * 0x10 + 4) == *pfVar21) break;
        }
      }
      local_c8._0_8_ = *(undefined8 *)param_2;
      FUN_7101d0d2a0(&local_300,(int *)local_c8,0);
      local_408 = (float *)(DAT_7103a5a2a8 + 0x10);
      local_400 = (float *)CONCAT62(CONCAT51(local_400._3_5_,bStack_2f6),
                                    CONCAT11(bStack_2f7,local_2f8));
      if ((ulong)bStack_2f6 == 0xff) break;
      piVar15 = DAT_7103a5c420;
      if ((*DAT_7103a5a160 != 0) &&
         (lVar23 = *(long *)(*DAT_7103a5a160 + (ulong)bStack_2f6 * 8 + 8), lVar23 != 0)) {
        piVar15 = (int *)(lVar23 + 0x150);
      }
      uVar9 = piVar15[1];
      if ((int)uVar9 < 0) break;
      lVar23 = *(long *)((uint *)*puVar17 + 2);
      if (*(uint *)*puVar17 <= uVar9) {
        uVar9 = 0;
        if (lVar23 != 0) goto LAB_71019ff4bc;
        break;
      }
      if (lVar23 == 0) break;
LAB_71019ff4bc:
      lVar23 = lVar23 + (ulong)uVar9 * 0x10;
      if ((((*(int *)(lVar23 + 4) != *piVar15) || (lVar23 = *(long *)(lVar23 + 8), lVar23 == 0)) ||
          (*(byte *)(lVar23 + 0x24) <= local_2f8)) || (*(byte *)(lVar23 + 0x25) <= bStack_2f7))
      break;
      local_128 = 0;
      local_300 = (long *)((long)&local_2f0 + 4);
      local_2f8 = 5;
      bStack_2f7 = 0;
      bStack_2f6 = 0;
      uStack_2f5 = 0;
      local_270 = auStack_25c;
      local_268 = 5;
      local_1d8 = 5;
      local_1e0 = auStack_1cc;
      uStack_2f4 = 0;
      local_2f0._0_4_ = 0;
      local_264 = 0;
      local_1d4 = 0;
      local_150 = 0;
      local_148 = 0;
      local_144 = *DAT_7103a5ba00;
      local_13c = *(undefined4 *)(DAT_7103a5ba00 + 1);
      local_e8 = 0;
      local_f0 = 0;
      local_dc = '\0';
      local_138 = *DAT_7103a5a248;
      local_130 = (ulong)*(uint *)(DAT_7103a5a248 + 1);
      uStack_118 = 0;
      local_120 = 0x3f800000;
      uStack_108 = 0;
      uStack_110 = 0x3f80000000000000;
      local_e0 = 0xffffffff;
      uStack_f8 = 0x3f800000;
      local_100 = 0;
      uVar12 = FUN_71015513c0((long)pfVar29);
      local_418[0] = (int)uVar12;
      FUN_7101483c20((long *)local_c8);
      plVar18 = (long *)local_c8._0_8_;
      plVar14 = (long *)local_c8._0_8_;
      if ((long *)local_c8._0_8_ == (long *)0x0) {
        plVar14 = FUN_7100d1d130();
        plVar18 = FUN_7100d1d130();
      }
      fVar35 = *(float *)((long)plVar14 + 0x44) - *(float *)(plVar18 + 7);
      fVar38 = *(float *)((long)plVar14 + 0x4c) - *(float *)(plVar18 + 8);
      fVar37 = fVar38;
      if (fVar38 <= 0.0) {
        fVar37 = -fVar38;
      }
      fVar39 = fVar35;
      if (fVar35 <= 0.0) {
        fVar39 = -fVar35;
      }
      if (fVar39 <= fVar37) {
        local_308 = (float)((uint)(0.0 < fVar38) << 1);
        local_304 = 3;
        if (fVar35 <= 0.0) {
          local_304 = 1;
        }
      }
      else {
        local_308 = 4.2039e-45;
        if (fVar35 <= 0.0) {
          local_308 = 1.4013e-45;
        }
        local_304 = (uint)(0.0 < fVar38) << 1;
      }
      uVar9 = FUN_71019f6ed0(ZEXT416((uint)fVar35),ZEXT416((uint)fVar38),fVar39,&local_300,
                             (long)&local_408,local_418,(uint *)&local_308);
      if ((uVar9 & 1) == 0) goto switchD_71019fe33c_caseD_1;
      puVar31 = (uint *)local_c8;
      local_c8._0_8_ = 0xffffffffffffffff;
LAB_7101a006bc:
      FUN_71019fc62c((undefined8 *)param_1,(undefined8 *)puVar31,&local_300);
      goto switchD_71019fe33c_caseD_1;
    }
    break;
  case 2.8026e-45:
    uVar9 = 0;
    local_c8._0_8_ = -1;
    local_408 = (float *)0x0;
    local_400 = (float *)((ulong)local_400 & 0xffffffffffffff00);
    switch(param_2[10]) {
    case 0.0:
      uVar12 = FUN_71015513c0((long)pfVar29);
      puVar17 = DAT_7103a59c40;
      uVar9 = 0;
      switch(uVar12 & 0xffffffff) {
      case 0:
        bVar7 = FUN_7101cbb4a0((int *)param_2);
        if (!bVar7) break;
LAB_71019ff304:
        puVar19 = (ulong *)FUN_7101cba9d0((int *)param_2);
        goto LAB_7101a0002c;
      default:
        goto switchD_71019fe33c_caseD_1;
      case 0x19:
        bVar7 = FUN_7100ee8e40((int *)param_2);
        if (!bVar7) break;
        FUN_7101a01c20(&local_300,(int *)param_2);
        plVar18 = local_300;
        goto LAB_7101a00070;
      case 0x1a:
      case 0x1b:
        bVar7 = FUN_7101cbb5d0((int *)param_2);
        if (bVar7) {
          puVar19 = FUN_7101cbd7d0((int *)param_2);
          goto LAB_7101a0002c;
        }
        break;
      case 0x1c:
      case 0x1d:
      case 0x21:
        fVar37 = param_2[1];
        if (-1 < (int)fVar37) {
          lVar23 = *(long *)((float *)*DAT_7103a59c40 + 2);
          if (lVar23 != 0) {
            if ((uint)*(float *)*DAT_7103a59c40 <= (uint)fVar37) {
              fVar37 = 0.0;
            }
            if (*(float *)(lVar23 + (ulong)(uint)fVar37 * 0x10 + 4) == *param_2) {
              piVar15 = (int *)FUN_7101cba9d0((int *)param_2);
              uVar9 = piVar15[1];
              if (-1 < (int)uVar9) {
                lVar23 = *(long *)((uint *)*puVar17 + 2);
                if (lVar23 != 0) {
                  if (*(uint *)*puVar17 <= uVar9) {
                    uVar9 = 0;
                  }
                  if (((*(int *)(lVar23 + (ulong)uVar9 * 0x10 + 4) == *piVar15) &&
                      (bVar8 = FUN_7101cba6f0(piVar15), (bVar8 & 1) != 0)) &&
                     (iVar11 = FUN_7101cbae80((int *)param_2), iVar11 == 0)) goto LAB_71019ff304;
                }
              }
            }
          }
        }
        break;
      case 0x1e:
        bVar7 = FUN_7101a01ec0((int *)param_2);
        if (!bVar7) break;
        puVar19 = (ulong *)FUN_7101cba9d0((int *)param_2);
        uVar12 = *puVar19;
        local_308 = -50936236.0;
LAB_71019ff374:
        local_c8._0_8_ = uVar12;
        FUN_7101a01fc0((int *)&local_300,(int *)param_2,(int *)&local_308);
        goto LAB_7101a000d4;
      case 0x1f:
        bVar7 = FUN_7101a01ec0((int *)param_2);
        if (bVar7) {
          puVar19 = (ulong *)FUN_7101cba9d0((int *)param_2);
          uVar12 = *puVar19;
          local_308 = 1.924544e-05;
          goto LAB_71019ff374;
        }
        break;
      case 0x20:
        bVar7 = FUN_7101a01ec0((int *)param_2);
        if (bVar7) {
          puVar19 = (ulong *)FUN_7101cba9d0((int *)param_2);
          uVar12 = *puVar19;
          local_308 = 5.3192497e-33;
          goto LAB_71019ff374;
        }
      }
      break;
    default:
      goto switchD_71019fe33c_caseD_1;
    case 2.8026e-45:
      goto switchD_71019fe33c_caseD_2;
    case 4.2039e-45:
    case 5.60519e-45:
      goto switchD_71019fe33c_caseD_3;
    case 7.00649e-45:
      uVar12 = FUN_71015513c0((long)pfVar29);
      if (5 < (int)uVar12 - 0x1cU) break;
      puVar13 = (undefined8 *)FUN_7101cbaad0();
      puVar17 = DAT_7103a59c40;
      plVar18 = (long *)*puVar13;
      local_c8._0_8_ = plVar18;
      if ((long)plVar18 < 0) break;
      lVar23 = *(long *)((uint *)*DAT_7103a59c40 + 2);
      if (lVar23 == 0) break;
      uVar16 = (ulong)plVar18 >> 0x20;
      uVar9 = (uint)((ulong)plVar18 >> 0x20);
      uVar12 = uVar16;
      if (*(uint *)*DAT_7103a59c40 <= uVar9) {
        uVar12 = 0;
      }
      iVar11 = (int)plVar18;
      if (*(int *)(lVar23 + uVar12 * 0x10 + 4) != iVar11) break;
      uVar12 = FUN_71015513c0((long)pfVar29);
      iVar10 = (int)uVar12;
      if (iVar10 == 0x1e) {
        lVar23 = *(long *)((uint *)*puVar17 + 2);
        uVar12 = uVar16;
        if (*(uint *)*puVar17 <= uVar9) {
          uVar12 = 0;
        }
        if (((lVar23 == 0) || (lVar23 = lVar23 + uVar12 * 0x10, *(int *)(lVar23 + 4) != iVar11)) ||
           (puVar13 = *(undefined8 **)(lVar23 + 8), puVar13 == (undefined8 *)0x0)) {
          puVar13 = FUN_7100baff84();
        }
        fVar37 = -NAN;
        if (*(int *)(puVar13 + 0x30) != 0) {
          lVar23 = (long)puVar13 + (long)*(int *)(puVar13 + 0x30) + 0x180;
          fVar35 = -NAN;
          if (lVar23 == 0) goto LAB_71019ff26c;
          pfVar21 = DAT_7103a59b30;
          if (*(int *)(lVar23 + 0x30) != 0) {
            plVar14 = *(long **)(lVar23 + 0x38);
            lVar23 = (long)*(int *)(lVar23 + 0x30) << 3;
            do {
              lVar33 = *plVar14;
              if (*(int *)(lVar33 + 4) == -0x33bdb195) goto LAB_71019ff230;
              plVar14 = plVar14 + 1;
              lVar23 = lVar23 + -8;
            } while (lVar23 != 0);
          }
LAB_71019ff234:
          fVar35 = pfVar21[1];
          if (-1 < (int)fVar35) {
            lVar23 = *(long *)((float *)*puVar17 + 2);
            if (lVar23 != 0) {
              fVar37 = fVar35;
              if ((uint)*(float *)*puVar17 <= (uint)fVar35) {
                fVar37 = 0.0;
              }
              fVar37 = *(float *)(lVar23 + (ulong)(uint)fVar37 * 0x10 + 4);
              if (fVar37 == *pfVar21) goto LAB_71019ff26c;
            }
          }
        }
LAB_7101a006e8:
        fVar37 = -NAN;
        fVar35 = fVar37;
LAB_71019ff26c:
        bVar7 = false;
        local_408 = (float *)CONCAT44(fVar35,fVar37);
        local_400 = (float *)CONCAT71(local_400._1_7_,1);
      }
      else {
        if (iVar10 == 0x20) {
          lVar23 = *(long *)((uint *)*puVar17 + 2);
          uVar12 = uVar16;
          if (*(uint *)*puVar17 <= uVar9) {
            uVar12 = 0;
          }
          if (((lVar23 == 0) || (lVar23 = lVar23 + uVar12 * 0x10, *(int *)(lVar23 + 4) != iVar11))
             || (puVar13 = *(undefined8 **)(lVar23 + 8), puVar13 == (undefined8 *)0x0)) {
            puVar13 = FUN_7100baff84();
          }
          fVar37 = -NAN;
          if (*(int *)(puVar13 + 0x30) == 0) goto LAB_7101a006e8;
          lVar23 = (long)puVar13 + (long)*(int *)(puVar13 + 0x30) + 0x180;
          fVar35 = -NAN;
          if (lVar23 != 0) {
            pfVar21 = DAT_7103a59b30;
            if (*(int *)(lVar23 + 0x30) != 0) {
              plVar14 = *(long **)(lVar23 + 0x38);
              lVar23 = (long)*(int *)(lVar23 + 0x30) << 3;
              do {
                lVar33 = *plVar14;
                if (*(int *)(lVar33 + 4) == 0x9dcf3f7) goto LAB_71019ff230;
                plVar14 = plVar14 + 1;
                lVar23 = lVar23 + -8;
              } while (lVar23 != 0);
            }
            goto LAB_71019ff234;
          }
          goto LAB_71019ff26c;
        }
        if (iVar10 == 0x1f) {
          lVar23 = *(long *)((uint *)*puVar17 + 2);
          uVar12 = uVar16;
          if (*(uint *)*puVar17 <= uVar9) {
            uVar12 = 0;
          }
          if (((lVar23 == 0) || (lVar23 = lVar23 + uVar12 * 0x10, *(int *)(lVar23 + 4) != iVar11))
             || (puVar13 = *(undefined8 **)(lVar23 + 8), puVar13 == (undefined8 *)0x0)) {
            puVar13 = FUN_7100baff84();
          }
          fVar37 = -NAN;
          if (*(int *)(puVar13 + 0x30) == 0) goto LAB_7101a006e8;
          lVar23 = (long)puVar13 + (long)*(int *)(puVar13 + 0x30) + 0x180;
          fVar35 = -NAN;
          if (lVar23 != 0) {
            pfVar21 = DAT_7103a59b30;
            if (*(int *)(lVar23 + 0x30) != 0) {
              plVar14 = *(long **)(lVar23 + 0x38);
              lVar23 = (long)*(int *)(lVar23 + 0x30) << 3;
              do {
                lVar33 = *plVar14;
                if (*(int *)(lVar33 + 4) == 0x37a17145) goto LAB_71019ff230;
                plVar14 = plVar14 + 1;
                lVar23 = lVar23 + -8;
              } while (lVar23 != 0);
            }
            goto LAB_71019ff234;
          }
          goto LAB_71019ff26c;
        }
        bVar7 = true;
        fVar37 = 0.0;
        fVar35 = 0.0;
      }
      goto LAB_7101a000f8;
    }
  case 4.2039e-45:
    uVar9 = FUN_710155127c((long)pfVar29);
    puVar17 = DAT_7103a59c40;
    if (uVar9 < 0x28) {
      pcVar26 = *(char **)(DAT_7103a5b0b8 + (ulong)uVar9 * 8 + 0x328);
    }
    else {
      pcVar26 = "";
    }
    if (((((*pcVar26 == 'F') && (pcVar26[1] == 'a')) && (pcVar26[2] == 'c')) &&
        ((pcVar26[3] == 'i' && (pcVar26[4] == 'l')))) &&
       ((pcVar26[5] == 'i' && ((pcVar26[6] == 't' && (pcVar26[7] == 'y')))))) {
      fVar37 = param_2[10];
      if (pcVar26[8] == '_') {
        if (fVar37 == 1.4013e-45) {
          fVar37 = param_2[3];
          if (-1 < (int)fVar37) {
            lVar23 = *(long *)((float *)*DAT_7103a59c40 + 2);
            if (lVar23 != 0) {
              pfVar21 = param_2 + 2;
              if ((uint)*(float *)*DAT_7103a59c40 <= (uint)fVar37) {
                fVar37 = 0.0;
              }
              if (*(float *)(lVar23 + (ulong)(uint)fVar37 * 0x10 + 4) == *pfVar21) {
                iVar11 = FUN_710155127c((long)pfVar29);
                fVar37 = param_2[3];
                if ((int)fVar37 < 0) {
LAB_7101a00dc4:
                  puVar17 = FUN_7100baff84();
                }
                else {
                  pfVar29 = (float *)*puVar17;
                  lVar23 = *(long *)(pfVar29 + 2);
                  if ((uint)*pfVar29 <= (uint)fVar37) {
                    fVar37 = 0.0;
                    if (lVar23 != 0) goto LAB_71019fe664;
                    goto LAB_7101a00dc4;
                  }
                  if (lVar23 == 0) goto LAB_7101a00dc4;
LAB_71019fe664:
                  lVar23 = lVar23 + (ulong)(uint)fVar37 * 0x10;
                  if ((*(float *)(lVar23 + 4) != *pfVar21) ||
                     (puVar17 = *(undefined8 **)(lVar23 + 8), puVar17 == (undefined8 *)0x0))
                  goto LAB_7101a00dc4;
                }
                uVar9 = 0;
                if ((*(int *)(puVar17 + 0x52) == 0) ||
                   (lVar23 = (long)puVar17 + (long)*(int *)(puVar17 + 0x52) + 0x290, lVar23 == 0))
                goto switchD_71019fe33c_caseD_1;
                if (*(int *)(lVar23 + 0x28) != 0) {
                  puVar17 = *(undefined8 **)(lVar23 + 0x30);
                  lVar23 = (long)*(int *)(lVar23 + 0x28) << 3;
                  do {
                    if (*(int *)*puVar17 == 0) goto switchD_7101a00174_default;
                    if (*(int *)*puVar17 == iVar11) goto LAB_71019ff3e4;
                    uVar9 = 0;
                    puVar17 = puVar17 + 1;
                    lVar23 = lVar23 + -8;
                  } while (lVar23 != 0);
                  goto switchD_71019fe33c_caseD_1;
                }
              }
            }
          }
          break;
        }
        if ((int)fVar37 - 2U < 2) {
LAB_71019ff908:
          iVar11 = FUN_710155127c((long)pfVar29);
          local_c8._0_4_ = iVar11;
          FUN_7101a03790(&local_408,(uint *)local_c8);
          local_428 = (long *)local_408;
LAB_71019ff924:
          uVar12 = (ulong)local_428 >> 0x20;
          local_300 = local_428;
        }
        else {
          if (fVar37 != 0.0) {
            FUN_710155127c((long)pfVar29);
            goto LAB_71019ff908;
          }
          uVar12 = FUN_71015513c0((long)pfVar29);
          if ((int)uVar12 == 0x44) {
            uVar9 = FUN_710155127c((long)pfVar29);
            FUN_7102554df4((uint *)&local_2f0);
            local_300 = *(long **)DAT_7103a59b30;
            local_2f8 = 0;
            bStack_2f7 = 0;
            bStack_2f6 = 0;
            uStack_2f5 = 0;
            uStack_2f4 = 0;
            FUN_7102554df4((uint *)&local_2f0);
            fVar37 = param_2[1];
            if ((int)fVar37 < 0) {
LAB_7101a00e78:
              puVar17 = FUN_7100baff84();
            }
            else {
              lVar23 = *(long *)((float *)*DAT_7103a59c40 + 2);
              if ((uint)*(float *)*DAT_7103a59c40 <= (uint)fVar37) {
                fVar37 = 0.0;
                if (lVar23 != 0) goto LAB_71019ff694;
                goto LAB_7101a00e78;
              }
              if (lVar23 == 0) goto LAB_7101a00e78;
LAB_71019ff694:
              lVar23 = lVar23 + (ulong)(uint)fVar37 * 0x10;
              if ((*(float *)(lVar23 + 4) != *param_2) ||
                 (puVar17 = *(undefined8 **)(lVar23 + 8), puVar17 == (undefined8 *)0x0))
              goto LAB_7101a00e78;
            }
            iVar11 = *(int *)((long)puVar17 + 0x84);
            if ((iVar11 == 0) ||
               (plVar18 = (long *)((long)iVar11 + (long)puVar17 + 0x84), plVar18 == (long *)0x0)) {
              plVar18 = FUN_7100bbfd30();
              fVar37 = param_2[1];
              if (-1 < (int)fVar37) goto LAB_7101a00e94;
LAB_7101a00ee8:
              puVar17 = FUN_7100baff84();
            }
            else {
              fVar37 = param_2[1];
              if ((int)fVar37 < 0) goto LAB_7101a00ee8;
LAB_7101a00e94:
              lVar23 = *(long *)((float *)*DAT_7103a59c40 + 2);
              if ((uint)*(float *)*DAT_7103a59c40 <= (uint)fVar37) {
                fVar37 = 0.0;
                if (lVar23 != 0) goto LAB_7101a00eb4;
                goto LAB_7101a00ee8;
              }
              if (lVar23 == 0) goto LAB_7101a00ee8;
LAB_7101a00eb4:
              lVar23 = lVar23 + (ulong)(uint)fVar37 * 0x10;
              if ((*(float *)(lVar23 + 4) != *param_2) ||
                 (puVar17 = *(undefined8 **)(lVar23 + 8), puVar17 == (undefined8 *)0x0))
              goto LAB_7101a00ee8;
            }
            iVar11 = *(int *)((long)puVar17 + 0x84);
            if ((iVar11 == 0) ||
               (plVar14 = (long *)((long)iVar11 + (long)puVar17 + 0x84), plVar14 == (long *)0x0)) {
              plVar14 = FUN_7100bbfd30();
            }
            piVar15 = (int *)(*(long *)(*DAT_7103a59c30 + 0x19a8e0) + 0x5add0);
            if (uVar9 < 0x28) {
              piVar15 = piVar15 + (ulong)uVar9 * 4;
            }
            local_428 = local_300;
            if (*piVar15 != 0) {
              lVar33 = plVar14[0x29];
              fVar35 = *(float *)((long)plVar18 + 0x11c);
              fVar38 = *(float *)((long)plVar18 + 0x124);
              lVar23 = (long)*piVar15 << 3;
              plVar18 = *(long **)(piVar15 + 2);
              fVar37 = (float)CONCAT13(uStack_2f5,
                                       CONCAT12(bStack_2f6,CONCAT11(bStack_2f7,local_2f8)));
              local_420 = (uint)local_2f0;
              uVar34 = local_2e8._4_4_;
              uVar9 = (uint)local_2e8;
              uVar32 = local_2f0._4_4_;
              do {
                lVar25 = *plVar18;
                piVar15 = (int *)(lVar25 + 0x84);
                iVar11 = *piVar15;
                plVar14 = (long *)((long)iVar11 + (long)piVar15);
                if ((((iVar11 != 0 && plVar14 != (long *)0x0) &&
                     (pfVar29 = (float *)(**(code **)(*plVar14 + 0xa8))(plVar14),
                     (int)plVar14[0x29] == (int)lVar33)) &&
                    (fVar39 = pfVar29[2] - fVar38, fVar36 = *pfVar29 - fVar35,
                    fVar39 * fVar39 + fVar36 * fVar36 <= 25.0)) &&
                   ((fVar37 = fVar37 + 1.0, ABS(fVar37) != INFINITY &&
                    ((fVar37 < 0.0 ||
                     (local_420 = local_420 ^ local_420 << 0xb,
                     uVar2 = local_420 >> 8 ^ uVar34 >> 0x13 ^ local_420 ^ uVar34,
                     local_420 = uVar32, uVar32 = uVar9, uVar9 = uVar34, uVar34 = uVar2,
                     fVar37 * ((float)(uVar2 >> 9 | 0x3f800000) + -1.0) + 0.0 < 1.0)))))) {
                  local_428 = *(long **)(lVar25 + 0x400);
                }
                plVar18 = plVar18 + 1;
                lVar23 = lVar23 + -8;
              } while (lVar23 != 0);
            }
            goto LAB_71019ff924;
          }
          uVar12 = FUN_71015513c0((long)pfVar29);
          if ((int)uVar12 == 0x52) {
            iVar10 = FUN_710155127c((long)pfVar29);
            iVar11 = 0x56198083;
            local_c8._0_4_ = iVar10;
LAB_7101a00480:
            FUN_7101a03000((int *)&local_408,(uint *)local_c8,iVar11,(int *)param_2);
            local_428 = (long *)local_408;
            goto LAB_71019ff924;
          }
          uVar12 = FUN_71015513c0((long)pfVar29);
          if ((int)uVar12 == 0x53) {
            iVar11 = FUN_710155127c((long)pfVar29);
            local_c8._0_4_ = iVar11;
            iVar11 = 0x4cc86307;
            goto LAB_7101a00480;
          }
          iVar11 = FUN_710155127c((long)pfVar29);
          local_c8._0_4_ = iVar11;
          if (iVar11 == 0x17) {
            FUN_7100eec850((undefined4 *)&local_408,(int *)param_2);
            if ((long)local_408 < 0) goto LAB_7101a00764;
            lVar23 = *(long *)((uint *)*DAT_7103a59c40 + 2);
            if (lVar23 == 0) goto LAB_7101a00764;
            uVar9 = local_408._4_4_;
            if (*(uint *)*DAT_7103a59c40 <= local_408._4_4_) {
              uVar9 = 0;
            }
            if ((*(float *)(lVar23 + (ulong)uVar9 * 0x10 + 4) != (float)local_408) ||
               (uVar12 = FUN_71019f41e0((int *)&local_408,(int *)local_c8), (uVar12 & 1) == 0))
            goto LAB_7101a00764;
          }
          else {
LAB_7101a00764:
            local_408 = (float *)0xffffffffffffffff;
          }
          local_300 = (long *)local_408;
          if ((long)local_408 < 0) {
LAB_7101a007b0:
            iVar11 = FUN_710155127c((long)pfVar29);
            local_c8._0_4_ = iVar11;
            FUN_7101a03450(&local_408,(uint *)local_c8,(int *)param_2);
            local_300 = (long *)local_408;
            uVar12 = (ulong)local_408 >> 0x20;
          }
          else {
            lVar23 = *(long *)((uint *)*DAT_7103a59c40 + 2);
            if (lVar23 == 0) goto LAB_7101a007b0;
            uVar12 = (ulong)local_408 >> 0x20;
            uVar16 = uVar12;
            if (*(uint *)*DAT_7103a59c40 <= (uint)((ulong)local_408 >> 0x20)) {
              uVar16 = 0;
            }
            if (*(int *)(lVar23 + uVar16 * 0x10 + 4) != (int)local_408) goto LAB_7101a007b0;
          }
        }
        if (-1 < (int)(uint)uVar12) {
          lVar23 = *(long *)((uint *)*DAT_7103a59c40 + 2);
          if (lVar23 != 0) {
            if (*(uint *)*DAT_7103a59c40 <= (uint)uVar12) {
              uVar12 = 0;
            }
            if (*(int *)(lVar23 + uVar12 * 0x10 + 4) == (int)local_300) goto LAB_71019ff3d8;
          }
        }
        break;
      }
    }
    else {
      fVar37 = param_2[10];
    }
    pfVar21 = param_2 + 10;
    if (fVar37 == 1.4013e-45) {
      fVar37 = param_2[3];
      if (-1 < (int)fVar37) {
        lVar23 = *(long *)((float *)*DAT_7103a59c40 + 2);
        if (lVar23 != 0) {
          pfVar21 = param_2 + 2;
          if ((uint)*(float *)*DAT_7103a59c40 <= (uint)fVar37) {
            fVar37 = 0.0;
          }
          if (*(float *)(lVar23 + (ulong)(uint)fVar37 * 0x10 + 4) == *pfVar21) {
            iVar11 = FUN_710155127c((long)pfVar29);
            fVar37 = param_2[3];
            if ((int)fVar37 < 0) {
LAB_71019ffc78:
              puVar17 = FUN_7100baff84();
            }
            else {
              pfVar30 = (float *)*puVar17;
              lVar23 = *(long *)(pfVar30 + 2);
              if ((uint)*pfVar30 <= (uint)fVar37) {
                fVar37 = 0.0;
                if (lVar23 != 0) goto LAB_71019fe704;
                goto LAB_71019ffc78;
              }
              if (lVar23 == 0) goto LAB_71019ffc78;
LAB_71019fe704:
              lVar23 = lVar23 + (ulong)(uint)fVar37 * 0x10;
              if ((*(float *)(lVar23 + 4) != *pfVar21) ||
                 (puVar17 = *(undefined8 **)(lVar23 + 8), puVar17 == (undefined8 *)0x0))
              goto LAB_71019ffc78;
            }
            uVar9 = 0;
            if ((*(int *)(puVar17 + 0x52) == 0) ||
               (lVar23 = (long)puVar17 + (long)*(int *)(puVar17 + 0x52) + 0x290, lVar23 == 0))
            goto switchD_71019fe33c_caseD_1;
            if (*(int *)(lVar23 + 0x28) != 0) {
              puVar17 = *(undefined8 **)(lVar23 + 0x30);
              lVar23 = (long)*(int *)(lVar23 + 0x28) << 3;
              do {
                if (*(int *)*puVar17 == 0) goto switchD_7101a00174_default;
                if (*(int *)*puVar17 == iVar11) {
                  iVar11 = FUN_710155127c((long)pfVar29);
                  local_418[0] = iVar11;
                  bVar7 = FUN_7101a04a20(local_418);
                  if (bVar7) {
                    local_128 = 0;
                    local_300 = (long *)((long)&local_2f0 + 4);
                    local_2f8 = 5;
                    bStack_2f7 = 0;
                    bStack_2f6 = 0;
                    uStack_2f5 = 0;
                    local_270 = auStack_25c;
                    local_268 = 5;
                    local_1d8 = 5;
                    local_1e0 = auStack_1cc;
                    uStack_2f4 = 0;
                    local_2f0._0_4_ = 0;
                    local_264 = 0;
                    local_1d4 = 0;
                    local_150 = 0;
                    local_148 = 0;
                    local_144 = *DAT_7103a5ba00;
                    local_13c = *(undefined4 *)(DAT_7103a5ba00 + 1);
                    local_e8 = 0;
                    local_f0 = 0;
                    local_dc = 0;
                    local_138 = *DAT_7103a5a248;
                    local_130 = (ulong)*(uint *)(DAT_7103a5a248 + 1);
                    uStack_118 = 0;
                    local_120 = 0x3f800000;
                    uStack_108 = 0;
                    uStack_110 = 0x3f80000000000000;
                    local_e0 = 0xffffffff;
                    uStack_f8 = 0x3f800000;
                    local_100 = 0;
                    uVar12 = FUN_71015513c0((long)pfVar29);
                    local_308 = (float)uVar12;
                    FUN_7101483c20(&local_408);
                    plVar18 = (long *)local_408;
                    plVar14 = (long *)local_408;
                    if (local_408 == (float *)0x0) {
                      plVar14 = FUN_7100d1d130();
                      plVar18 = FUN_7100d1d130();
                    }
                    fVar35 = *(float *)((long)plVar14 + 0x44) - *(float *)(plVar18 + 7);
                    fVar38 = *(float *)((long)plVar14 + 0x4c) - *(float *)(plVar18 + 8);
                    fVar37 = fVar38;
                    if (fVar38 <= 0.0) {
                      fVar37 = -fVar38;
                    }
                    fVar39 = fVar35;
                    if (fVar35 <= 0.0) {
                      fVar39 = -fVar35;
                    }
                    if (fVar39 <= fVar37) {
                      iVar11 = (uint)(0.0 < fVar38) << 1;
                      iVar10 = 3;
                      if (fVar35 <= 0.0) {
                        iVar10 = 1;
                      }
                    }
                    else {
                      iVar11 = 3;
                      if (fVar35 <= 0.0) {
                        iVar11 = 1;
                      }
                      iVar10 = (uint)(0.0 < fVar38) << 1;
                    }
                    local_c8._4_4_ = iVar10;
                    local_c8._0_4_ = iVar11;
                    uVar9 = FUN_71019f87d0(ZEXT416((uint)fVar35),ZEXT416((uint)fVar38),fVar39,
                                           &local_300,(int *)pfVar21,(int *)&local_308,
                                           (uint *)local_c8);
                  }
                  else {
                    if (1 < iVar11 - 0x25U) goto switchD_7101a00174_default;
                    local_128 = 0;
                    local_300 = (long *)((long)&local_2f0 + 4);
                    local_2f8 = 5;
                    bStack_2f7 = 0;
                    bStack_2f6 = 0;
                    uStack_2f5 = 0;
                    local_270 = auStack_25c;
                    local_268 = 5;
                    local_1d8 = 5;
                    local_1e0 = auStack_1cc;
                    uStack_2f4 = 0;
                    local_2f0._0_4_ = 0;
                    local_264 = 0;
                    local_1d4 = 0;
                    local_150 = 0;
                    local_148 = 0;
                    local_144 = *DAT_7103a5ba00;
                    local_13c = *(undefined4 *)(DAT_7103a5ba00 + 1);
                    local_e8 = 0;
                    local_f0 = 0;
                    local_dc = 0;
                    local_138 = *DAT_7103a5a248;
                    local_130 = (ulong)*(uint *)(DAT_7103a5a248 + 1);
                    uStack_118 = 0;
                    local_120 = 0x3f800000;
                    uStack_108 = 0;
                    uStack_110 = 0x3f80000000000000;
                    local_e0 = 0xffffffff;
                    uStack_f8 = 0x3f800000;
                    local_100 = 0;
                    uVar12 = FUN_71015513c0((long)pfVar29);
                    local_308 = (float)uVar12;
                    FUN_7101483c20(&local_408);
                    plVar18 = (long *)local_408;
                    plVar14 = (long *)local_408;
                    if (local_408 == (float *)0x0) {
                      plVar14 = FUN_7100d1d130();
                      plVar18 = FUN_7100d1d130();
                    }
                    fVar35 = *(float *)((long)plVar14 + 0x44) - *(float *)(plVar18 + 7);
                    fVar38 = *(float *)((long)plVar14 + 0x4c) - *(float *)(plVar18 + 8);
                    fVar37 = fVar38;
                    if (fVar38 <= 0.0) {
                      fVar37 = -fVar38;
                    }
                    fVar39 = fVar35;
                    if (fVar35 <= 0.0) {
                      fVar39 = -fVar35;
                    }
                    if (fVar39 <= fVar37) {
                      iVar11 = (uint)(0.0 < fVar38) << 1;
                      iVar10 = 3;
                      if (fVar35 <= 0.0) {
                        iVar10 = 1;
                      }
                    }
                    else {
                      iVar11 = 3;
                      if (fVar35 <= 0.0) {
                        iVar11 = 1;
                      }
                      iVar10 = (uint)(0.0 < fVar38) << 1;
                    }
                    local_c8._4_4_ = iVar10;
                    local_c8._0_4_ = iVar11;
                    uVar9 = FUN_71019f9bf0(&local_300,(int *)pfVar21,(int *)&local_308,
                                           (uint *)local_c8);
                  }
                  if ((uVar9 & 1) != 0) {
                    FUN_71019fc62c((undefined8 *)param_1,(undefined8 *)pfVar21,&local_300);
                  }
                  break;
                }
                uVar9 = 0;
                puVar17 = puVar17 + 1;
                lVar23 = lVar23 + -8;
              } while (lVar23 != 0);
              goto switchD_71019fe33c_caseD_1;
            }
          }
        }
      }
    }
    else {
      fVar37 = param_2[1];
      if ((int)fVar37 < 0) {
LAB_71019ffaa8:
        puVar17 = FUN_7100baff84();
      }
      else {
        lVar23 = *(long *)((float *)*DAT_7103a59c40 + 2);
        if ((uint)*(float *)*DAT_7103a59c40 <= (uint)fVar37) {
          fVar37 = 0.0;
          if (lVar23 != 0) goto LAB_71019fe968;
          goto LAB_71019ffaa8;
        }
        if (lVar23 == 0) goto LAB_71019ffaa8;
LAB_71019fe968:
        lVar23 = lVar23 + (ulong)(uint)fVar37 * 0x10;
        if ((*(float *)(lVar23 + 4) != *param_2) ||
           (puVar17 = *(undefined8 **)(lVar23 + 8), puVar17 == (undefined8 *)0x0))
        goto LAB_71019ffaa8;
      }
      iVar11 = *(int *)((long)puVar17 + 0x84);
      uVar9 = 0;
      if ((iVar11 == 0) || (lVar23 = (long)iVar11 + (long)puVar17 + 0x84, lVar23 == 0))
      goto switchD_71019fe33c_caseD_1;
      if (*pfVar21 == 0.0) {
        if (*(int *)(lVar23 + 0x148) != 0) break;
        FUN_7100eec850((undefined4 *)&local_300,(int *)param_2);
        if (-1 < (long)local_300) {
          lVar23 = *(long *)((uint *)*DAT_7103a59c40 + 2);
          if (lVar23 != 0) {
            uVar9 = (uint)local_300._4_4_;
            if (*(uint *)*DAT_7103a59c40 <= (uint)local_300._4_4_) {
              uVar9 = 0;
            }
            if (*(float *)(lVar23 + (ulong)uVar9 * 0x10 + 4) == (float)local_300) break;
          }
        }
      }
      uVar9 = FUN_710155127c((long)pfVar29);
      if (uVar9 < 0x28) {
        pcVar26 = *(char **)(DAT_7103a5b0b8 + (ulong)uVar9 * 8 + 0x328);
      }
      else {
        pcVar26 = "";
      }
      if ((((*pcVar26 != 'N') || (pcVar26[1] != 'o')) || (pcVar26[2] != 'D')) ||
         ((pcVar26[3] != 'i' || (pcVar26[4] != 'r')))) {
        if (uVar9 < 0x28) {
          pcVar26 = *(char **)(DAT_7103a5b0b8 + (ulong)uVar9 * 8 + 0x328);
        }
        else {
          pcVar26 = "";
        }
        if (((*pcVar26 != 'D') || (pcVar26[1] != 'i')) || (pcVar26[2] != 'r')) {
          if (1 < uVar9 - 0x25) break;
          fVar37 = param_2[1];
          if ((int)fVar37 < 0) {
LAB_7101a004ec:
            puVar17 = FUN_7100baff84();
          }
          else {
            lVar23 = *(long *)((float *)*DAT_7103a59c40 + 2);
            if ((uint)*(float *)*DAT_7103a59c40 <= (uint)fVar37) {
              fVar37 = 0.0;
              if (lVar23 != 0) goto LAB_71019ffc4c;
              goto LAB_7101a004ec;
            }
            if (lVar23 == 0) goto LAB_7101a004ec;
LAB_71019ffc4c:
            lVar23 = lVar23 + (ulong)(uint)fVar37 * 0x10;
            if ((*(float *)(lVar23 + 4) != *param_2) ||
               (puVar17 = *(undefined8 **)(lVar23 + 8), puVar17 == (undefined8 *)0x0))
            goto LAB_7101a004ec;
          }
          iVar11 = *(int *)((long)puVar17 + 0x84);
          uVar9 = 0;
          if ((iVar11 == 0) || (lVar23 = (long)iVar11 + (long)puVar17 + 0x84, lVar23 == 0))
          goto switchD_71019fe33c_caseD_1;
          local_2f8 = 5;
          bStack_2f7 = 0;
          bStack_2f6 = 0;
          uStack_2f5 = 0;
          local_300 = (long *)((long)&local_2f0 + 4);
          local_268 = 5;
          local_1d8 = 5;
          local_270 = auStack_25c;
          local_1e0 = auStack_1cc;
          local_128 = 0;
          uStack_2f4 = 0;
          local_2f0._0_4_ = 0;
          local_264 = 0;
          local_1d4 = 0;
          pfVar29 = (float *)(lVar23 + 0x11c);
          if (*(int *)(lVar23 + 0x148) != 0) {
            pfVar29 = DAT_7103a5a0f8;
          }
          local_150 = 0;
          local_148 = 0;
          local_144 = *DAT_7103a5ba00;
          local_13c = *(undefined4 *)(DAT_7103a5ba00 + 1);
          local_e8 = 0;
          local_f0 = 0;
          local_dc = '\0';
          local_138 = *DAT_7103a5a248;
          local_130 = (ulong)*(uint *)(DAT_7103a5a248 + 1);
          uStack_118 = 0;
          local_120 = 0x3f800000;
          uStack_108 = 0;
          uStack_110 = 0x3f80000000000000;
          local_e0 = 0xffffffff;
          local_418[0] = 0x7f7fffff;
          local_c8._0_8_ = 0xffffffffffffffff;
          uStack_f8 = 0x3f800000;
          local_100 = 0;
          FUN_7101483c20(&local_408);
          plVar18 = (long *)local_408;
          if (local_408 == (float *)0x0) {
            plVar18 = FUN_7100d1d130();
            local_408 = (float *)FUN_7100d1d130();
          }
          fVar35 = *(float *)((long)plVar18 + 0x44) - *(float *)((long)local_408 + 0x38);
          fVar38 = *(float *)((long)plVar18 + 0x4c) - *(float *)((long)local_408 + 0x40);
          fVar37 = fVar38;
          if (fVar38 <= 0.0) {
            fVar37 = -fVar38;
          }
          fVar39 = fVar35;
          if (fVar35 <= 0.0) {
            fVar39 = -fVar35;
          }
          if (fVar39 <= fVar37) {
            local_308 = (float)((uint)(0.0 < fVar38) << 1);
            local_304 = 3;
            if (fVar35 <= 0.0) {
              local_304 = 1;
            }
          }
          else {
            local_308 = 4.2039e-45;
            if (fVar35 <= 0.0) {
              local_308 = 1.4013e-45;
            }
            local_304 = (uint)(0.0 < fVar38) << 1;
          }
          local_408 = (float *)&DAT_710398f9a8;
          puStack_3f0 = local_418;
          local_3e0 = (uint *)local_c8;
          local_3e8 = (float *)&local_300;
          local_400 = param_2;
          local_3f8 = pfVar29;
          FUN_71019e8c60((int *)&local_308,&local_408);
          (**(code **)((long)local_408 + 0x18))(&local_408);
          uVar9 = (uint)(local_dc != '\0' || (uint)local_2f0 != 0);
          if (local_dc == '\0' && (uint)local_2f0 == 0) goto switchD_71019fe33c_caseD_1;
          puVar31 = (uint *)local_c8;
          goto LAB_7101a006bc;
        }
      }
      fVar37 = param_2[1];
      if ((int)fVar37 < 0) {
LAB_7101a0080c:
        puVar17 = FUN_7100baff84();
      }
      else {
        lVar23 = *(long *)((float *)*DAT_7103a59c40 + 2);
        if ((uint)*(float *)*DAT_7103a59c40 <= (uint)fVar37) {
          fVar37 = 0.0;
          if (lVar23 != 0) goto LAB_71019ffbf4;
          goto LAB_7101a0080c;
        }
        if (lVar23 == 0) goto LAB_7101a0080c;
LAB_71019ffbf4:
        lVar23 = lVar23 + (ulong)(uint)fVar37 * 0x10;
        if ((*(float *)(lVar23 + 4) != *param_2) ||
           (puVar17 = *(undefined8 **)(lVar23 + 8), puVar17 == (undefined8 *)0x0))
        goto LAB_7101a0080c;
      }
      iVar11 = *(int *)((long)puVar17 + 0x84);
      uVar9 = 0;
      if ((iVar11 == 0) || (lVar23 = (long)iVar11 + (long)puVar17 + 0x84, lVar23 == 0))
      goto switchD_71019fe33c_caseD_1;
      pfVar30 = (float *)(lVar23 + 0x11c);
      if (*(int *)(lVar23 + 0x148) != 0) {
        pfVar30 = DAT_7103a5a0f8;
      }
      uVar12 = FUN_71015513c0((long)pfVar29);
      if ((int)uVar12 != 0) {
        local_128 = 0;
        local_300 = (long *)((long)&local_2f0 + 4);
        local_2f8 = 5;
        bStack_2f7 = 0;
        bStack_2f6 = 0;
        uStack_2f5 = 0;
        local_270 = auStack_25c;
        local_268 = 5;
        local_1d8 = 5;
        local_1e0 = auStack_1cc;
        uStack_2f4 = 0;
        local_2f0._0_4_ = 0;
        local_264 = 0;
        local_1d4 = 0;
        local_150 = 0;
        local_148 = 0;
        local_144 = *DAT_7103a5ba00;
        local_13c = *(undefined4 *)(DAT_7103a5ba00 + 1);
        local_e8 = 0;
        local_f0 = 0;
        local_dc = '\0';
        local_138 = *DAT_7103a5a248;
        local_130 = (ulong)*(uint *)(DAT_7103a5a248 + 1);
        uStack_118 = 0;
        local_120 = 0x3f800000;
        uStack_108 = 0;
        uStack_110 = 0x3f80000000000000;
        local_e0 = 0xffffffff;
        local_418[2] = 0x7f7fffff;
        local_418[0] = 0xffffffff;
        local_418[1] = 0xffffffff;
        local_41c = 4;
        uStack_f8 = 0x3f800000;
        local_100 = 0;
        uVar9 = FUN_710155127c((long)pfVar29);
        puVar17 = DAT_7103a59c40;
        piVar15 = (int *)(*(long *)(*DAT_7103a59c30 + 0x19a8e0) + 0x5add0);
        if (uVar9 < 0x28) {
          piVar15 = piVar15 + (ulong)uVar9 * 4;
        }
        if (*piVar15 != 0) {
          plVar18 = *(long **)(piVar15 + 2);
          lVar23 = (long)*piVar15 << 3;
          do {
            piVar15 = (int *)(*plVar18 + 0x400);
            uVar9 = *(uint *)(*plVar18 + 0x404);
            local_c8._0_8_ = *(undefined8 *)piVar15;
            if ((int)uVar9 < 0) {
LAB_7101a00a04:
              puVar13 = FUN_7100baff84();
            }
            else {
              puVar31 = (uint *)*puVar17;
              if (*puVar31 <= uVar9) {
                uVar9 = 0;
                lVar33 = *(long *)(puVar31 + 2);
                if (lVar33 != 0) goto LAB_7101a009d8;
                goto LAB_7101a00a04;
              }
              lVar33 = *(long *)(puVar31 + 2);
              if (lVar33 == 0) goto LAB_7101a00a04;
LAB_7101a009d8:
              lVar33 = lVar33 + (ulong)uVar9 * 0x10;
              if ((*(int *)(lVar33 + 4) != *piVar15) ||
                 (puVar13 = *(undefined8 **)(lVar33 + 8), puVar13 == (undefined8 *)0x0))
              goto LAB_7101a00a04;
            }
            iVar11 = *(int *)((long)puVar13 + 0x84);
            if ((iVar11 == 0) ||
               (plVar14 = (long *)((long)iVar11 + (long)puVar13 + 0x84), plVar14 == (long *)0x0)) {
              plVar14 = FUN_7100bbfd30();
            }
            fVar37 = *(float *)((long)plVar14 + 0x11c) - *pfVar30;
            fVar35 = *(float *)((long)plVar14 + 0x124) - pfVar30[2];
            local_40c = fVar35 * fVar35 + fVar37 * fVar37;
            if ((*pfVar21 != 0.0) || (local_40c < 25.0)) {
              FUN_7101483c20(&local_408);
              plVar14 = (long *)local_408;
              if (local_408 == (float *)0x0) {
                plVar14 = FUN_7100d1d130();
                local_408 = (float *)FUN_7100d1d130();
              }
              fVar35 = *(float *)((long)plVar14 + 0x44) - *(float *)((long)local_408 + 0x38);
              fVar38 = *(float *)((long)plVar14 + 0x4c) - *(float *)((long)local_408 + 0x40);
              fVar37 = fVar38;
              if (fVar38 <= 0.0) {
                fVar37 = -fVar38;
              }
              fVar39 = fVar35;
              if (fVar35 <= 0.0) {
                fVar39 = -fVar35;
              }
              if (fVar39 <= fVar37) {
                local_308 = (float)((uint)(0.0 < fVar38) << 1);
                local_304 = 3;
                if (fVar35 <= 0.0) {
                  local_304 = 1;
                }
              }
              else {
                local_308 = 4.2039e-45;
                if (fVar35 <= 0.0) {
                  local_308 = 1.4013e-45;
                }
                local_304 = (uint)(0.0 < fVar38) << 1;
              }
              local_400 = (float *)local_c8;
              local_408 = (float *)&DAT_710398f970;
              puStack_3f0 = &local_41c;
              local_3e8 = &local_40c;
              local_3e0 = local_418 + 2;
              local_3d0 = &local_300;
              local_3c8 = local_418;
              local_3f8 = param_2;
              pfStack_3d8 = &local_308;
              bVar7 = FUN_7101a03900(ZEXT416((uint)fVar35),ZEXT416((uint)fVar38),fVar39,
                                     (long)&local_408,(uint *)&local_308);
              if ((!bVar7) &&
                 (uVar12 = (**(code **)local_408)(&local_408,(ulong)&local_308 | 4),
                 (uVar12 & 1) == 0)) {
                if (local_304 - 1U < 3) {
                  local_b4[0] = (&DAT_71032b4e00)[(int)(local_304 - 1U)];
                }
                else {
                  local_b4[0] = 2;
                }
                uVar12 = (**(code **)local_408)(&local_408,local_b4);
                if ((uVar12 & 1) == 0) {
                  if ((int)local_308 - 1U < 3) {
                    local_b4[0] = (&DAT_71032b4e00)[(int)((int)local_308 - 1U)];
                  }
                  else {
                    local_b4[0] = 2;
                  }
                  (**(code **)local_408)(&local_408,local_b4);
                }
              }
              (**(code **)((long)local_408 + 0x18))(&local_408);
            }
            plVar18 = plVar18 + 1;
            lVar23 = lVar23 + -8;
          } while (lVar23 != 0);
        }
        uVar9 = (uint)(local_dc != '\0' || (uint)local_2f0 != 0);
        if (local_dc == '\0' && (uint)local_2f0 == 0) goto switchD_71019fe33c_caseD_1;
        puVar31 = local_418;
        goto LAB_7101a006bc;
      }
      local_300 = (long *)0xffffffffffffffff;
      uVar9 = FUN_710155127c((long)pfVar29);
      piVar15 = (int *)(*(long *)(*DAT_7103a59c30 + 0x19a8e0) + 0x5add0);
      if (uVar9 < 0x28) {
        piVar15 = piVar15 + (ulong)uVar9 * 4;
      }
      if (*piVar15 != 0) {
        plVar18 = *(long **)(piVar15 + 2);
        fVar37 = 3.4028235e+38;
        iVar11 = -1;
        lVar23 = (long)*piVar15 << 3;
        uVar12 = 0xffffffff;
        do {
          plVar14 = (long *)(*plVar18 + 0x400);
          iVar10 = *(int *)plVar14;
          uVar9 = *(uint *)(*plVar18 + 0x404);
          lVar33 = *plVar14;
          if ((int)uVar9 < 0) {
LAB_7101a00c94:
            puVar17 = FUN_7100baff84();
          }
          else {
            puVar31 = (uint *)*DAT_7103a59c40;
            if (*puVar31 <= uVar9) {
              uVar32 = 0;
              lVar25 = *(long *)(puVar31 + 2);
              if (lVar25 != 0) goto LAB_7101a00c68;
              goto LAB_7101a00c94;
            }
            lVar25 = *(long *)(puVar31 + 2);
            uVar32 = uVar9;
            if (lVar25 == 0) goto LAB_7101a00c94;
LAB_7101a00c68:
            lVar25 = lVar25 + (ulong)uVar32 * 0x10;
            if ((*(int *)(lVar25 + 4) != iVar10) ||
               (puVar17 = *(undefined8 **)(lVar25 + 8), puVar17 == (undefined8 *)0x0))
            goto LAB_7101a00c94;
          }
          iVar3 = *(int *)((long)puVar17 + 0x84);
          if ((iVar3 == 0) ||
             (plVar14 = (long *)((long)iVar3 + (long)puVar17 + 0x84), plVar14 == (long *)0x0)) {
            plVar14 = FUN_7100bbfd30();
          }
          fVar35 = *(float *)((long)plVar14 + 0x11c) - *pfVar30;
          fVar38 = *(float *)((long)plVar14 + 0x124) - pfVar30[2];
          fVar35 = fVar38 * fVar38 + fVar35 * fVar35;
          bVar7 = false;
          bVar6 = false;
          if (fVar35 < 25.0 || *pfVar21 != 0.0) {
            bVar7 = false;
            bVar6 = true;
            if (!NAN(fVar35) && !NAN(fVar37)) {
              bVar7 = fVar35 < fVar37;
              bVar6 = false;
            }
          }
          if (bVar7 != bVar6) {
            uVar12 = (ulong)uVar9;
            fVar37 = fVar35;
            local_300 = (long *)lVar33;
            iVar11 = iVar10;
          }
          plVar18 = plVar18 + 1;
          lVar23 = lVar23 + -8;
        } while (lVar23 != 0);
        if (-1 < (int)(uint)uVar12) {
          lVar23 = *(long *)((uint *)*DAT_7103a59c40 + 2);
          if (lVar23 != 0) {
            if (*(uint *)*DAT_7103a59c40 <= (uint)uVar12) {
              uVar12 = 0;
            }
            if (*(int *)(lVar23 + uVar12 * 0x10 + 4) == iVar11) {
              FUN_71019fcfd4((undefined8 *)param_1,(int *)&local_300);
              goto LAB_7101a004dc;
            }
          }
        }
      }
    }
    break;
  case 5.60519e-45:
    uVar12 = FUN_71015513c0((long)pfVar29);
    if (param_2[10] == 4.2039e-45) {
      fVar37 = param_2[1];
      if ((int)fVar37 < 0) {
LAB_71019ff974:
        puVar17 = FUN_7100baff84();
      }
      else {
        lVar23 = *(long *)((float *)*DAT_7103a59c40 + 2);
        if ((uint)*(float *)*DAT_7103a59c40 <= (uint)fVar37) {
          fVar37 = 0.0;
          if (lVar23 != 0) goto LAB_71019fe2e4;
          goto LAB_71019ff974;
        }
        if (lVar23 == 0) goto LAB_71019ff974;
LAB_71019fe2e4:
        lVar23 = lVar23 + (ulong)(uint)fVar37 * 0x10;
        if ((*(float *)(lVar23 + 4) != *param_2) ||
           (puVar17 = *(undefined8 **)(lVar23 + 8), puVar17 == (undefined8 *)0x0))
        goto LAB_71019ff974;
      }
      iVar11 = *(int *)((long)puVar17 + 0xbc);
      uVar9 = 0;
      if ((iVar11 == 0) || (lVar23 = (long)iVar11 + (long)puVar17 + 0xbc, lVar23 == 0))
      goto switchD_71019fe33c_caseD_1;
      puVar19 = (ulong *)FUN_7100e01584(lVar23);
      uVar9 = *(uint *)((long)puVar19 + 4);
      if (-1 < (int)uVar9) {
        lVar23 = *(long *)((uint *)*DAT_7103a59c40 + 2);
        if (lVar23 != 0) {
          if (*(uint *)*DAT_7103a59c40 <= uVar9) {
            uVar9 = 0;
          }
          if (*(int *)(lVar23 + (ulong)uVar9 * 0x10 + 4) == (int)*puVar19) {
            uVar12 = *puVar19;
            param_1[4] = 1.4013e-45;
            puVar17 = DAT_7103a5ba00;
            param_1[0xb] = 0.0;
            param_1[0xc] = 0.0;
            fVar37 = *(float *)(puVar17 + 1);
            *(undefined8 *)(param_1 + 0x77) = *puVar17;
            pfVar29 = DAT_7103a59b30;
            param_1[0x53] = 0.0;
            plVar18 = DAT_7103a5a248;
            param_1[0x54] = 0.0;
            *(ulong *)param_1 = uVar12;
            param_1[0x79] = fVar37;
            param_1[0x2f] = 0.0;
            param_1[0x30] = 0.0;
            param_1[0x76] = 0.0;
            param_1[0x74] = 0.0;
            param_1[0x75] = 0.0;
            fVar37 = pfVar29[1];
            lVar23 = *plVar18;
            fVar35 = *(float *)(plVar18 + 1);
            param_1[2] = *pfVar29;
            param_1[3] = fVar37;
            param_1[0x7c] = fVar35;
            *(long *)(param_1 + 0x7a) = lVar23;
            goto LAB_71019ffa48;
          }
        }
      }
      break;
    }
    bVar7 = FUN_7101cbb5d0((int *)param_2);
    if (bVar7) {
LAB_71019fe738:
      puVar19 = FUN_7101cbd7d0((int *)param_2);
      uVar9 = *(uint *)((long)puVar19 + 4);
      if ((int)uVar9 < 0) break;
      lVar23 = *(long *)((uint *)*DAT_7103a59c40 + 2);
      if (lVar23 == 0) break;
      if (*(uint *)*DAT_7103a59c40 <= uVar9) {
        uVar9 = 0;
      }
      if (*(int *)(lVar23 + (ulong)uVar9 * 0x10 + 4) != (int)*puVar19) break;
      uVar12 = *puVar19;
      param_1[0xb] = 0.0;
      param_1[0xc] = 0.0;
      param_1[0x2f] = 0.0;
      puVar17 = DAT_7103a5ba00;
      param_1[0x30] = 0.0;
      param_1[4] = 1.4013e-45;
      fVar37 = *(float *)(puVar17 + 1);
      *(undefined8 *)(param_1 + 0x77) = *puVar17;
      pfVar29 = DAT_7103a59b30;
      param_1[0x74] = 0.0;
      param_1[0x75] = 0.0;
      param_1[0x76] = 0.0;
      param_1[0x53] = 0.0;
      plVar18 = DAT_7103a5a248;
      param_1[0x54] = 0.0;
      *(ulong *)param_1 = uVar12;
      param_1[0x79] = fVar37;
      fVar37 = pfVar29[1];
      param_1[2] = *pfVar29;
      param_1[3] = fVar37;
      *(long *)(param_1 + 0x7a) = *plVar18;
      param_1[0x7c] = *(float *)(plVar18 + 1);
LAB_71019ffa48:
      local_300 = (long *)CONCAT44(local_300._4_4_,0x4782c42d);
      param_1[0x8e] = 0.0;
      param_1[0x8f] = 0.0;
      param_1[0x8c] = 0.0;
      param_1[0x8d] = 0.0;
      *(undefined1 *)(param_1 + 0x91) = 0;
      param_1[0x82] = 0.0;
      param_1[0x83] = 0.0;
      param_1[0x80] = 1.0;
      param_1[0x81] = 0.0;
      param_1[0x86] = 0.0;
      param_1[0x87] = 0.0;
      param_1[0x84] = 0.0;
      param_1[0x85] = 1.0;
      param_1[0x90] = -NAN;
      param_1[0x8a] = 1.0;
      param_1[0x8b] = 0.0;
      param_1[0x88] = 0.0;
      param_1[0x89] = 0.0;
      bVar7 = FUN_71019fcad4((int *)param_1,(int *)puVar19,(int *)&local_300);
      uVar9 = (uint)bVar7;
      goto switchD_71019fe33c_caseD_1;
    }
    piVar15 = (int *)FUN_7101cba9d0((int *)param_2);
    uVar9 = piVar15[1];
    if (-1 < (int)uVar9) {
      lVar23 = *(long *)((uint *)*DAT_7103a59c40 + 2);
      if (lVar23 != 0) {
        if (*(uint *)*DAT_7103a59c40 <= uVar9) {
          uVar9 = 0;
        }
        if (*(int *)(lVar23 + (ulong)uVar9 * 0x10 + 4) == *piVar15) {
          puVar17 = *(undefined8 **)(lVar23 + (ulong)uVar9 * 0x10 + 8);
          if (puVar17 == (undefined8 *)0x0) {
            puVar17 = FUN_7100baff84();
            iVar11 = *(int *)((long)puVar17 + 0x144);
          }
          else {
            iVar11 = *(int *)((long)puVar17 + 0x144);
          }
          if (((iVar11 != 0) && (lVar23 = (long)puVar17 + (long)iVar11 + 0x144, lVar23 != 0)) &&
             (bVar8 = FUN_7100d5c470(lVar23), (bVar8 & 1) == 0)) goto LAB_71019fe738;
        }
      }
    }
    bVar7 = FUN_7101cbb4a0((int *)param_2);
    if (!bVar7) {
      FUN_7100eec850((undefined4 *)&local_300,(int *)param_2);
      if (-1 < (long)local_300) {
        lVar23 = *(long *)((uint *)*DAT_7103a59c40 + 2);
        if (lVar23 != 0) {
          uVar9 = (uint)local_300._4_4_;
          if (*(uint *)*DAT_7103a59c40 <= (uint)local_300._4_4_) {
            uVar9 = 0;
          }
          if (*(float *)(lVar23 + (ulong)uVar9 * 0x10 + 4) == (float)local_300) {
            local_408._0_4_ = 3.22299e-44;
            uVar16 = FUN_71019f41e0((int *)&local_300,(int *)&local_408);
            uVar9 = 0;
            if (((int)uVar12 == 0x4f) || ((uVar16 & 1) == 0)) goto switchD_71019fe33c_caseD_1;
            local_408 = (float *)CONCAT44(local_408._4_4_,0x4782c42d);
            piVar15 = (int *)&local_300;
            local_c8._0_4_ = 3;
            piVar20 = (int *)&local_408;
            pfVar29 = (float *)local_c8;
            goto LAB_7101a003c4;
          }
        }
      }
      local_408 = param_1;
      bVar7 = FUN_7100ee8e40((int *)param_2);
      if (bVar7) {
        FUN_7101483c20(&local_300);
        plVar18 = local_300;
        if (local_300 == (long *)0x0) {
          plVar18 = FUN_7100d1d130();
          local_300 = FUN_7100d1d130();
        }
        fVar35 = *(float *)((long)plVar18 + 0x44) - *(float *)(local_300 + 7);
        fVar38 = *(float *)((long)plVar18 + 0x4c) - *(float *)(local_300 + 8);
        fVar37 = fVar38;
        if (fVar38 <= 0.0) {
          fVar37 = -fVar38;
        }
        fVar39 = fVar35;
        if (fVar35 <= 0.0) {
          fVar39 = -fVar35;
        }
        if (fVar39 <= fVar37) {
          iVar11 = (uint)(0.0 < fVar38) << 1;
          iVar10 = 3;
          if (fVar35 <= 0.0) {
            iVar10 = 1;
          }
        }
        else {
          iVar11 = 3;
          if (fVar35 <= 0.0) {
            iVar11 = 1;
          }
          iVar10 = (uint)(0.0 < fVar38) << 1;
        }
        local_c8._4_4_ = iVar10;
        local_c8._0_4_ = iVar11;
        local_300 = (long *)&DAT_710398f9e0;
        local_2f8 = (byte)&local_408;
        bStack_2f7 = (byte)((ulong)&local_408 >> 8);
        bStack_2f6 = (byte)((ulong)&local_408 >> 0x10);
        uStack_2f5 = (undefined1)((ulong)&local_408 >> 0x18);
        uStack_2f4 = (undefined4)((ulong)&local_408 >> 0x20);
        local_2f0 = param_2;
        uVar9 = FUN_71019e8c60((int *)local_c8,&local_300);
        (**(code **)((long)local_300 + 0x18))(&local_300);
        goto switchD_71019fe33c_caseD_1;
      }
      break;
    }
    uVar12 = FUN_71015513c0((long)pfVar29);
    piVar15 = (int *)FUN_7101cba9d0((int *)param_2);
    local_c8._0_8_ = 0x4782c42d7c06f6f8;
    if ((int)uVar12 != 0x4f) {
      if (param_2[10] == 0.0) {
        local_2f8 = 0;
        bStack_2f7 = 0;
        bStack_2f6 = 0;
        uStack_2f5 = 0;
        local_300 = (long *)0x0;
        bVar7 = FUN_7100ee91c0((int *)param_2,piVar15);
        if (((bVar7) && (uVar12 = FUN_7100ee9100(&local_300,(int *)param_2), (uVar12 & 1) != 0)) &&
           (lVar23 = FUN_7101227350(piVar15,0x7c06f6f8), lVar23 != 0)) {
          local_408 = *(float **)(lVar23 + 0x10);
          local_400._0_4_ = *(float *)(lVar23 + 0x18);
          uVar12 = FUN_7100bc84d0((float *)&local_408,piVar15);
          if ((uVar12 & 1) != 0) {
            fVar37 = (float)CONCAT13(uStack_2f5,CONCAT12(bStack_2f6,CONCAT11(bStack_2f7,local_2f8)))
                     - (float)local_400;
            fVar37 = SQRT(fVar37 * fVar37 +
                          ((float)local_300 - (float)local_408) *
                          ((float)local_300 - (float)local_408));
            lVar23 = FUN_7101227350(piVar15,0x4782c42d);
            if (lVar23 != 0) {
              local_408 = *(float **)(lVar23 + 0x10);
              local_400 = (float *)CONCAT44(local_400._4_4_,*(undefined4 *)(lVar23 + 0x18));
              uVar12 = FUN_7100bc84d0((float *)&local_408,piVar15);
              if ((uVar12 & 1) != 0) {
                fVar35 = (float)NEON_fminnm(fVar37,0x7f800000);
                uVar9 = (uint)(INFINITY <= fVar37) << 1;
                fVar38 = (float)CONCAT13(uStack_2f5,
                                         CONCAT12(bStack_2f6,CONCAT11(bStack_2f7,local_2f8))) -
                         (float)local_400;
                fVar38 = SQRT(fVar38 * fVar38 +
                              ((float)local_300 - (float)local_408) *
                              ((float)local_300 - (float)local_408));
                if (fVar38 < fVar35) {
                  uVar9 = 1;
                }
                if (uVar9 != 2) {
                  piVar20 = (int *)local_c8;
                  piVar5 = piVar20 + uVar9;
                  if ((fVar37 < INFINITY) || (fVar38 < fVar35)) goto LAB_71019feb08;
                  goto LAB_71019feb0c;
                }
              }
            }
          }
        }
      }
      break;
    }
    piVar5 = (int *)local_c8;
LAB_71019feb08:
    piVar20 = piVar5;
LAB_71019feb0c:
    pfVar29 = (float *)&local_300;
    local_300 = (long *)CONCAT44(local_300._4_4_,2);
    goto LAB_7101a003c4;
  case 7.00649e-45:
    if (param_2[10] != 7.00649e-45) {
LAB_71019fe48c:
      param_1[0xb] = 0.0;
      param_1[0xc] = 0.0;
      param_1[0x2f] = 0.0;
      param_1[0x30] = 0.0;
      uVar9 = 1;
      fVar37 = *(float *)(DAT_7103a5ba00 + 1);
      *(undefined8 *)(param_1 + 0x77) = *DAT_7103a5ba00;
      pfVar29 = DAT_7103a59b30;
      param_1[0x53] = 0.0;
      param_1[0x54] = 0.0;
      param_1[0x74] = 0.0;
      param_1[0x75] = 0.0;
      param_1[0x76] = 0.0;
      param_1[0x79] = fVar37;
      fVar37 = *pfVar29;
      *param_1 = fVar37;
      plVar18 = DAT_7103a5a248;
      fVar35 = pfVar29[1];
      param_1[0x8e] = 0.0;
      param_1[0x8f] = 0.0;
      param_1[0x8c] = 0.0;
      param_1[0x8d] = 0.0;
      param_1[0x82] = 0.0;
      param_1[0x83] = 0.0;
      param_1[0x80] = 1.0;
      param_1[0x81] = 0.0;
      param_1[0x86] = 0.0;
      param_1[0x87] = 0.0;
      param_1[0x84] = 0.0;
      param_1[0x85] = 1.0;
      *(undefined1 *)(param_1 + 0x91) = 0;
      param_1[1] = fVar35;
      param_1[2] = fVar37;
      param_1[3] = fVar35;
      param_1[4] = 0.0;
      lVar23 = *plVar18;
      fVar37 = *(float *)(plVar18 + 1);
      param_1[0x90] = -NAN;
      param_1[0x7c] = fVar37;
      *(long *)(param_1 + 0x7a) = lVar23;
      param_1[0x8a] = 1.0;
      param_1[0x8b] = 0.0;
      param_1[0x88] = 0.0;
      param_1[0x89] = 0.0;
      goto switchD_71019fe33c_caseD_1;
    }
    lVar23 = *DAT_7103a5a160;
    piVar15 = DAT_7103a5c420;
    if (((lVar23 != 0) && (*(uint *)(lVar23 + 0x808) < 0x100)) &&
       (lVar23 = *(long *)(lVar23 + (ulong)*(uint *)(lVar23 + 0x808) * 8 + 8), lVar23 != 0)) {
      piVar15 = (int *)(lVar23 + 0x150);
    }
    uVar9 = piVar15[1];
    if ((int)uVar9 < 0) {
LAB_71019feb80:
      iVar11 = -1;
    }
    else {
      lVar23 = *(long *)((uint *)*DAT_7103a59c40 + 2);
      if (lVar23 == 0) goto LAB_71019feb80;
      if (*(uint *)*DAT_7103a59c40 <= uVar9) {
        uVar9 = 0;
      }
      if (*(int *)(lVar23 + (ulong)uVar9 * 0x10 + 4) != *piVar15) goto LAB_71019feb80;
      plVar18 = *(long **)(lVar23 + (ulong)uVar9 * 0x10 + 8);
      if (plVar18 == (long *)0x0) {
        plVar18 = FUN_7100bc6230();
      }
      iVar11 = (int)plVar18[4];
    }
    iVar10 = FUN_71015517f4((long)pfVar29);
    FUN_71019fd7d0((long)param_1,iVar11,iVar10);
    goto LAB_7101a004dc;
  case 8.40779e-45:
    if (param_2[10] != 7.00649e-45) goto LAB_71019fe48c;
    uVar9 = FUN_710155127c((long)pfVar29);
    plVar18 = DAT_7103a5a160;
    puVar17 = DAT_7103a59c40;
    piVar15 = (int *)(*(long *)(*DAT_7103a59c30 + 0x19a8e0) + 0x5add0);
    piVar20 = piVar15 + (ulong)uVar9 * 4;
    if (0x27 < uVar9) {
      piVar20 = piVar15;
    }
    iVar11 = *piVar20;
    if (iVar11 != 0) {
      plVar14 = *(long **)(piVar20 + 2);
      plVar1 = plVar14 + iVar11;
      lVar23 = (long)iVar11 * 8;
      do {
        lVar23 = lVar23 + -8;
        lVar33 = *plVar14;
        uVar9 = *(uint *)(lVar33 + 0x404);
        if (-1 < (int)uVar9) {
          lVar25 = *(long *)((uint *)*puVar17 + 2);
          if (lVar25 != 0) {
            if (*(uint *)*puVar17 <= uVar9) {
              uVar9 = 0;
            }
            if (*(int *)(lVar25 + (ulong)uVar9 * 0x10 + 4) == *(int *)(lVar33 + 0x400)) {
              puVar13 = *(undefined8 **)(lVar25 + (ulong)uVar9 * 0x10 + 8);
              if (puVar13 == (undefined8 *)0x0) {
                puVar13 = FUN_7100baff84();
              }
              iVar11 = *(int *)((long)puVar13 + 0x84);
              lVar25 = (long)iVar11 + (long)puVar13 + 0x84;
              if (((iVar11 != 0 && lVar25 != 0) && (lVar28 = *plVar18, lVar28 != 0)) &&
                 (*(int *)(lVar28 + 0x808) == *(int *)(lVar25 + 0x148))) {
                iVar11 = *(int *)(lVar33 + 0x400);
                local_2f8 = 1;
                uVar9 = *(uint *)(lVar33 + 0x404);
                local_300 = *(long **)(lVar33 + 0x400);
                if (plVar14 + 1 == plVar1) goto LAB_71019ff0cc;
                bVar7 = false;
                lVar33 = 8;
                goto LAB_71019ff040;
              }
            }
          }
        }
        plVar14 = plVar14 + 1;
      } while (plVar14 != plVar1);
    }
    break;
  case 9.80909e-45:
    lVar23 = *DAT_7103a5a160;
    piVar15 = DAT_7103a5c420;
    if (((lVar23 != 0) && (*(uint *)(lVar23 + 0x808) < 0x100)) &&
       (lVar23 = *(long *)(lVar23 + (ulong)*(uint *)(lVar23 + 0x808) * 8 + 8), lVar23 != 0)) {
      piVar15 = (int *)(lVar23 + 0x150);
    }
    uVar9 = piVar15[1];
    iVar11 = -1;
    if ((int)uVar9 < 0) {
      fVar37 = param_2[1];
joined_r0x0071019fe9fc:
      if (-1 < (int)fVar37) goto LAB_71019fea10;
LAB_71019ff6c0:
      puVar17 = FUN_7100baff84();
    }
    else {
      lVar23 = *(long *)((uint *)*DAT_7103a59c40 + 2);
      if (lVar23 != 0) {
        if (*(uint *)*DAT_7103a59c40 <= uVar9) {
          uVar9 = 0;
        }
        if (*(int *)(lVar23 + (ulong)uVar9 * 0x10 + 4) == *piVar15) {
          plVar14 = *(long **)(lVar23 + (ulong)uVar9 * 0x10 + 8);
          if (plVar14 == (long *)0x0) {
            plVar14 = FUN_7100bc6230();
          }
          iVar11 = (int)plVar14[4];
          fVar37 = param_2[1];
          goto joined_r0x0071019fe9fc;
        }
      }
      iVar11 = -1;
      fVar37 = param_2[1];
      if ((int)fVar37 < 0) goto LAB_71019ff6c0;
LAB_71019fea10:
      lVar23 = *(long *)((float *)*DAT_7103a59c40 + 2);
      if ((uint)*(float *)*DAT_7103a59c40 <= (uint)fVar37) {
        fVar37 = 0.0;
        if (lVar23 != 0) goto LAB_71019fea30;
        goto LAB_71019ff6c0;
      }
      if (lVar23 == 0) goto LAB_71019ff6c0;
LAB_71019fea30:
      lVar23 = lVar23 + (ulong)(uint)fVar37 * 0x10;
      if ((*(float *)(lVar23 + 4) != *param_2) ||
         (puVar17 = *(undefined8 **)(lVar23 + 8), puVar17 == (undefined8 *)0x0))
      goto LAB_71019ff6c0;
    }
    iVar10 = *(int *)((long)puVar17 + 0x84);
    if ((iVar10 == 0) ||
       (plVar14 = (long *)((long)iVar10 + (long)puVar17 + 0x84), plVar14 == (long *)0x0)) {
      plVar14 = FUN_7100bbfd30();
    }
    if (iVar11 == (int)plVar14[0x29]) {
      FUN_71019fd1e8(param_1,(int *)param_2);
    }
    else {
      lVar23 = *plVar18;
      piVar15 = DAT_7103a5c420;
      if (((lVar23 != 0) && (*(uint *)(lVar23 + 0x808) < 0x100)) &&
         (lVar23 = *(long *)(lVar23 + (ulong)*(uint *)(lVar23 + 0x808) * 8 + 8), lVar23 != 0)) {
        piVar15 = (int *)(lVar23 + 0x150);
      }
      uVar9 = piVar15[1];
      if (-1 < (int)uVar9) {
        lVar23 = *(long *)((uint *)*DAT_7103a59c40 + 2);
        if (lVar23 != 0) {
          if (*(uint *)*DAT_7103a59c40 <= uVar9) {
            uVar9 = 0;
          }
          if (*(int *)(lVar23 + (ulong)uVar9 * 0x10 + 4) == *piVar15) {
            plVar18 = *(long **)(lVar23 + (ulong)uVar9 * 0x10 + 8);
            if (plVar18 == (long *)0x0) {
              plVar18 = FUN_7100bc6230();
            }
            fVar37 = *(float *)(plVar18 + 4);
            uVar9 = 1;
            if (-1 < (int)fVar37) {
              param_1[0xb] = 0.0;
              pfVar29 = DAT_7103a59b30;
              param_1[0xc] = 0.0;
              param_1[0x2f] = 0.0;
              param_1[0x30] = 0.0;
              param_1[0x74] = 0.0;
              puVar17 = DAT_7103a5ba00;
              param_1[0x75] = 0.0;
              param_1[0x76] = 0.0;
              plVar18 = DAT_7103a5a248;
              param_1[0x53] = 0.0;
              param_1[0x54] = 0.0;
              fVar35 = *pfVar29;
              uVar24 = *puVar17;
              fVar38 = *(float *)(puVar17 + 1);
              param_1[0x90] = -NAN;
              *(undefined1 *)(param_1 + 0x91) = 0;
              *param_1 = fVar35;
              param_1[0x82] = 0.0;
              param_1[0x83] = 0.0;
              param_1[0x80] = 1.0;
              param_1[0x81] = 0.0;
              param_1[0x86] = 0.0;
              param_1[0x87] = 0.0;
              param_1[0x84] = 0.0;
              param_1[0x85] = 1.0;
              fVar39 = pfVar29[1];
              *(undefined8 *)(param_1 + 0x77) = uVar24;
              local_300 = (long *)*plVar18;
              param_1[0x79] = fVar38;
              fVar38 = *(float *)(plVar18 + 1);
              param_1[1] = fVar39;
              param_1[2] = fVar35;
              param_1[3] = fVar39;
              param_1[4] = 9.80909e-45;
              param_1[0x7c] = fVar38;
              *(long **)(param_1 + 0x7a) = local_300;
              local_2f8 = SUB41(fVar38,0);
              bStack_2f7 = (byte)((uint)fVar38 >> 8);
              bStack_2f6 = (byte)((uint)fVar38 >> 0x10);
              uStack_2f5 = (undefined1)((uint)fVar38 >> 0x18);
              param_1[0x8a] = 1.0;
              param_1[0x8b] = 0.0;
              param_1[0x88] = 0.0;
              param_1[0x89] = 0.0;
              param_1[0x8e] = 0.0;
              param_1[0x8f] = 0.0;
              param_1[0x8c] = 0.0;
              param_1[0x8d] = 0.0;
              FUN_71019a6340((float *)&local_300,plVar18);
              fVar35 = (float)CONCAT13(uStack_2f5,
                                       CONCAT12(bStack_2f6,CONCAT11(bStack_2f7,local_2f8)));
              param_1[0x90] = fVar37;
              param_1[0x74] = 0.0;
              param_1[0x75] = 0.0;
              param_1[0x8e] = 0.0;
              param_1[0x8f] = 0.0;
              param_1[0x8c] = 0.0;
              param_1[0x8d] = 0.0;
              fVar39 = local_300._4_4_ * 0.0 - (float)local_300;
              fVar37 = fVar35 * -0.0 + (float)local_300 * 0.0;
              param_1[0x76] = 0.0;
              param_1[0x7a] = (float)local_300;
              param_1[0x7b] = local_300._4_4_;
              param_1[0x7c] = fVar35;
              *(undefined1 *)(param_1 + 0x91) = 1;
              fVar38 = fVar35 + local_300._4_4_ * -0.0;
              param_1[0x78] = fVar37;
              param_1[0x79] = fVar39;
              param_1[0x77] = fVar38;
              auVar4 = _DAT_7102ebfe20;
              param_1[0x88] = (float)local_300;
              param_1[0x89] = local_300._4_4_;
              param_1[0x8a] = fVar35;
              param_1[0x8b] = 0.0;
              param_1[0x86] = 0.0;
              param_1[0x87] = 0.0;
              *(ulong *)(param_1 + 0x84) = (ulong)auVar4._8_4_ << 0x20;
              param_1[0x80] = fVar38;
              param_1[0x81] = fVar37;
              param_1[0x82] = fVar39;
              param_1[0x83] = 0.0;
            }
            goto switchD_71019fe33c_caseD_1;
          }
        }
      }
    }
    goto LAB_7101a004dc;
  }
  goto switchD_7101a00174_default;
LAB_71019ff040:
  do {
    if (bVar7) {
      bVar7 = true;
    }
    else {
      uVar32 = *(uint *)(*(long *)((long)plVar14 + lVar33) + 0x404);
      if (-1 < (int)uVar32) {
        lVar25 = *(long *)((uint *)*puVar17 + 2);
        if (lVar25 != 0) {
          if (*(uint *)*puVar17 <= uVar32) {
            uVar32 = 0;
          }
          if (*(int *)(lVar25 + (ulong)uVar32 * 0x10 + 4) ==
              *(int *)(*(long *)((long)plVar14 + lVar33) + 0x400)) {
            puVar13 = *(undefined8 **)(lVar25 + (ulong)uVar32 * 0x10 + 8);
            if (puVar13 == (undefined8 *)0x0) {
              puVar13 = FUN_7100baff84();
            }
            iVar10 = *(int *)((long)puVar13 + 0x84);
            lVar25 = (long)iVar10 + (long)puVar13 + 0x84;
            if ((iVar10 != 0 && lVar25 != 0) && (lVar28 = *plVar18, lVar28 != 0)) {
              bVar7 = *(int *)(lVar28 + 0x808) == *(int *)(lVar25 + 0x148);
              goto LAB_71019ff034;
            }
          }
        }
      }
      bVar7 = false;
    }
LAB_71019ff034:
    lVar23 = lVar23 + -8;
    lVar33 = lVar33 + 8;
  } while (lVar23 != 0);
LAB_71019ff0cc:
  fVar37 = (float)FUN_710155127c((long)pfVar29);
  local_408._0_4_ = fVar37;
  bVar7 = FUN_7101a04a20((uint *)&local_408);
  if (!bVar7) {
    if (-1 < (int)uVar9) {
      lVar23 = *(long *)((uint *)*puVar17 + 2);
      if (lVar23 != 0) {
        if (*(uint *)*puVar17 <= uVar9) {
          uVar9 = 0;
        }
        if (*(int *)(lVar23 + (ulong)uVar9 * 0x10 + 4) == iVar11) {
          iVar11 = FUN_710155127c((long)pfVar29);
          local_408 = (float *)CONCAT44(local_408._4_4_,iVar11);
          uVar12 = FUN_71019f41e0((int *)&local_300,(int *)&local_408);
          if ((uVar12 & 1) != 0) {
LAB_71019ff3d8:
            pfVar21 = (float *)&local_300;
LAB_71019ff3e4:
            uVar9 = FUN_7101a02380((ulong *)param_1,(int *)param_2,(ulong *)pfVar21);
            goto switchD_71019fe33c_caseD_1;
          }
        }
      }
    }
    goto switchD_7101a00174_default;
  }
  FUN_71019fdb0c((undefined8 *)param_1,(int *)&local_300);
LAB_7101a004dc:
  uVar9 = 1;
  goto switchD_71019fe33c_caseD_1;
LAB_71019ff230:
  pfVar21 = (float *)(lVar33 + 0x20);
  goto LAB_71019ff234;
switchD_71019fe33c_caseD_2:
  fVar37 = param_2[1];
  if ((int)fVar37 < 0) {
LAB_7101a0049c:
    puVar17 = FUN_7100baff84();
  }
  else {
    lVar23 = *(long *)((float *)*DAT_7103a59c40 + 2);
    if ((uint)*(float *)*DAT_7103a59c40 <= (uint)fVar37) {
      fVar37 = 0.0;
      if (lVar23 != 0) goto LAB_71019fec88;
      goto LAB_7101a0049c;
    }
    if (lVar23 == 0) goto LAB_7101a0049c;
LAB_71019fec88:
    lVar23 = lVar23 + (ulong)(uint)fVar37 * 0x10;
    if ((*(float *)(lVar23 + 4) != *param_2) ||
       (puVar17 = *(undefined8 **)(lVar23 + 8), puVar17 == (undefined8 *)0x0)) goto LAB_7101a0049c;
  }
  iVar11 = *(int *)((long)puVar17 + 0xbc);
  uVar9 = 0;
  if ((iVar11 == 0) || (lVar23 = (long)iVar11 + (long)puVar17 + 0xbc, lVar23 == 0))
  goto switchD_71019fe33c_caseD_1;
  uVar12 = FUN_71015513c0((long)pfVar29);
  if (((int)uVar12 - 0x1cU < 6) &&
     (bVar8 = FUN_7101cba6f0((int *)(lVar23 + 0x28)), (bVar8 & 1) == 0)) {
    FUN_71019fdd20(param_1);
    goto LAB_7101a004dc;
  }
switchD_71019fe33c_caseD_3:
  fVar37 = param_2[1];
  if ((int)fVar37 < 0) {
LAB_71019fffc4:
    puVar17 = FUN_7100baff84();
  }
  else {
    lVar23 = *(long *)((float *)*DAT_7103a59c40 + 2);
    if ((uint)*(float *)*DAT_7103a59c40 <= (uint)fVar37) {
      fVar37 = 0.0;
      if (lVar23 != 0) goto LAB_71019fe368;
      goto LAB_71019fffc4;
    }
    if (lVar23 == 0) goto LAB_71019fffc4;
LAB_71019fe368:
    lVar23 = lVar23 + (ulong)(uint)fVar37 * 0x10;
    if ((*(float *)(lVar23 + 4) != *param_2) ||
       (puVar17 = *(undefined8 **)(lVar23 + 8), puVar17 == (undefined8 *)0x0)) goto LAB_71019fffc4;
  }
  iVar11 = *(int *)((long)puVar17 + 0xbc);
  uVar9 = 0;
  if ((iVar11 == 0) ||
     (plVar18 = (long *)((long)iVar11 + (long)puVar17 + 0xbc), plVar18 == (long *)0x0))
  goto switchD_71019fe33c_caseD_1;
  uVar12 = FUN_71015513c0((long)pfVar29);
  uVar9 = 0;
  switch(uVar12 & 0xffffffff) {
  case 0:
    plVar18 = (long *)plVar18[5];
    goto LAB_7101a00070;
  default:
    goto switchD_71019fe33c_caseD_1;
  case 0x19:
    plVar18 = (long *)plVar18[6];
LAB_7101a00070:
    local_c8._0_8_ = plVar18;
branch_7101A00084_0x7101a000f8:
    bVar7 = true;
    uVar16 = (ulong)plVar18 >> 0x20;
    fVar37 = 0.0;
    fVar35 = 0.0;
LAB_7101a000f8:
    if ((int)(float)uVar16 < 0) break;
    lVar23 = *(long *)((float *)*DAT_7103a59c40 + 2);
    if (lVar23 == 0) break;
    fVar38 = *(float *)*DAT_7103a59c40;
    if ((uint)fVar38 <= (uint)(float)uVar16) {
      uVar16 = 0;
    }
    if (*(int *)(lVar23 + uVar16 * 0x10 + 4) != (int)plVar18) break;
    if (!bVar7) {
      if (-1 < (int)fVar35) {
        if ((uint)fVar38 <= (uint)fVar35) {
          fVar35 = 0.0;
        }
        if (*(float *)(lVar23 + (ulong)(uint)fVar35 * 0x10 + 4) == fVar37) goto LAB_7101a0014c;
      }
      break;
    }
LAB_7101a0014c:
    uVar12 = FUN_71015513c0((long)pfVar29);
    switch((int)uVar12) {
    case 0x19:
      uVar12 = FUN_71015513c0((long)pfVar29);
      local_300 = (long *)CONCAT44(local_300._4_4_,(int)uVar12);
      uVar9 = FUN_7101a02240((undefined8 *)param_1,(int *)local_c8,(undefined8 *)local_c8,
                             (int *)&local_300);
      goto switchD_71019fe33c_caseD_1;
    case 0x1a:
      local_300 = (long *)CONCAT44(local_300._4_4_,0xb2d2b21f);
      local_308 = 1.4013e-45;
      goto LAB_7101a003b0;
    case 0x1b:
      local_300 = (long *)0x0;
      local_2f8 = 0;
      bStack_2f7 = 0;
      bStack_2f6 = 0;
      uStack_2f5 = 0;
      uStack_2f4 = 0;
      local_2d8 = &local_2d0;
      local_2e8 = &local_2e0;
      local_2d0 = &local_2c8;
      local_2c8 = 0;
      local_2e0 = &local_2d8;
      local_2f0 = (float *)local_2e8;
      if (&local_2c0 != (undefined8 **)0x0) {
        local_2f8 = (byte)&local_2c0;
        bStack_2f7 = (byte)((ulong)&local_2c0 >> 8);
        bStack_2f6 = (byte)((ulong)&local_2c0 >> 0x10);
        uStack_2f5 = (undefined1)((ulong)&local_2c0 >> 0x18);
        uStack_2f4 = (undefined4)((ulong)&local_2c0 >> 0x20);
        local_2f0._4_4_ = (uint)((ulong)&local_2d8 >> 0x20);
        local_2e0 = (undefined8 ***)CONCAT44(local_2f0._4_4_,0x196ed334);
        ppuStack_2b0 = (undefined8 **)0x0;
        if (&local_2d8 != (undefined8 ***)0x0) {
          ppuStack_2b0 = local_2d8;
        }
                    // WARNING: Read-only address (ram,0x007102ebfe20) is written
        plStack_2a8 = (long *)0x0;
        if (ppuStack_2b0 != (undefined8 **)0x0) {
          plStack_2a8 = *ppuStack_2b0;
        }
        *(undefined4 *)ppuStack_2b0 = 0x338b406a;
        local_2f0 = (float *)0x0;
        if (plStack_2a8 != (long *)0x0) {
          local_2f0 = (float *)*plStack_2a8;
        }
        *(undefined4 *)plStack_2a8 = 0xc2f1de9b;
        local_300 = (long *)0x400000004;
        local_2c0 = local_2e8;
        pppuStack_2b8 = &local_2d8;
      }
      local_308 = -2.4528218e-08;
      local_418[0] = 1;
      bVar7 = FUN_71019fc760((int *)param_1,(int *)local_c8,(int *)&local_308,(int *)&local_300,
                             (int *)local_418);
      uVar9 = (uint)bVar7;
      goto switchD_71019fe33c_caseD_1;
    case 0x1c:
      uVar22 = 0x4782c42d;
      break;
    case 0x1d:
      uVar22 = 0x63c82d18;
      break;
    case 0x1e:
      if (!bVar7) {
        uVar22 = 0x25f2eeb0;
        goto LAB_7101a00370;
      }
      goto switchD_7101a00174_default;
    case 0x1f:
      if (bVar7) {
        local_408 = (float *)0xffffffffffffffff;
      }
      uVar22 = 0x9f8f4002;
      goto LAB_7101a00370;
    case 0x20:
      if (bVar7) {
        local_408 = (float *)0xffffffffffffffff;
      }
      uVar22 = 0x77f6b53c;
LAB_7101a00370:
      local_300 = (long *)CONCAT44(local_300._4_4_,uVar22);
      local_308 = 2.8026e-45;
      bVar7 = FUN_71019fc994((int *)param_1,(int *)local_c8,(int *)&local_408,(int *)local_c8,
                             (int *)&local_300,(int *)&local_308);
      uVar9 = (uint)bVar7;
      goto switchD_71019fe33c_caseD_1;
    case 0x21:
      uVar22 = 0x7b8d2997;
      break;
    default:
      goto switchD_7101a00174_default;
    }
    local_300 = (long *)CONCAT44(local_300._4_4_,uVar22);
    local_308 = 2.8026e-45;
LAB_7101a003b0:
    piVar15 = (int *)local_c8;
    piVar20 = (int *)&local_300;
    pfVar29 = &local_308;
LAB_7101a003c4:
    bVar7 = FUN_71019fc670((int *)param_1,piVar15,piVar20,(int *)pfVar29);
    uVar9 = (uint)bVar7;
    goto switchD_71019fe33c_caseD_1;
  case 0x1a:
  case 0x1b:
    puVar19 = (ulong *)FUN_7100e01584((long)plVar18);
LAB_7101a0002c:
    plVar18 = (long *)*puVar19;
    local_c8._0_8_ = plVar18;
    goto branch_7101A00084_0x7101a000f8;
  case 0x1c:
  case 0x1d:
  case 0x21:
    bVar8 = FUN_7101cba6f0((int *)(plVar18 + 5));
    if ((bVar8 & 1) != 0) {
      plVar18 = (long *)plVar18[5];
      goto LAB_7101a00070;
    }
    break;
  case 0x1e:
    bVar8 = FUN_7101cba6f0((int *)(plVar18 + 5));
    if ((bVar8 & 1) == 0) break;
    uVar12 = plVar18[5];
    local_308 = -50936236.0;
LAB_7101a000bc:
    local_c8._0_8_ = uVar12;
    FUN_7101a02100((int *)&local_300,plVar18,(int *)&local_308);
LAB_7101a000d4:
    uVar16 = uVar12 >> 0x20;
    bVar7 = false;
    local_400 = (float *)CONCAT71(local_400._1_7_,1);
    plVar18 = (long *)(uVar12 & 0xffffffff);
    local_408 = (float *)local_300;
    fVar37 = (float)local_300;
    fVar35 = local_300._4_4_;
    goto LAB_7101a000f8;
  case 0x1f:
    bVar8 = FUN_7101cba6f0((int *)(plVar18 + 5));
    if ((bVar8 & 1) != 0) {
      uVar12 = plVar18[5];
      local_308 = 1.924544e-05;
      goto LAB_7101a000bc;
    }
    break;
  case 0x20:
    bVar8 = FUN_7101cba6f0((int *)(plVar18 + 5));
    if ((bVar8 & 1) != 0) {
      uVar12 = plVar18[5];
      local_308 = 5.3192497e-33;
      goto LAB_7101a000bc;
    }
  }
switchD_7101a00174_default:
  uVar9 = 0;
switchD_71019fe33c_caseD_1:
  return uVar9 & 1;
}
