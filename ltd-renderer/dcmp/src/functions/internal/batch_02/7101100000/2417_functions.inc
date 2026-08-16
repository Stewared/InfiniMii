


void FUN_71011ebbd4(long param_1)

{
  float *pfVar1;
  int iVar2;
  undefined8 *puVar3;
  int *piVar4;
  long lVar5;
  uint uVar6;
  undefined8 uVar7;
  
  if ((((((uint)*(ulong *)(param_1 + 0x38) >> 1 & 1) != 0) &&
       (pfVar1 = (float *)(*(ulong *)(param_1 + 0x38) & 0xfffffffffffffffc), pfVar1 != (float *)0x0)
       ) && ((*pfVar1 != 0.0 || ((pfVar1[1] != 0.0 || (pfVar1[2] != 0.0)))))) &&
     (iVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a094a8 + 0x54)), iVar2 < 0)) {
    thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a094a8 + 0x54),0x80000001);
  }
  puVar3 = (undefined8 *)(*(ulong *)(param_1 + 0x38) & 0xfffffffffffffffc);
  *(undefined4 *)(puVar3 + 1) = 0;
  *puVar3 = 0;
  piVar4 = (int *)**(undefined8 **)(param_1 + 0x30);
  if ((piVar4 != (int *)0x0) && (uVar6 = piVar4[1], -1 < (int)uVar6)) {
    if (*DAT_71040e7d48 <= uVar6) {
      uVar6 = 0;
    }
    if ((((*(long *)(DAT_71040e7d48 + 2) != 0) &&
         (lVar5 = *(long *)(DAT_71040e7d48 + 2) + (ulong)uVar6 * 0x10,
         *(int *)(lVar5 + 4) == *piVar4)) && (lVar5 = *(long *)(lVar5 + 8), lVar5 != 0)) &&
       (piVar4 = (int *)(lVar5 + 0x84), iVar2 = *piVar4, lVar5 = (long)iVar2 + (long)piVar4,
       iVar2 != 0 && lVar5 != 0)) {
      if ((((((uint)*(ulong *)(param_1 + 0x38) >> 1 & 1) != 0) &&
           (pfVar1 = (float *)(*(ulong *)(param_1 + 0x38) & 0xfffffffffffffffc),
           pfVar1 != (float *)0x0)) &&
          ((*pfVar1 != *(float *)(lVar5 + 0x11c) ||
           ((pfVar1[1] != *(float *)(lVar5 + 0x120) || (pfVar1[2] != *(float *)(lVar5 + 0x124)))))))
         && (iVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a094a8 + 0x54)), iVar2 < 0)) {
        thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a094a8 + 0x54),0x80000001);
      }
      puVar3 = (undefined8 *)(*(ulong *)(param_1 + 0x38) & 0xfffffffffffffffc);
      uVar7 = *(undefined8 *)(lVar5 + 0x11c);
      *(undefined4 *)(puVar3 + 1) = *(undefined4 *)(lVar5 + 0x124);
      *puVar3 = uVar7;
    }
  }
  return;
}



void FUN_71011ebd74(long *param_1)

{
  uint uVar1;
  long lVar2;
  undefined8 in_x5;
  undefined8 in_x6;
  undefined8 in_x7;
  long lVar3;
  char *local_38;
  byte local_14 [4];
  
  local_38 = "Prop_GetOnUpdate";
  FUN_7101012e40(param_1,(long *)&local_38,param_1 + 5,1,0,in_x5,in_x6,in_x7);
  local_38 = "ActorHandle";
  FUN_710101275c(param_1,(long *)&local_38,param_1 + 6,1,(long *)0x0);
  local_14[0] = 0;
  local_38 = "Position";
  lVar3 = *(long *)(param_1[1] + 0x10);
  lVar2 = (**(code **)(*param_1 + 0xa0))(param_1);
  uVar1 = FUN_7102963610(lVar3,(long *)&local_38,lVar2 + 0x30,param_1,local_14,(undefined1 *)0x0,
                         in_x6,in_x7);
  FUN_7102962d38((long)param_1,(ulong *)(param_1 + 7),uVar1,(uint)local_14[0]);
  return;
}



void FUN_71011ebe40(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if ((DAT_710406a1c0 & 1) == 0) {
    iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a1c0);
    if (iVar1 != 0) {
      DAT_710406a1b8 = DAT_7103a60348 + 0x10;
      thunk_EXT_FUN_02e95df0(&DAT_710406a1c0);
    }
  }
  if (param_2 != &DAT_710406a1b8) {
    FUN_710101133c(param_1,param_2);
    return;
  }
  return;
}



undefined8 * FUN_71011ebecc(void)

{
  int iVar1;
  
  if (((DAT_710406a1c0 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a1c0), iVar1 != 0))
  {
    DAT_710406a1b8 = DAT_7103a60348 + 0x10;
    thunk_EXT_FUN_02e95df0(&DAT_710406a1c0);
  }
  return &DAT_710406a1b8;
}



void FUN_71011ebf28(long *param_1)

{
  long *plVar1;
  
  *param_1 = DAT_7103a72c80 + 0x10;
  if ((long *)param_1[2] != (long *)0x0) {
    (**(code **)(*(long *)param_1[2] + 8))();
  }
  if (DAT_7105a06420 != 0) {
    plVar1 = FUN_71024ef490(DAT_7105a06420,param_1);
    if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071011ebf8c. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
      return;
    }
    return;
  }
  FUN_71005fbbd0((long)param_1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_71011ebfd0(void)

{
  int iVar1;
  
  DAT_710406a1b0 = (undefined8 *)0x0;
  DAT_710406a198 = 0x5afd033;
  DAT_710406a1a0 = FUN_71011ebb38;
  DAT_710406a1a8 = (undefined8 *)0x0;
  if (((DAT_710405c890 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710405c890), iVar1 != 0))
  {
    DAT_710405c878 = &DAT_710405c878;
    DAT_710405c880 = &DAT_710405c878;
    _DAT_710405c888 = 0xffffffff00000000;
    thunk_EXT_FUN_02e95df0(DAT_7103a5fe28);
  }
  DAT_710406a1a8 = DAT_710405c878;
  DAT_710405c88c = 0x10;
  DAT_710405c878 = &DAT_710406a1a8;
  DAT_710406a1b0 = &DAT_710405c878;
  if (DAT_710406a1a8 != (undefined8 *)0x0) {
    DAT_710406a1a8[1] = &DAT_710406a1a8;
  }
  _DAT_710405c888 = CONCAT44(DAT_710405c88c,DAT_710405c888 + 1);
  return;
}



void FUN_71011ec088(long *param_1)

{
  long lVar1;
  long lVar2;
  undefined8 *puVar3;
  
  lVar1 = DAT_7105a06420;
  if (DAT_7105a06420 == 0) {
    puVar3 = (undefined8 *)FUN_71005fbcb0(8,0x40);
  }
  else {
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar3 = (undefined8 *)(lVar1 + 8);
      if (lVar2 != 0) {
        puVar3 = (undefined8 *)(lVar2 + 0x88);
      }
      param_1 = (long *)*puVar3;
    }
    puVar3 = (undefined8 *)(**(code **)(*param_1 + 0x30))(param_1,0x40,8);
  }
  puVar3[2] = 0;
  puVar3[3] = 0;
  *(undefined1 *)((long)puVar3 + 0x1e) = 0xff;
  *puVar3 = &DAT_71038fce10;
  puVar3[1] = 0;
  puVar3[4] = 0;
  puVar3[5] = 0xffffffffffffffff;
  puVar3[6] = 0;
  puVar3[7] = 0;
  return;
}



void FUN_71011ec660(long *param_1)

{
  uint uVar1;
  long lVar2;
  undefined8 in_x7;
  undefined *puVar3;
  long lVar4;
  char *local_30;
  char local_24 [4];
  
  local_30 = "ActorHandle";
  FUN_710101275c(param_1,(long *)&local_30,param_1 + 6,1,(long *)0x0);
  local_24[0] = '\0';
  local_30 = "DoorActor";
  lVar4 = *(long *)(param_1[1] + 0x10);
  lVar2 = (**(code **)(*param_1 + 0xa0))(param_1);
  uVar1 = FUN_7102963780(lVar4,(long *)&local_30,lVar2 + 0x30,param_1,local_24,(undefined1 *)0x0,
                         (long *)0x0,in_x7);
  if ((int)uVar1 < 0) {
    puVar3 = &DAT_7105a09400;
  }
  else {
    param_1[7] = 0;
    lVar2 = 0;
    if ((long *)param_1[2] != (long *)0x0) {
      lVar2 = (**(code **)(*(long *)param_1[2] + 0x10))();
    }
    puVar3 = (undefined *)(lVar2 + (ulong)uVar1 & 0xfffffffffffffffc);
  }
  param_1[7] = (long)puVar3;
  if (local_24[0] != '\0') {
    puVar3 = (undefined *)((ulong)puVar3 | 1);
    param_1[7] = (long)puVar3;
  }
  if ((*(byte *)(*(long *)(param_1[1] + 8) + 0x1ac) & 1) != 0) {
    param_1[7] = (ulong)puVar3 | 2;
  }
  return;
}



void FUN_71011ec74c(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if ((DAT_710406a1f0 & 1) == 0) {
    iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a1f0);
    if (iVar1 != 0) {
      DAT_710406a1e8 = DAT_7103a60348 + 0x10;
      thunk_EXT_FUN_02e95df0(&DAT_710406a1f0);
    }
  }
  if (param_2 != &DAT_710406a1e8) {
    FUN_710101133c(param_1,param_2);
    return;
  }
  return;
}



undefined8 * FUN_71011ec7d8(void)

{
  int iVar1;
  
  if (((DAT_710406a1f0 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a1f0), iVar1 != 0))
  {
    DAT_710406a1e8 = DAT_7103a60348 + 0x10;
    thunk_EXT_FUN_02e95df0(&DAT_710406a1f0);
  }
  return &DAT_710406a1e8;
}



void FUN_71011ec834(long *param_1)

{
  long *plVar1;
  
  *param_1 = DAT_7103a72c80 + 0x10;
  if ((long *)param_1[2] != (long *)0x0) {
    (**(code **)(*(long *)param_1[2] + 8))();
  }
  if (DAT_7105a06420 != 0) {
    plVar1 = FUN_71024ef490(DAT_7105a06420,param_1);
    if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071011ec898. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
      return;
    }
    return;
  }
  FUN_71005fbbd0((long)param_1);
  return;
}



bool FUN_71011ec8d0(undefined8 param_1,int *param_2)

{
  uint uVar1;
  int iVar2;
  bool bVar3;
  undefined8 *puVar4;
  long lVar5;
  uint *puVar6;
  
  uVar1 = param_2[1];
  if ((-1 < (int)uVar1) && (lVar5 = *(long *)(DAT_71040e7d48 + 2), lVar5 != 0)) {
    if (*DAT_71040e7d48 <= uVar1) {
      uVar1 = 0;
    }
    if (*(int *)(lVar5 + (ulong)uVar1 * 0x10 + 4) == *param_2) {
      puVar4 = *(undefined8 **)(lVar5 + (ulong)uVar1 * 0x10 + 8);
      if (puVar4 == (undefined8 *)0x0) {
        puVar4 = FUN_7100baff84();
      }
      iVar2 = *(int *)((long)puVar4 + 0x8c);
      lVar5 = (long)iVar2 + (long)puVar4 + 0x8c;
      if (iVar2 != 0 && lVar5 != 0) {
        puVar6 = (uint *)(lVar5 + 0x30);
        goto LAB_71011ec93c;
      }
    }
  }
  puVar6 = &DAT_71032b5460;
LAB_71011ec93c:
  bVar3 = FUN_7100ef07b0(*puVar6);
  return bVar3;
}



void FUN_71011ec968(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071011ec9a8. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_71011ec9d0(void)

{
  int iVar1;
  
  DAT_710406a1e0 = (undefined8 *)0x0;
  DAT_710406a1c8 = 0xd9307cc2;
  DAT_710406a1d0 = FUN_71011ec088;
  DAT_710406a1d8 = (undefined8 *)0x0;
  if (((DAT_710405c890 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710405c890), iVar1 != 0))
  {
    DAT_710405c878 = &DAT_710405c878;
    DAT_710405c880 = &DAT_710405c878;
    _DAT_710405c888 = 0xffffffff00000000;
    thunk_EXT_FUN_02e95df0(DAT_7103a5fe28);
  }
  DAT_710406a1d8 = DAT_710405c878;
  DAT_710405c88c = 0x10;
  DAT_710405c878 = &DAT_710406a1d8;
  DAT_710406a1e0 = &DAT_710405c878;
  if (DAT_710406a1d8 != (undefined8 *)0x0) {
    DAT_710406a1d8[1] = &DAT_710406a1d8;
  }
  _DAT_710405c888 = CONCAT44(DAT_710405c88c,DAT_710405c888 + 1);
  return;
}



void FUN_71011eca88(long *param_1)

{
  long lVar1;
  long lVar2;
  undefined8 *puVar3;
  
  lVar1 = DAT_7105a06420;
  if (DAT_7105a06420 == 0) {
    puVar3 = (undefined8 *)FUN_71005fbcb0(8,0x48);
  }
  else {
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar3 = (undefined8 *)(lVar1 + 8);
      if (lVar2 != 0) {
        puVar3 = (undefined8 *)(lVar2 + 0x88);
      }
      param_1 = (long *)*puVar3;
    }
    puVar3 = (undefined8 *)(**(code **)(*param_1 + 0x30))(param_1,0x48,8);
  }
  puVar3[8] = 0;
  puVar3[2] = 0;
  puVar3[3] = 0;
  *(undefined1 *)((long)puVar3 + 0x1e) = 0xff;
  *puVar3 = &DAT_71038fcf80;
  puVar3[1] = 0;
  puVar3[4] = 0;
  puVar3[5] = 0xffffffffffffffff;
  puVar3[6] = 0;
  puVar3[7] = 0;
  return;
}



void FUN_71011ecb28(long param_1)

{
  long lVar1;
  int iVar2;
  undefined8 *puVar3;
  ulong uVar4;
  uint uVar5;
  undefined8 *puVar6;
  
  puVar3 = *(undefined8 **)(param_1 + 0x30);
  if (puVar3 == (undefined8 *)0x0 || puVar3 == (undefined8 *)&DAT_7105a09400) {
    return;
  }
  uVar5 = ((int *)*puVar3)[1];
  if (-1 < (int)uVar5) {
    if (*DAT_71040e7d48 <= uVar5) {
      uVar5 = 0;
    }
    if (((*(long *)(DAT_71040e7d48 + 2) != 0) &&
        (lVar1 = *(long *)(DAT_71040e7d48 + 2) + (ulong)uVar5 * 0x10,
        *(int *)(lVar1 + 4) == *(int *)*puVar3)) &&
       (puVar3 = *(undefined8 **)(lVar1 + 8), puVar3 != (undefined8 *)0x0)) {
      iVar2 = *(int *)(puVar3 + 0x30);
      goto joined_r0x0071011ecbbc;
    }
  }
  puVar3 = FUN_7100baff84();
  iVar2 = *(int *)(puVar3 + 0x30);
joined_r0x0071011ecbbc:
  if ((iVar2 != 0) && (lVar1 = (long)puVar3 + (long)iVar2 + 0x180, lVar1 != 0)) {
    uVar5 = *(uint *)(*(ulong *)(param_1 + 0x38) & 0xfffffffffffffffc);
    puVar3 = (undefined8 *)&DAT_71040104c0;
    if ((-1 < (int)uVar5) && ((int)uVar5 < *(int *)(lVar1 + 0x30))) {
      puVar3 = (undefined8 *)(*(long *)(*(long *)(lVar1 + 0x38) + (ulong)uVar5 * 8) + 0x20);
    }
    puVar6 = (undefined8 *)(param_1 + 0x28);
    *puVar6 = *puVar3;
    uVar4 = *(ulong *)(param_1 + 0x40);
    if ((((uVar4 & 1) != 0) &&
        (puVar3 = (undefined8 *)(uVar4 & 0xfffffffffffffffc), puVar3 != (undefined8 *)0x0)) &&
       (puVar3 != (undefined8 *)&DAT_7105a09400)) {
      if (((((uint)uVar4 >> 1 & 1) != 0) && ((undefined8 *)*puVar3 != puVar6)) &&
         (iVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a094a8 + 0x54)), iVar2 < 0)) {
        thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a094a8 + 0x54),0x80000001);
      }
      *(undefined8 **)(*(ulong *)(param_1 + 0x40) & 0xfffffffffffffffc) = puVar6;
    }
  }
  return;
}



void FUN_71011ecc7c(long *param_1)

{
  uint uVar1;
  long lVar2;
  undefined4 *puVar3;
  undefined8 uVar4;
  undefined *puVar5;
  long lVar6;
  char *local_48;
  uint local_40;
  ushort local_3c [2];
  ushort local_38 [2];
  uint local_34;
  
  local_48 = "ActorHandle";
  FUN_710101275c(param_1,(long *)&local_48,param_1 + 6,1,(long *)0x0);
  local_34 = 0;
  local_48 = "Index";
  local_38[0] = 0xffff;
  local_3c[0] = 0xffff;
  lVar6 = *(long *)(param_1[1] + 0x10);
  local_40 = 0;
  lVar2 = (**(code **)(*param_1 + 0xa0))(param_1);
  puVar3 = FUN_7101011c30(lVar6,(long *)&local_48,(int *)(lVar2 + 0x30),local_38,local_3c,&local_34,
                          (long)param_1,(undefined1 *)0x0,&local_40);
  uVar4 = 0;
  FUN_7101011e70((long)param_1,(long *)&local_48,(ulong *)(param_1 + 7),0,(ulong)local_34,
                 (ulong)local_38[0],(ulong)local_3c[0],0,(ulong)puVar3,local_40);
  local_48 = "ActorHandle";
  local_34 = local_34 & 0xffffff00;
  lVar6 = *(long *)(param_1[1] + 0x10);
  lVar2 = (**(code **)(*param_1 + 0xa0))(param_1);
  uVar1 = FUN_7102963780(lVar6,(long *)&local_48,lVar2 + 0x30,param_1,(undefined1 *)&local_34,
                         (undefined1 *)0x0,(long *)0x0,uVar4);
  if ((int)uVar1 < 0) {
    puVar5 = &DAT_7105a09400;
  }
  else {
    param_1[8] = 0;
    lVar2 = 0;
    if ((long *)param_1[2] != (long *)0x0) {
      lVar2 = (**(code **)(*(long *)param_1[2] + 0x10))();
    }
    puVar5 = (undefined *)(lVar2 + (ulong)uVar1 & 0xfffffffffffffffc);
  }
  param_1[8] = (long)puVar5;
  if ((char)local_34 != '\0') {
    puVar5 = (undefined *)((ulong)puVar5 | 1);
    param_1[8] = (long)puVar5;
  }
  if ((*(byte *)(*(long *)(param_1[1] + 8) + 0x1ac) & 1) != 0) {
    param_1[8] = (ulong)puVar5 | 2;
  }
  return;
}



void FUN_71011ecdfc(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if ((DAT_710406a220 & 1) == 0) {
    iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a220);
    if (iVar1 != 0) {
      DAT_710406a218 = DAT_7103a60348 + 0x10;
      thunk_EXT_FUN_02e95df0(&DAT_710406a220);
    }
  }
  if (param_2 != &DAT_710406a218) {
    FUN_710101133c(param_1,param_2);
    return;
  }
  return;
}



undefined8 * FUN_71011ece88(void)

{
  int iVar1;
  
  if (((DAT_710406a220 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a220), iVar1 != 0))
  {
    DAT_710406a218 = DAT_7103a60348 + 0x10;
    thunk_EXT_FUN_02e95df0(&DAT_710406a220);
  }
  return &DAT_710406a218;
}



void FUN_71011ecee4(long *param_1)

{
  long *plVar1;
  
  *param_1 = DAT_7103a72c80 + 0x10;
  if ((long *)param_1[2] != (long *)0x0) {
    (**(code **)(*(long *)param_1[2] + 8))();
  }
  if (DAT_7105a06420 != 0) {
    plVar1 = FUN_71024ef490(DAT_7105a06420,param_1);
    if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071011ecf48. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
      return;
    }
    return;
  }
  FUN_71005fbbd0((long)param_1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_71011ecf80(void)

{
  int iVar1;
  
  DAT_710406a210 = (undefined8 *)0x0;
  DAT_710406a1f8 = 0x34267cac;
  DAT_710406a200 = FUN_71011eca88;
  DAT_710406a208 = (undefined8 *)0x0;
  if (((DAT_710405c890 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710405c890), iVar1 != 0))
  {
    DAT_710405c878 = &DAT_710405c878;
    DAT_710405c880 = &DAT_710405c878;
    _DAT_710405c888 = 0xffffffff00000000;
    thunk_EXT_FUN_02e95df0(DAT_7103a5fe28);
  }
  DAT_710406a208 = DAT_710405c878;
  DAT_710405c88c = 0x10;
  DAT_710405c878 = &DAT_710406a208;
  DAT_710406a210 = &DAT_710405c878;
  if (DAT_710406a208 != (undefined8 *)0x0) {
    DAT_710406a208[1] = &DAT_710406a208;
  }
  _DAT_710405c888 = CONCAT44(DAT_710405c88c,DAT_710405c888 + 1);
  return;
}



void FUN_71011ed038(long *param_1)

{
  long lVar1;
  long lVar2;
  undefined8 *puVar3;
  
  lVar1 = DAT_7105a06420;
  if (DAT_7105a06420 == 0) {
    puVar3 = (undefined8 *)FUN_71005fbcb0(8,0x38);
  }
  else {
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar3 = (undefined8 *)(lVar1 + 8);
      if (lVar2 != 0) {
        puVar3 = (undefined8 *)(lVar2 + 0x88);
      }
      param_1 = (long *)*puVar3;
    }
    puVar3 = (undefined8 *)(**(code **)(*param_1 + 0x30))(param_1,0x38,8);
  }
  puVar3[6] = 0;
  puVar3[2] = 0;
  puVar3[3] = 0;
  *(undefined1 *)((long)puVar3 + 0x1e) = 0xff;
  *puVar3 = &DAT_71038fd0b8;
  puVar3[1] = 0;
  puVar3[4] = 0;
  puVar3[5] = 0;
  return;
}



int * FUN_71011ed0d0(long *param_1)

{
  char *pcVar1;
  char cVar2;
  uint uVar3;
  undefined8 *puVar4;
  long lVar5;
  int *piVar6;
  long lVar7;
  undefined8 local_90;
  undefined8 local_88;
  undefined1 *puStack_80;
  undefined4 local_78;
  undefined1 local_74 [63];
  undefined1 local_35;
  
  puVar4 = (undefined8 *)param_1[5];
  if (puVar4 == (undefined8 *)0x0 || puVar4 == (undefined8 *)&DAT_7105a09400) {
    lVar7 = *(long *)(*(long *)(param_1[1] + 8) + 0x1d8);
    (**(code **)(*param_1 + 0x90))(param_1);
    lVar5 = *(long *)(*(long *)(param_1[1] + 0x10) + 0x48) +
            (ulong)*(ushort *)((long)param_1 + 0x1c) * 0x3c;
    puStack_80 = local_74;
    local_90 = *(undefined8 *)(lVar5 + 0x2c);
    local_88 = *(undefined8 *)(lVar5 + 0x34);
    local_35 = 0;
    local_74[0] = 0;
    local_78 = 0x40;
    uVar3 = FUN_7100f700b0((long *)&puStack_80,0x7103176cba,(uint *)&local_90);
    piVar6 = (int *)(ulong)uVar3;
    for (lVar5 = *(long *)(lVar7 + 0x30); lVar5 != lVar7 + 0x28; lVar5 = *(long *)(lVar5 + 8)) {
      *(uint *)(*(long *)(lVar5 + 0x10) + 0x20) = *(uint *)(*(long *)(lVar5 + 0x10) + 0x20) | 4;
    }
  }
  else {
    piVar6 = (int *)*puVar4;
    if (piVar6 == (int *)0x0) {
      lVar7 = *(long *)(*(long *)(param_1[1] + 8) + 0x1d8);
      (**(code **)(*param_1 + 0x90))(param_1);
      lVar5 = *(long *)(*(long *)(param_1[1] + 0x10) + 0x48) +
              (ulong)*(ushort *)((long)param_1 + 0x1c) * 0x3c;
      puStack_80 = local_74;
      local_90 = *(undefined8 *)(lVar5 + 0x2c);
      local_88 = *(undefined8 *)(lVar5 + 0x34);
      local_35 = 0;
      local_74[0] = 0;
      local_78 = 0x40;
      uVar3 = FUN_7100f700b0((long *)&puStack_80,0x7103176cba,(uint *)&local_90);
      piVar6 = (int *)(ulong)uVar3;
      for (lVar5 = *(long *)(lVar7 + 0x30); lVar5 != lVar7 + 0x28; lVar5 = *(long *)(lVar5 + 8)) {
        *(uint *)(*(long *)(lVar5 + 0x10) + 0x20) = *(uint *)(*(long *)(lVar5 + 0x10) + 0x20) | 4;
      }
    }
    else {
      uVar3 = piVar6[1];
      if ((-1 < (int)uVar3) && (lVar5 = *(long *)(DAT_71040e7d48 + 2), lVar5 != 0)) {
        if (*DAT_71040e7d48 <= uVar3) {
          uVar3 = 0;
        }
        if (*(int *)(lVar5 + (ulong)uVar3 * 0x10 + 4) == *piVar6) {
          puVar4 = *(undefined8 **)(lVar5 + (ulong)uVar3 * 0x10 + 8);
          if (puVar4 == (undefined8 *)0x0) {
            puVar4 = FUN_7100baff84();
          }
          piVar6 = (int *)((long)puVar4 + 0x54);
          lVar5 = (long)*piVar6 + (long)piVar6;
          if (*piVar6 == 0 || lVar5 == 0) {
            if (((((uint)param_1[6] >> 1 & 1) != 0) &&
                (pcVar1 = (char *)(param_1[6] & 0xfffffffffffffffc), pcVar1 != (char *)0x0)) &&
               ((*pcVar1 != '\0' &&
                (piVar6 = (int *)thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a094a8 + 0x54)),
                (int)piVar6 < 0)))) {
              piVar6 = (int *)thunk_EXT_FUN_02e95df0
                                        (*(undefined4 *)(DAT_7105a094a8 + 0x54),0x80000001);
            }
            *(undefined1 *)(param_1[6] & 0xfffffffffffffffc) = 0;
            return piVar6;
          }
          cVar2 = *(char *)(lVar5 + 0x270);
          if ((((((uint)param_1[6] >> 1 & 1) != 0) &&
               (pcVar1 = (char *)(param_1[6] & 0xfffffffffffffffc), pcVar1 != (char *)0x0)) &&
              (*pcVar1 != cVar2)) &&
             (piVar6 = (int *)thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a094a8 + 0x54)),
             (int)piVar6 < 0)) {
            piVar6 = (int *)thunk_EXT_FUN_02e95df0
                                      (*(undefined4 *)(DAT_7105a094a8 + 0x54),0x80000001);
          }
          *(char *)(param_1[6] & 0xfffffffffffffffc) = cVar2;
          return piVar6;
        }
      }
      lVar7 = *(long *)(*(long *)(param_1[1] + 8) + 0x1d8);
      (**(code **)(*param_1 + 0x90))(param_1);
      lVar5 = *(long *)(*(long *)(param_1[1] + 0x10) + 0x48) +
              (ulong)*(ushort *)((long)param_1 + 0x1c) * 0x3c;
      puStack_80 = local_74;
      local_90 = *(undefined8 *)(lVar5 + 0x2c);
      local_88 = *(undefined8 *)(lVar5 + 0x34);
      local_35 = 0;
      local_74[0] = 0;
      local_78 = 0x40;
      uVar3 = FUN_7100f700b0((long *)&puStack_80,0x7103176cba,(uint *)&local_90);
      piVar6 = (int *)(ulong)uVar3;
      for (lVar5 = *(long *)(lVar7 + 0x30); lVar5 != lVar7 + 0x28; lVar5 = *(long *)(lVar5 + 8)) {
        *(uint *)(*(long *)(lVar5 + 0x10) + 0x20) = *(uint *)(*(long *)(lVar5 + 0x10) + 0x20) | 4;
      }
    }
  }
  if ((*(uint *)(lVar7 + 0x20) >> 2 & 1) == 0) {
    *(uint *)(lVar7 + 0x20) = *(uint *)(lVar7 + 0x20) | 4;
  }
  return piVar6;
}



void FUN_71011ed580(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if ((DAT_710406a250 & 1) == 0) {
    iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a250);
    if (iVar1 != 0) {
      DAT_710406a248 = DAT_7103a60348 + 0x10;
      thunk_EXT_FUN_02e95df0(&DAT_710406a250);
    }
  }
  if (param_2 != &DAT_710406a248) {
    FUN_710101133c(param_1,param_2);
    return;
  }
  return;
}



undefined8 * FUN_71011ed60c(void)

{
  int iVar1;
  
  if (((DAT_710406a250 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a250), iVar1 != 0))
  {
    DAT_710406a248 = DAT_7103a60348 + 0x10;
    thunk_EXT_FUN_02e95df0(&DAT_710406a250);
  }
  return &DAT_710406a248;
}



void FUN_71011ed668(long *param_1)

{
  long *plVar1;
  
  *param_1 = DAT_7103a72c80 + 0x10;
  if ((long *)param_1[2] != (long *)0x0) {
    (**(code **)(*(long *)param_1[2] + 8))();
  }
  if (DAT_7105a06420 != 0) {
    plVar1 = FUN_71024ef490(DAT_7105a06420,param_1);
    if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071011ed6cc. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
      return;
    }
    return;
  }
  FUN_71005fbbd0((long)param_1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_71011ed710(void)

{
  int iVar1;
  
  DAT_710406a240 = (undefined8 *)0x0;
  DAT_710406a228 = 0x4081199d;
  DAT_710406a230 = FUN_71011ed038;
  DAT_710406a238 = (undefined8 *)0x0;
  if (((DAT_710405c890 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710405c890), iVar1 != 0))
  {
    DAT_710405c878 = &DAT_710405c878;
    DAT_710405c880 = &DAT_710405c878;
    _DAT_710405c888 = 0xffffffff00000000;
    thunk_EXT_FUN_02e95df0(DAT_7103a5fe28);
  }
  DAT_710406a238 = DAT_710405c878;
  DAT_710405c88c = 0x10;
  DAT_710405c878 = &DAT_710406a238;
  DAT_710406a240 = &DAT_710405c878;
  if (DAT_710406a238 != (undefined8 *)0x0) {
    DAT_710406a238[1] = &DAT_710406a238;
  }
  _DAT_710405c888 = CONCAT44(DAT_710405c88c,DAT_710405c888 + 1);
  return;
}



void FUN_71011ed7c8(long *param_1)

{
  long lVar1;
  long lVar2;
  undefined8 *puVar3;
  
  lVar1 = DAT_7105a06420;
  if (DAT_7105a06420 == 0) {
    puVar3 = (undefined8 *)FUN_71005fbcb0(8,0x40);
  }
  else {
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar3 = (undefined8 *)(lVar1 + 8);
      if (lVar2 != 0) {
        puVar3 = (undefined8 *)(lVar2 + 0x88);
      }
      param_1 = (long *)*puVar3;
    }
    puVar3 = (undefined8 *)(**(code **)(*param_1 + 0x30))(param_1,0x40,8);
  }
  puVar3[2] = 0;
  puVar3[3] = 0;
  *(undefined1 *)((long)puVar3 + 0x1e) = 0xff;
  *puVar3 = &DAT_71038fd1f0;
  puVar3[1] = 0;
  puVar3[4] = 0;
  puVar3[5] = 0;
  puVar3[6] = 0;
  puVar3[7] = 0;
  return;
}



void FUN_71011ed860(long param_1)

{
  long *plVar1;
  int iVar2;
  ulong uVar3;
  int *piVar4;
  undefined4 *puVar5;
  undefined8 *puVar6;
  long lVar7;
  
  lVar7 = **(long **)(param_1 + 0x30);
  if (lVar7 != 0) {
    uVar3 = *(ulong *)(param_1 + 0x38);
    if ((((uVar3 & 1) != 0) &&
        (plVar1 = (long *)(uVar3 & 0xfffffffffffffffc), plVar1 != (long *)0x0)) &&
       (plVar1 != (long *)&DAT_7105a09400)) {
      if (((((uint)uVar3 >> 1 & 1) != 0) && (*plVar1 != lVar7)) &&
         (iVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a094a8 + 0x54)), iVar2 < 0)) {
        thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a094a8 + 0x54),0x80000001);
      }
      *(long *)(*(ulong *)(param_1 + 0x38) & 0xfffffffffffffffc) = lVar7;
    }
    puVar5 = (undefined4 *)**(undefined8 **)(param_1 + 0x28);
    if ((puVar5 != (undefined4 *)0x0) &&
       (piVar4 = *(int **)(*(ulong *)(param_1 + 0x38) & 0xfffffffffffffffc), *piVar4 < piVar4[1])) {
      puVar6 = *(undefined8 **)(piVar4 + 4);
      if (puVar6 != (undefined8 *)0x0) {
        *(undefined8 *)(piVar4 + 4) = *puVar6;
      }
      *puVar6 = 0xffffffffffffffff;
      *(undefined4 *)puVar6 = *puVar5;
      *(undefined4 *)((long)puVar6 + 4) = puVar5[1];
      if (*piVar4 < piVar4[1]) {
        *(undefined8 **)(*(long *)(piVar4 + 2) + (long)*piVar4 * 8) = puVar6;
        *piVar4 = *piVar4 + 1;
      }
    }
  }
  return;
}



void FUN_71011ed96c(long *param_1)

{
  uint uVar1;
  long lVar2;
  undefined8 in_x7;
  undefined *puVar3;
  long lVar4;
  char *local_30;
  char local_24 [4];
  
  local_30 = "ActorHandle";
  FUN_710101275c(param_1,(long *)&local_30,param_1 + 5,1,(long *)0x0);
  local_30 = "ActorHandleList";
  FUN_710101275c(param_1,(long *)&local_30,param_1 + 6,1,(long *)0x0);
  local_30 = "ActorHandleList";
  local_24[0] = '\0';
  lVar4 = *(long *)(param_1[1] + 0x10);
  lVar2 = (**(code **)(*param_1 + 0xa0))(param_1);
  uVar1 = FUN_7102963780(lVar4,(long *)&local_30,lVar2 + 0x30,param_1,local_24,(undefined1 *)0x0,
                         (long *)0x0,in_x7);
  if ((int)uVar1 < 0) {
    puVar3 = &DAT_7105a09400;
  }
  else {
    param_1[7] = 0;
    lVar2 = 0;
    if ((long *)param_1[2] != (long *)0x0) {
      lVar2 = (**(code **)(*(long *)param_1[2] + 0x10))();
    }
    puVar3 = (undefined *)(lVar2 + (ulong)uVar1 & 0xfffffffffffffffc);
  }
  param_1[7] = (long)puVar3;
  if (local_24[0] != '\0') {
    puVar3 = (undefined *)((ulong)puVar3 | 1);
    param_1[7] = (long)puVar3;
  }
  if ((*(byte *)(*(long *)(param_1[1] + 8) + 0x1ac) & 1) != 0) {
    param_1[7] = (ulong)puVar3 | 2;
  }
  return;
}



void FUN_71011eda78(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if ((DAT_710406a280 & 1) == 0) {
    iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a280);
    if (iVar1 != 0) {
      DAT_710406a278 = DAT_7103a60348 + 0x10;
      thunk_EXT_FUN_02e95df0(&DAT_710406a280);
    }
  }
  if (param_2 != &DAT_710406a278) {
    FUN_710101133c(param_1,param_2);
    return;
  }
  return;
}



undefined8 * FUN_71011edb04(void)

{
  int iVar1;
  
  if (((DAT_710406a280 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a280), iVar1 != 0))
  {
    DAT_710406a278 = DAT_7103a60348 + 0x10;
    thunk_EXT_FUN_02e95df0(&DAT_710406a280);
  }
  return &DAT_710406a278;
}



void FUN_71011edb60(long *param_1)

{
  long *plVar1;
  
  *param_1 = DAT_7103a72c80 + 0x10;
  if ((long *)param_1[2] != (long *)0x0) {
    (**(code **)(*(long *)param_1[2] + 8))();
  }
  if (DAT_7105a06420 != 0) {
    plVar1 = FUN_71024ef490(DAT_7105a06420,param_1);
    if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071011edbc4. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
      return;
    }
    return;
  }
  FUN_71005fbbd0((long)param_1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_71011edc00(void)

{
  int iVar1;
  
  DAT_710406a270 = (undefined8 *)0x0;
  DAT_710406a258 = 0xed092902;
  DAT_710406a260 = FUN_71011ed7c8;
  DAT_710406a268 = (undefined8 *)0x0;
  if (((DAT_710405c890 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710405c890), iVar1 != 0))
  {
    DAT_710405c878 = &DAT_710405c878;
    DAT_710405c880 = &DAT_710405c878;
    _DAT_710405c888 = 0xffffffff00000000;
    thunk_EXT_FUN_02e95df0(DAT_7103a5fe28);
  }
  DAT_710406a268 = DAT_710405c878;
  DAT_710405c88c = 0x10;
  DAT_710405c878 = &DAT_710406a268;
  DAT_710406a270 = &DAT_710405c878;
  if (DAT_710406a268 != (undefined8 *)0x0) {
    DAT_710406a268[1] = &DAT_710406a268;
  }
  _DAT_710405c888 = CONCAT44(DAT_710405c88c,DAT_710405c888 + 1);
  return;
}



void FUN_71011edcb8(long *param_1)

{
  long lVar1;
  long lVar2;
  undefined8 *puVar3;
  
  lVar1 = DAT_7105a06420;
  if (DAT_7105a06420 == 0) {
    puVar3 = (undefined8 *)FUN_71005fbcb0(8,0x48);
  }
  else {
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar3 = (undefined8 *)(lVar1 + 8);
      if (lVar2 != 0) {
        puVar3 = (undefined8 *)(lVar2 + 0x88);
      }
      param_1 = (long *)*puVar3;
    }
    puVar3 = (undefined8 *)(**(code **)(*param_1 + 0x30))(param_1,0x48,8);
  }
  puVar3[2] = 0;
  puVar3[3] = 0;
  *(undefined1 *)((long)puVar3 + 0x1e) = 0xff;
  puVar3[8] = 0;
  *puVar3 = &DAT_71038fd328;
  puVar3[1] = 0;
  puVar3[4] = 0;
  puVar3[5] = 0;
  puVar3[6] = 0;
  puVar3[7] = 0;
  return;
}



void FUN_71011edf28(long *param_1)

{
  uint uVar1;
  long lVar2;
  undefined8 in_x5;
  undefined8 in_x6;
  undefined8 in_x7;
  undefined *puVar3;
  long lVar4;
  char *local_30;
  char local_24 [4];
  
  local_30 = "Prop_OnUpdate";
  FUN_7101012e40(param_1,(long *)&local_30,param_1 + 5,1,0,in_x5,in_x6,in_x7);
  local_30 = "ActorHandleList";
  FUN_710101275c(param_1,(long *)&local_30,param_1 + 6,1,(long *)0x0);
  local_30 = "Src";
  FUN_710101275c(param_1,(long *)&local_30,param_1 + 7,1,(long *)0x0);
  local_30 = "ActorHandleList";
  local_24[0] = '\0';
  lVar4 = *(long *)(param_1[1] + 0x10);
  lVar2 = (**(code **)(*param_1 + 0xa0))(param_1);
  uVar1 = FUN_7102963780(lVar4,(long *)&local_30,lVar2 + 0x30,param_1,local_24,(undefined1 *)0x0,
                         (long *)0x0,in_x7);
  if ((int)uVar1 < 0) {
    puVar3 = &DAT_7105a09400;
  }
  else {
    param_1[8] = 0;
    lVar2 = 0;
    if ((long *)param_1[2] != (long *)0x0) {
      lVar2 = (**(code **)(*(long *)param_1[2] + 0x10))();
    }
    puVar3 = (undefined *)(lVar2 + (ulong)uVar1 & 0xfffffffffffffffc);
  }
  param_1[8] = (long)puVar3;
  if (local_24[0] != '\0') {
    puVar3 = (undefined *)((ulong)puVar3 | 1);
    param_1[8] = (long)puVar3;
  }
  if ((*(byte *)(*(long *)(param_1[1] + 8) + 0x1ac) & 1) != 0) {
    param_1[8] = (ulong)puVar3 | 2;
  }
  return;
}



void FUN_71011ee058(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if ((DAT_710406a2b0 & 1) == 0) {
    iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a2b0);
    if (iVar1 != 0) {
      DAT_710406a2a8 = DAT_7103a60348 + 0x10;
      thunk_EXT_FUN_02e95df0(&DAT_710406a2b0);
    }
  }
  if (param_2 != &DAT_710406a2a8) {
    FUN_710101133c(param_1,param_2);
    return;
  }
  return;
}



undefined8 * FUN_71011ee0e4(void)

{
  int iVar1;
  
  if (((DAT_710406a2b0 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a2b0), iVar1 != 0))
  {
    DAT_710406a2a8 = DAT_7103a60348 + 0x10;
    thunk_EXT_FUN_02e95df0(&DAT_710406a2b0);
  }
  return &DAT_710406a2a8;
}



void FUN_71011ee140(long *param_1)

{
  long *plVar1;
  
  *param_1 = DAT_7103a72c80 + 0x10;
  if ((long *)param_1[2] != (long *)0x0) {
    (**(code **)(*(long *)param_1[2] + 8))();
  }
  if (DAT_7105a06420 != 0) {
    plVar1 = FUN_71024ef490(DAT_7105a06420,param_1);
    if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071011ee1a4. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
      return;
    }
    return;
  }
  FUN_71005fbbd0((long)param_1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_71011ee1e0(void)

{
  int iVar1;
  
  DAT_710406a2a0 = (undefined8 *)0x0;
  DAT_710406a288 = 0xa0e0328b;
  DAT_710406a290 = FUN_71011edcb8;
  DAT_710406a298 = (undefined8 *)0x0;
  if (((DAT_710405c890 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710405c890), iVar1 != 0))
  {
    DAT_710405c878 = &DAT_710405c878;
    DAT_710405c880 = &DAT_710405c878;
    _DAT_710405c888 = 0xffffffff00000000;
    thunk_EXT_FUN_02e95df0(DAT_7103a5fe28);
  }
  DAT_710406a298 = DAT_710405c878;
  DAT_710405c88c = 0x10;
  DAT_710405c878 = &DAT_710406a298;
  DAT_710406a2a0 = &DAT_710405c878;
  if (DAT_710406a298 != (undefined8 *)0x0) {
    DAT_710406a298[1] = &DAT_710406a298;
  }
  _DAT_710405c888 = CONCAT44(DAT_710405c88c,DAT_710405c888 + 1);
  return;
}



void FUN_71011ee298(long *param_1)

{
  long lVar1;
  long lVar2;
  undefined8 *puVar3;
  
  lVar1 = DAT_7105a06420;
  if (DAT_7105a06420 == 0) {
    puVar3 = (undefined8 *)FUN_71005fbcb0(8,0x38);
  }
  else {
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar3 = (undefined8 *)(lVar1 + 8);
      if (lVar2 != 0) {
        puVar3 = (undefined8 *)(lVar2 + 0x88);
      }
      param_1 = (long *)*puVar3;
    }
    puVar3 = (undefined8 *)(**(code **)(*param_1 + 0x30))(param_1,0x38,8);
  }
  puVar3[6] = 0;
  puVar3[2] = 0;
  puVar3[3] = 0;
  *(undefined1 *)((long)puVar3 + 0x1e) = 0xff;
  *puVar3 = &DAT_71038fd460;
  puVar3[1] = 0;
  puVar3[4] = 0;
  puVar3[5] = 0;
  return;
}



long * FUN_71011ee330(long *param_1)

{
  uint uVar1;
  long *plVar2;
  long lVar3;
  undefined8 *puVar4;
  ulong uVar5;
  long lVar6;
  int *piVar7;
  long lVar8;
  uint *puVar9;
  undefined8 local_90;
  undefined8 local_88;
  undefined1 *puStack_80;
  undefined4 local_78;
  undefined1 local_74 [63];
  undefined1 local_35;
  
  puVar4 = (undefined8 *)param_1[5];
  if ((puVar4 != (undefined8 *)0x0 && puVar4 != (undefined8 *)&DAT_7105a09400) &&
     (puVar9 = (uint *)*puVar4, puVar9 != (uint *)0x0)) {
    uVar5 = (ulong)*puVar9;
    if (0 < (int)*puVar9) {
      puVar4 = *(undefined8 **)(puVar9 + 2);
      do {
        uVar1 = ((int *)*puVar4)[1];
        if (((int)uVar1 < 0) || (*(long *)(DAT_71040e7d48 + 2) == 0)) goto LAB_71011ee4ec;
        if (*DAT_71040e7d48 <= uVar1) {
          uVar1 = 0;
        }
        if (*(int *)(*(long *)(DAT_71040e7d48 + 2) + (ulong)uVar1 * 0x10 + 4) != *(int *)*puVar4)
        goto LAB_71011ee4ec;
        puVar4 = puVar4 + 1;
        uVar5 = uVar5 - 1;
      } while (uVar5 != 0);
    }
    uVar5 = param_1[6];
    plVar2 = param_1;
    if ((((uVar5 & 1) != 0) &&
        (puVar4 = (undefined8 *)(uVar5 & 0xfffffffffffffffc), puVar4 != (undefined8 *)0x0)) &&
       (puVar4 != (undefined8 *)&DAT_7105a09400)) {
      if (((((uint)uVar5 >> 1 & 1) != 0) && ((uint *)*puVar4 != puVar9)) &&
         (plVar2 = (long *)thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a094a8 + 0x54)),
         (int)plVar2 < 0)) {
        plVar2 = (long *)thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a094a8 + 0x54),0x80000001);
      }
      *(uint **)(param_1[6] & 0xfffffffffffffffc) = puVar9;
      uVar5 = param_1[6];
    }
    if (0x45 < (uint)((*(int **)(uVar5 & 0xfffffffffffffffc))[1] -
                     **(int **)(uVar5 & 0xfffffffffffffffc))) {
      lVar3 = *(long *)(*DAT_7103a59c30 + 0x19a7f8);
      if (*(int *)(lVar3 + 8) < 1) {
        return plVar2;
      }
      lVar6 = 0;
      do {
        piVar7 = *(int **)(param_1[6] & 0xfffffffffffffffc);
        if (*piVar7 < piVar7[1]) {
          lVar8 = *(long *)(*(long *)(lVar3 + 0x10) + lVar6 * 8);
          puVar4 = *(undefined8 **)(piVar7 + 4);
          if (puVar4 != (undefined8 *)0x0) {
            *(undefined8 *)(piVar7 + 4) = *puVar4;
          }
          *puVar4 = 0xffffffffffffffff;
          *(undefined4 *)puVar4 = *(undefined4 *)(lVar8 + 0x400);
          *(undefined4 *)((long)puVar4 + 4) = *(undefined4 *)(lVar8 + 0x404);
          if (*piVar7 < piVar7[1]) {
            *(undefined8 **)(*(long *)(piVar7 + 2) + (long)*piVar7 * 8) = puVar4;
            *piVar7 = *piVar7 + 1;
          }
        }
        lVar6 = lVar6 + 1;
      } while (lVar6 < *(int *)(lVar3 + 8));
      return plVar2;
    }
  }
LAB_71011ee4ec:
  lVar6 = *(long *)(*(long *)(param_1[1] + 8) + 0x1d8);
  (**(code **)(*param_1 + 0x90))(param_1);
  lVar3 = *(long *)(*(long *)(param_1[1] + 0x10) + 0x48) +
          (ulong)*(ushort *)((long)param_1 + 0x1c) * 0x3c;
  puStack_80 = local_74;
  local_90 = *(undefined8 *)(lVar3 + 0x2c);
  local_88 = *(undefined8 *)(lVar3 + 0x34);
  local_35 = 0;
  local_74[0] = 0;
  local_78 = 0x40;
  uVar1 = FUN_7100f700b0((long *)&puStack_80,0x7103176cba,(uint *)&local_90);
  for (lVar3 = *(long *)(lVar6 + 0x30); lVar3 != lVar6 + 0x28; lVar3 = *(long *)(lVar3 + 8)) {
    *(uint *)(*(long *)(lVar3 + 0x10) + 0x20) = *(uint *)(*(long *)(lVar3 + 0x10) + 0x20) | 4;
  }
  if ((*(uint *)(lVar6 + 0x20) >> 2 & 1) == 0) {
    *(uint *)(lVar6 + 0x20) = *(uint *)(lVar6 + 0x20) | 4;
  }
  return (long *)(ulong)uVar1;
}



void FUN_71011ee5b8(long *param_1)

{
  uint uVar1;
  long lVar2;
  undefined8 in_x7;
  undefined *puVar3;
  long lVar4;
  char *local_30;
  char local_24 [4];
  
  local_30 = "ActorHandleList";
  FUN_710101275c(param_1,(long *)&local_30,param_1 + 5,1,(long *)0x0);
  local_30 = "ActorHandleList";
  local_24[0] = '\0';
  lVar4 = *(long *)(param_1[1] + 0x10);
  lVar2 = (**(code **)(*param_1 + 0xa0))(param_1);
  uVar1 = FUN_7102963780(lVar4,(long *)&local_30,lVar2 + 0x30,param_1,local_24,(undefined1 *)0x0,
                         (long *)0x0,in_x7);
  if ((int)uVar1 < 0) {
    puVar3 = &DAT_7105a09400;
  }
  else {
    param_1[6] = 0;
    lVar2 = 0;
    if ((long *)param_1[2] != (long *)0x0) {
      lVar2 = (**(code **)(*(long *)param_1[2] + 0x10))();
    }
    puVar3 = (undefined *)(lVar2 + (ulong)uVar1 & 0xfffffffffffffffc);
  }
  param_1[6] = (long)puVar3;
  if (local_24[0] != '\0') {
    puVar3 = (undefined *)((ulong)puVar3 | 1);
    param_1[6] = (long)puVar3;
  }
  if ((*(byte *)(*(long *)(param_1[1] + 8) + 0x1ac) & 1) != 0) {
    param_1[6] = (ulong)puVar3 | 2;
  }
  return;
}



void FUN_71011ee69c(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if ((DAT_710406a2e0 & 1) == 0) {
    iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a2e0);
    if (iVar1 != 0) {
      DAT_710406a2d8 = DAT_7103a60348 + 0x10;
      thunk_EXT_FUN_02e95df0(&DAT_710406a2e0);
    }
  }
  if (param_2 != &DAT_710406a2d8) {
    FUN_710101133c(param_1,param_2);
    return;
  }
  return;
}



undefined8 * FUN_71011ee728(void)

{
  int iVar1;
  
  if (((DAT_710406a2e0 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a2e0), iVar1 != 0))
  {
    DAT_710406a2d8 = DAT_7103a60348 + 0x10;
    thunk_EXT_FUN_02e95df0(&DAT_710406a2e0);
  }
  return &DAT_710406a2d8;
}



void FUN_71011ee784(long *param_1)

{
  long *plVar1;
  
  *param_1 = DAT_7103a72c80 + 0x10;
  if ((long *)param_1[2] != (long *)0x0) {
    (**(code **)(*(long *)param_1[2] + 8))();
  }
  if (DAT_7105a06420 != 0) {
    plVar1 = FUN_71024ef490(DAT_7105a06420,param_1);
    if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071011ee7e8. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
      return;
    }
    return;
  }
  FUN_71005fbbd0((long)param_1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_71011ee820(void)

{
  int iVar1;
  
  DAT_710406a2d0 = (undefined8 *)0x0;
  DAT_710406a2b8 = 0x1e60cf2a;
  DAT_710406a2c0 = FUN_71011ee298;
  DAT_710406a2c8 = (undefined8 *)0x0;
  if (((DAT_710405c890 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710405c890), iVar1 != 0))
  {
    DAT_710405c878 = &DAT_710405c878;
    DAT_710405c880 = &DAT_710405c878;
    _DAT_710405c888 = 0xffffffff00000000;
    thunk_EXT_FUN_02e95df0(DAT_7103a5fe28);
  }
  DAT_710406a2c8 = DAT_710405c878;
  DAT_710405c88c = 0x10;
  DAT_710405c878 = &DAT_710406a2c8;
  DAT_710406a2d0 = &DAT_710405c878;
  if (DAT_710406a2c8 != (undefined8 *)0x0) {
    DAT_710406a2c8[1] = &DAT_710406a2c8;
  }
  _DAT_710405c888 = CONCAT44(DAT_710405c88c,DAT_710405c888 + 1);
  return;
}



void FUN_71011ee8d8(long *param_1)

{
  long lVar1;
  long lVar2;
  undefined8 *puVar3;
  
  lVar1 = DAT_7105a06420;
  if (DAT_7105a06420 == 0) {
    puVar3 = (undefined8 *)FUN_71005fbcb0(8,0x50);
  }
  else {
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar3 = (undefined8 *)(lVar1 + 8);
      if (lVar2 != 0) {
        puVar3 = (undefined8 *)(lVar2 + 0x88);
      }
      param_1 = (long *)*puVar3;
    }
    puVar3 = (undefined8 *)(**(code **)(*param_1 + 0x30))(param_1,0x50,8);
  }
  puVar3[2] = 0;
  puVar3[3] = 0;
  *(undefined1 *)((long)puVar3 + 0x1e) = 0xff;
  *puVar3 = &DAT_71038fd598;
  puVar3[1] = 0;
  puVar3[4] = 0;
  puVar3[5] = 0;
  puVar3[6] = 0;
  puVar3[7] = 0;
  puVar3[8] = 0;
  puVar3[9] = 0;
  return;
}



void FUN_71011eed18(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if ((DAT_710406a310 & 1) == 0) {
    iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a310);
    if (iVar1 != 0) {
      DAT_710406a308 = DAT_7103a60348 + 0x10;
      thunk_EXT_FUN_02e95df0(&DAT_710406a310);
    }
  }
  if (param_2 != &DAT_710406a308) {
    FUN_710101133c(param_1,param_2);
    return;
  }
  return;
}



undefined8 * FUN_71011eeda4(void)

{
  int iVar1;
  
  if (((DAT_710406a310 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a310), iVar1 != 0))
  {
    DAT_710406a308 = DAT_7103a60348 + 0x10;
    thunk_EXT_FUN_02e95df0(&DAT_710406a310);
  }
  return &DAT_710406a308;
}



void FUN_71011eee00(long *param_1)

{
  long *plVar1;
  
  *param_1 = DAT_7103a72c80 + 0x10;
  if ((long *)param_1[2] != (long *)0x0) {
    (**(code **)(*(long *)param_1[2] + 8))();
  }
  if (DAT_7105a06420 != 0) {
    plVar1 = FUN_71024ef490(DAT_7105a06420,param_1);
    if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071011eee64. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
      return;
    }
    return;
  }
  FUN_71005fbbd0((long)param_1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_71011ef610(void)

{
  int iVar1;
  
  DAT_710406a300 = (undefined8 *)0x0;
  DAT_710406a2e8 = 0x1aa45322;
  DAT_710406a2f0 = FUN_71011ee8d8;
  DAT_710406a2f8 = (undefined8 *)0x0;
  if (((DAT_710405c890 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710405c890), iVar1 != 0))
  {
    DAT_710405c878 = &DAT_710405c878;
    DAT_710405c880 = &DAT_710405c878;
    _DAT_710405c888 = 0xffffffff00000000;
    thunk_EXT_FUN_02e95df0(DAT_7103a5fe28);
  }
  DAT_710406a2f8 = DAT_710405c878;
  DAT_710405c88c = 0x10;
  DAT_710405c878 = &DAT_710406a2f8;
  DAT_710406a300 = &DAT_710405c878;
  if (DAT_710406a2f8 != (undefined8 *)0x0) {
    DAT_710406a2f8[1] = &DAT_710406a2f8;
  }
  _DAT_710405c888 = CONCAT44(DAT_710405c88c,DAT_710405c888 + 1);
  return;
}



void FUN_71011ef6c8(long *param_1)

{
  long lVar1;
  long lVar2;
  undefined8 *puVar3;
  
  lVar1 = DAT_7105a06420;
  if (DAT_7105a06420 == 0) {
    puVar3 = (undefined8 *)FUN_71005fbcb0(8,0x40);
  }
  else {
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar3 = (undefined8 *)(lVar1 + 8);
      if (lVar2 != 0) {
        puVar3 = (undefined8 *)(lVar2 + 0x88);
      }
      param_1 = (long *)*puVar3;
    }
    puVar3 = (undefined8 *)(**(code **)(*param_1 + 0x30))(param_1,0x40,8);
  }
  puVar3[2] = 0;
  puVar3[3] = 0;
  *(undefined1 *)((long)puVar3 + 0x1e) = 0xff;
  *puVar3 = &DAT_71038fd6d0;
  puVar3[1] = 0;
  puVar3[4] = 0;
  puVar3[5] = 0;
  puVar3[6] = 0;
  puVar3[7] = 0;
  return;
}



// WARNING: Type propagation algorithm not settling

int * FUN_71011ef760(long *param_1)

{
  undefined8 *******pppppppuVar1;
  int iVar2;
  uint uVar3;
  long *plVar4;
  ulong uVar5;
  undefined8 *puVar6;
  int *piVar7;
  undefined8 *puVar8;
  long lVar9;
  long lVar10;
  long lVar11;
  long lVar12;
  undefined8 *local_4a8;
  long *plStack_4a0;
  undefined8 local_498;
  undefined8 local_490;
  undefined8 *******local_488;
  undefined8 *******pppppppuStack_480;
  undefined8 *******local_478;
  undefined8 *******local_470;
  undefined8 *******local_468;
  undefined8 *******local_460;
  undefined8 *******local_458;
  undefined8 *******local_450;
  undefined8 *******local_448;
  undefined8 *******local_440;
  undefined8 *******local_438;
  undefined8 *******local_430;
  undefined8 *******local_428;
  undefined8 *******local_420;
  undefined8 *******local_418;
  undefined8 *******local_410;
  undefined8 *******local_408;
  undefined8 *******local_400;
  undefined8 *******local_3f8;
  undefined8 *******local_3f0;
  undefined8 *******local_3e8;
  undefined8 *******local_3e0;
  undefined8 *******local_3d8;
  undefined8 *******local_3d0;
  undefined8 *******local_3c8;
  undefined8 *******local_3c0;
  undefined8 *******local_3b8;
  undefined8 *******local_3b0;
  undefined8 *******local_3a8;
  undefined8 *******local_3a0;
  undefined8 *******local_398;
  undefined8 *******local_390;
  undefined8 *******local_388;
  undefined8 *******local_380;
  undefined8 *******local_378;
  undefined8 *******local_370;
  undefined8 *******local_368;
  undefined8 *******local_360;
  undefined8 *******local_358;
  undefined8 *******local_350;
  undefined8 *******local_348;
  undefined8 *******local_340;
  undefined8 *******local_338;
  undefined8 *******local_330;
  undefined8 *******local_328;
  undefined8 *******local_320;
  undefined8 *******local_318;
  undefined8 *******local_310;
  undefined8 *******local_308;
  undefined8 *******local_300;
  undefined8 *******local_2f8;
  undefined8 *******local_2f0;
  undefined8 *******local_2e8;
  undefined8 *******local_2e0;
  undefined8 *******local_2d8;
  undefined8 *******local_2d0;
  undefined8 *******local_2c8;
  undefined8 *******local_2c0;
  undefined8 *******local_2b8;
  undefined8 ******local_2b0;
  undefined8 *****local_2a8;
  undefined8 ****local_2a0;
  undefined8 ***local_298;
  undefined8 **local_290;
  undefined8 *local_288;
  undefined8 local_280;
  undefined1 auStack_278 [512];
  undefined4 auStack_78 [2];
  undefined *local_70;
  undefined8 **ppuStack_68;
  
  uVar5 = param_1[7];
  if ((((uVar5 & 1) != 0) && (plVar4 = (long *)(uVar5 & 0xfffffffffffffffc), plVar4 != (long *)0x0))
     && (plVar4 != (long *)&DAT_7105a09400)) {
    lVar10 = *(long *)param_1[5];
    if (((((uint)uVar5 >> 1 & 1) != 0) && (*plVar4 != lVar10)) &&
       (iVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a094a8 + 0x54)), iVar2 < 0)) {
      thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a094a8 + 0x54),0x80000001);
    }
    *(long *)(param_1[7] & 0xfffffffffffffffc) = lVar10;
  }
  puVar6 = (undefined8 *)param_1[6];
  if ((puVar6 == (undefined8 *)0x0) || (puVar6 == (undefined8 *)&DAT_7105a09400)) {
    lVar11 = *(long *)(*(long *)(param_1[1] + 8) + 0x1d8);
    (**(code **)(*param_1 + 0x90))(param_1);
    lVar10 = *(long *)(*(long *)(param_1[1] + 0x10) + 0x48) +
             (ulong)*(ushort *)((long)param_1 + 0x1c) * 0x3c;
    local_498 = (long)&local_490 + 4;
    local_70 = *(undefined **)(lVar10 + 0x2c);
    ppuStack_68 = *(undefined8 ***)(lVar10 + 0x34);
    local_450._0_4_ = (uint)(uint3)local_450;
    local_490._4_4_ = local_490._4_4_ & 0xffffff00;
    local_490 = (undefined1 *)CONCAT44(local_490._4_4_,0x40);
    uVar3 = FUN_7100f700b0(&local_498,0x7103176cba,(uint *)&local_70);
    piVar7 = (int *)(ulong)uVar3;
    for (lVar10 = *(long *)(lVar11 + 0x30); lVar10 != lVar11 + 0x28; lVar10 = *(long *)(lVar10 + 8))
    {
      *(uint *)(*(long *)(lVar10 + 0x10) + 0x20) = *(uint *)(*(long *)(lVar10 + 0x10) + 0x20) | 4;
    }
    goto LAB_71011efacc;
  }
  piVar7 = (int *)*puVar6;
  if (piVar7 == (int *)0x0) {
    lVar11 = *(long *)(*(long *)(param_1[1] + 8) + 0x1d8);
    (**(code **)(*param_1 + 0x90))(param_1);
    lVar10 = *(long *)(*(long *)(param_1[1] + 0x10) + 0x48) +
             (ulong)*(ushort *)((long)param_1 + 0x1c) * 0x3c;
    local_498 = (long)&local_490 + 4;
    local_70 = *(undefined **)(lVar10 + 0x2c);
    ppuStack_68 = *(undefined8 ***)(lVar10 + 0x34);
    local_450._0_4_ = (uint)(uint3)local_450;
    local_490._4_4_ = local_490._4_4_ & 0xffffff00;
    local_490 = (undefined1 *)CONCAT44(local_490._4_4_,0x40);
    uVar3 = FUN_7100f700b0(&local_498,0x7103176cba,(uint *)&local_70);
    piVar7 = (int *)(ulong)uVar3;
    for (lVar10 = *(long *)(lVar11 + 0x30); lVar10 != lVar11 + 0x28; lVar10 = *(long *)(lVar10 + 8))
    {
      *(uint *)(*(long *)(lVar10 + 0x10) + 0x20) = *(uint *)(*(long *)(lVar10 + 0x10) + 0x20) | 4;
    }
    goto LAB_71011efacc;
  }
  uVar3 = piVar7[1];
  if ((-1 < (int)uVar3) && (*(long *)(DAT_71040e7d48 + 2) != 0)) {
    if (*DAT_71040e7d48 <= uVar3) {
      uVar3 = 0;
    }
    if (*(int *)(*(long *)(DAT_71040e7d48 + 2) + (ulong)uVar3 * 0x10 + 4) == *piVar7) {
      local_498 = 0;
      local_490 = (undefined1 *)0x0;
      local_478 = &local_470;
      local_470 = &local_468;
      local_488 = &local_478;
      local_468 = &local_460;
      local_460 = &local_458;
      local_280 = 0;
      local_458 = &local_450;
      local_450 = &local_448;
      local_448 = &local_440;
      local_440 = &local_438;
      local_438 = &local_430;
      local_430 = &local_428;
      local_428 = &local_420;
      local_420 = &local_418;
      local_418 = &local_410;
      local_410 = &local_408;
      local_408 = &local_400;
      local_400 = &local_3f8;
      local_3f8 = &local_3f0;
      local_3f0 = &local_3e8;
      local_3e8 = &local_3e0;
      local_3e0 = &local_3d8;
      local_3d8 = &local_3d0;
      local_3d0 = &local_3c8;
      local_3c8 = &local_3c0;
      local_3c0 = &local_3b8;
      local_3b8 = &local_3b0;
      local_3b0 = &local_3a8;
      local_3a8 = &local_3a0;
      local_3a0 = &local_398;
      local_398 = &local_390;
      local_390 = &local_388;
      local_388 = &local_380;
      local_380 = &local_378;
      local_378 = &local_370;
      local_370 = &local_368;
      local_368 = &local_360;
      local_360 = &local_358;
      local_358 = &local_350;
      local_350 = &local_348;
      local_348 = &local_340;
      local_340 = &local_338;
      local_338 = &local_330;
      local_330 = &local_328;
      local_328 = &local_320;
      local_320 = &local_318;
      local_318 = &local_310;
      local_310 = &local_308;
      local_308 = &local_300;
      local_300 = &local_2f8;
      local_2f8 = &local_2f0;
      local_2f0 = &local_2e8;
      local_2e8 = &local_2e0;
      local_2e0 = &local_2d8;
      local_2d8 = &local_2d0;
      local_2d0 = &local_2c8;
      local_2c8 = &local_2c0;
      local_2c0 = &local_2b8;
      local_2b8 = &local_2b0;
      local_2b0 = &local_2a8;
      local_2a8 = &local_2a0;
      local_2a0 = &local_298;
      local_298 = &local_290;
      local_290 = &local_288;
      local_288 = &local_280;
      if (auStack_278 != (undefined1 *)0x0) {
        local_498 = 0x4000000000;
        local_490 = auStack_278;
      }
      uVar3 = (*(int **)param_1[6])[1];
      pppppppuStack_480 = local_488;
      if ((int)uVar3 < 0) {
LAB_71011efc40:
        puVar6 = FUN_7100baff84();
      }
      else {
        lVar10 = *(long *)(DAT_71040e7d48 + 2);
        if (*DAT_71040e7d48 <= uVar3) {
          uVar3 = 0;
          if (lVar10 != 0) goto LAB_71011efa10;
          goto LAB_71011efc40;
        }
        if (lVar10 == 0) goto LAB_71011efc40;
LAB_71011efa10:
        lVar10 = lVar10 + (ulong)uVar3 * 0x10;
        if ((*(int *)(lVar10 + 4) != **(int **)param_1[6]) ||
           (puVar6 = *(undefined8 **)(lVar10 + 8), puVar6 == (undefined8 *)0x0))
        goto LAB_71011efc40;
      }
      iVar2 = *(int *)((long)puVar6 + 0xe4);
      if (((iVar2 != 0) && (lVar10 = (long)iVar2 + (long)puVar6 + 0xe4, lVar10 != 0)) &&
         (0 < *(int *)(lVar10 + 0x2288))) {
        lVar11 = 0;
        do {
          lVar12 = *(long *)(*(long *)(lVar10 + 0x2290) + lVar11 * 8);
          piVar7 = *(int **)param_1[5];
          uVar3 = *(uint *)(lVar12 + 0xc);
          if ((int)uVar3 < 0) {
LAB_71011efcd0:
            puVar6 = FUN_7100baff84();
          }
          else {
            if (*DAT_71040e7d48 <= uVar3) {
              uVar3 = 0;
              lVar9 = *(long *)(DAT_71040e7d48 + 2);
              if (lVar9 != 0) goto LAB_71011efca0;
              goto LAB_71011efcd0;
            }
            lVar9 = *(long *)(DAT_71040e7d48 + 2);
            if (lVar9 == 0) goto LAB_71011efcd0;
LAB_71011efca0:
            lVar9 = lVar9 + (ulong)uVar3 * 0x10;
            if ((*(int *)(lVar9 + 4) != *(int *)(lVar12 + 8)) ||
               (puVar6 = *(undefined8 **)(lVar9 + 8), puVar6 == (undefined8 *)0x0))
            goto LAB_71011efcd0;
          }
          if (*piVar7 < piVar7[1]) {
            puVar8 = *(undefined8 **)(piVar7 + 4);
            if (puVar8 != (undefined8 *)0x0) {
              *(undefined8 *)(piVar7 + 4) = *puVar8;
            }
            *puVar8 = 0xffffffffffffffff;
            *(undefined4 *)puVar8 = *(undefined4 *)(puVar6 + 0x80);
            *(undefined4 *)((long)puVar8 + 4) = *(undefined4 *)((long)puVar6 + 0x404);
            if (*piVar7 < piVar7[1]) {
              *(undefined8 **)(*(long *)(piVar7 + 2) + (long)*piVar7 * 8) = puVar8;
              *piVar7 = *piVar7 + 1;
            }
          }
          uVar3 = *(uint *)(lVar12 + 0xc);
          if ((int)uVar3 < 0) {
LAB_71011efd80:
            puVar6 = FUN_7100baff84();
          }
          else {
            if (*DAT_71040e7d48 <= uVar3) {
              uVar3 = 0;
              lVar9 = *(long *)(DAT_71040e7d48 + 2);
              if (lVar9 != 0) goto LAB_71011efd48;
              goto LAB_71011efd80;
            }
            lVar9 = *(long *)(DAT_71040e7d48 + 2);
            if (lVar9 == 0) goto LAB_71011efd80;
LAB_71011efd48:
            lVar9 = lVar9 + (ulong)uVar3 * 0x10;
            if ((*(int *)(lVar9 + 4) != *(int *)(lVar12 + 8)) ||
               (puVar6 = *(undefined8 **)(lVar9 + 8), puVar6 == (undefined8 *)0x0))
            goto LAB_71011efd80;
          }
          pppppppuVar1 = local_488;
          if ((int)local_498 < local_498._4_4_) {
            if (local_488 != (undefined8 *******)0x0) {
              local_488 = (undefined8 *******)*local_488;
            }
            *pppppppuVar1 = (undefined8 ******)0xffffffffffffffff;
            *(undefined4 *)pppppppuVar1 = *(undefined4 *)(puVar6 + 0x80);
            *(undefined4 *)((long)pppppppuVar1 + 4) = *(undefined4 *)((long)puVar6 + 0x404);
            if ((int)local_498 < local_498._4_4_) {
              *(undefined8 ********)(local_490 + (long)(int)local_498 * 8) = pppppppuVar1;
              local_498 = CONCAT44(local_498._4_4_,(int)local_498 + 1);
            }
          }
          lVar11 = lVar11 + 1;
        } while (lVar11 < *(int *)(lVar10 + 0x2288));
      }
      uVar3 = (*(int **)param_1[6])[1];
      if (-1 < (int)uVar3) {
        if (*DAT_71040e7d48 <= uVar3) {
          uVar3 = 0;
        }
        if (((*(long *)(DAT_71040e7d48 + 2) != 0) &&
            (lVar10 = *(long *)(DAT_71040e7d48 + 2) + (ulong)uVar3 * 0x10,
            *(int *)(lVar10 + 4) == **(int **)param_1[6])) &&
           (puVar6 = *(undefined8 **)(lVar10 + 8), puVar6 != (undefined8 *)0x0))
        goto LAB_71011efe40;
      }
      puVar6 = FUN_7100baff84();
LAB_71011efe40:
      piVar7 = (int *)(puVar6 + 0x1c);
      if (*piVar7 == 0) {
        return piVar7;
      }
      lVar10 = (long)*piVar7 + (long)piVar7;
      if (lVar10 == 0) {
        return piVar7;
      }
      local_4a8 = &local_498;
      uVar3 = *(uint *)(lVar10 + 0x34);
      if ((int)uVar3 < 0) {
        return piVar7;
      }
      lVar11 = *(long *)(DAT_71040e7d48 + 2);
      if (lVar11 != 0) {
        if (*DAT_71040e7d48 <= uVar3) {
          uVar3 = 0;
        }
        if (*(int *)(lVar11 + (ulong)uVar3 * 0x10 + 4) == *(int *)(lVar10 + 0x30)) {
          lVar10 = *(long *)(lVar11 + (ulong)uVar3 * 0x10 + 8);
          plStack_4a0 = param_1;
          if (lVar10 == 0) {
            puVar6 = FUN_7100baff84();
            piVar7 = (int *)(puVar6 + 0x1c);
            iVar2 = *piVar7;
          }
          else {
            piVar7 = (int *)(lVar10 + 0xe0);
            iVar2 = *piVar7;
          }
          if ((iVar2 == 0) || (plVar4 = (long *)((long)iVar2 + (long)piVar7), plVar4 == (long *)0x0)
             ) {
            plVar4 = FUN_7100c996dc();
          }
          ppuStack_68 = &local_4a8;
          local_70 = &DAT_71038fd808;
          FUN_7100d35680(auStack_78,plVar4,&local_70);
          piVar7 = (int *)(**(code **)(local_70 + 0x18))(&local_70);
          return piVar7;
        }
        return piVar7;
      }
      return piVar7;
    }
  }
  lVar11 = *(long *)(*(long *)(param_1[1] + 8) + 0x1d8);
  (**(code **)(*param_1 + 0x90))(param_1);
  lVar10 = *(long *)(*(long *)(param_1[1] + 0x10) + 0x48) +
           (ulong)*(ushort *)((long)param_1 + 0x1c) * 0x3c;
  local_498 = (long)&local_490 + 4;
  local_70 = *(undefined **)(lVar10 + 0x2c);
  ppuStack_68 = *(undefined8 ***)(lVar10 + 0x34);
  local_450._0_4_ = (uint)(uint3)local_450;
  local_490._4_4_ = local_490._4_4_ & 0xffffff00;
  local_490 = (undefined1 *)CONCAT44(local_490._4_4_,0x40);
  uVar3 = FUN_7100f700b0(&local_498,0x7103176cba,(uint *)&local_70);
  piVar7 = (int *)(ulong)uVar3;
  for (lVar10 = *(long *)(lVar11 + 0x30); lVar10 != lVar11 + 0x28; lVar10 = *(long *)(lVar10 + 8)) {
    *(uint *)(*(long *)(lVar10 + 0x10) + 0x20) = *(uint *)(*(long *)(lVar10 + 0x10) + 0x20) | 4;
  }
LAB_71011efacc:
  if ((*(uint *)(lVar11 + 0x20) >> 2 & 1) == 0) {
    *(uint *)(lVar11 + 0x20) = *(uint *)(lVar11 + 0x20) | 4;
  }
  return piVar7;
}



void FUN_71011eff00(long *param_1)

{
  uint uVar1;
  long lVar2;
  undefined8 in_x7;
  undefined *puVar3;
  long lVar4;
  char *local_30;
  char local_24 [4];
  
  local_30 = "ActorHandleList";
  FUN_710101275c(param_1,(long *)&local_30,param_1 + 5,1,(long *)0x0);
  local_30 = "Mii";
  FUN_710101275c(param_1,(long *)&local_30,param_1 + 6,1,(long *)0x0);
  local_30 = "ActorHandleList";
  local_24[0] = '\0';
  lVar4 = *(long *)(param_1[1] + 0x10);
  lVar2 = (**(code **)(*param_1 + 0xa0))(param_1);
  uVar1 = FUN_7102963780(lVar4,(long *)&local_30,lVar2 + 0x30,param_1,local_24,(undefined1 *)0x0,
                         (long *)0x0,in_x7);
  if ((int)uVar1 < 0) {
    puVar3 = &DAT_7105a09400;
  }
  else {
    param_1[7] = 0;
    lVar2 = 0;
    if ((long *)param_1[2] != (long *)0x0) {
      lVar2 = (**(code **)(*(long *)param_1[2] + 0x10))();
    }
    puVar3 = (undefined *)(lVar2 + (ulong)uVar1 & 0xfffffffffffffffc);
  }
  param_1[7] = (long)puVar3;
  if (local_24[0] != '\0') {
    puVar3 = (undefined *)((ulong)puVar3 | 1);
    param_1[7] = (long)puVar3;
  }
  if ((*(byte *)(*(long *)(param_1[1] + 8) + 0x1ac) & 1) != 0) {
    param_1[7] = (ulong)puVar3 | 2;
  }
  return;
}



void FUN_71011f000c(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if ((DAT_710406a350 & 1) == 0) {
    iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a350);
    if (iVar1 != 0) {
      DAT_710406a348 = DAT_7103a60348 + 0x10;
      thunk_EXT_FUN_02e95df0(&DAT_710406a350);
    }
  }
  if (param_2 != &DAT_710406a348) {
    FUN_710101133c(param_1,param_2);
    return;
  }
  return;
}



undefined8 * FUN_71011f0098(void)

{
  int iVar1;
  
  if (((DAT_710406a350 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a350), iVar1 != 0))
  {
    DAT_710406a348 = DAT_7103a60348 + 0x10;
    thunk_EXT_FUN_02e95df0(&DAT_710406a350);
  }
  return &DAT_710406a348;
}



void FUN_71011f00f4(long *param_1)

{
  long *plVar1;
  
  *param_1 = DAT_7103a72c80 + 0x10;
  if ((long *)param_1[2] != (long *)0x0) {
    (**(code **)(*(long *)param_1[2] + 8))();
  }
  if (DAT_7105a06420 != 0) {
    plVar1 = FUN_71024ef490(DAT_7105a06420,param_1);
    if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071011f0158. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
      return;
    }
    return;
  }
  FUN_71005fbbd0((long)param_1);
  return;
}



undefined8 FUN_71011f0190(long param_1,ulong *param_2)

{
  uint *puVar1;
  long lVar2;
  uint uVar3;
  ulong uVar4;
  int *piVar5;
  ulong uVar6;
  long lVar7;
  undefined8 *puVar8;
  ulong uVar9;
  ulong *puVar10;
  
  puVar1 = (uint *)**(long **)(param_1 + 8);
  lVar2 = (*(long **)(param_1 + 8))[1];
  uVar3 = *puVar1;
  uVar6 = (ulong)uVar3;
  if ((int)uVar3 < 1) {
    uVar4 = (ulong)*(uint *)((long)param_2 + 4);
  }
  else {
    uVar9 = *param_2;
    puVar8 = *(undefined8 **)(puVar1 + 2);
    uVar4 = uVar9 >> 0x20;
    uVar9 = (long)(int)uVar9 | uVar9 & 0xffffffff00000000;
    do {
      puVar10 = (ulong *)*puVar8;
      if ((uVar9 <= ((long)(int)*puVar10 | (ulong)*(uint *)((long)puVar10 + 4) << 0x20)) &&
         (((long)(int)*puVar10 | *puVar10 & 0xffffffff00000000) <= uVar9)) {
        return 0;
      }
      puVar8 = puVar8 + 1;
      uVar6 = uVar6 - 1;
    } while (uVar6 != 0);
  }
  if ((int)(uint)uVar4 < 0) {
LAB_71011f0264:
    puVar8 = FUN_7100baff84();
  }
  else {
    lVar7 = *(long *)(DAT_71040e7d48 + 2);
    if (*DAT_71040e7d48 <= (uint)uVar4) {
      uVar4 = 0;
      if (lVar7 != 0) goto LAB_71011f0238;
      goto LAB_71011f0264;
    }
    if (lVar7 == 0) goto LAB_71011f0264;
LAB_71011f0238:
    lVar7 = lVar7 + uVar4 * 0x10;
    if ((*(int *)(lVar7 + 4) != (int)*param_2) ||
       (puVar8 = *(undefined8 **)(lVar7 + 8), puVar8 == (undefined8 *)0x0)) goto LAB_71011f0264;
  }
  if (*(int *)((long)puVar8 + 0x2e4) != 3) {
    return 0;
  }
  uVar3 = *(uint *)((long)param_2 + 4);
  if (-1 < (int)uVar3) {
    if (*DAT_71040e7d48 <= uVar3) {
      uVar3 = 0;
    }
    if (((*(long *)(DAT_71040e7d48 + 2) != 0) &&
        (lVar7 = *(long *)(DAT_71040e7d48 + 2) + (ulong)uVar3 * 0x10,
        *(int *)(lVar7 + 4) == (int)*param_2)) &&
       (puVar8 = *(undefined8 **)(lVar7 + 8), puVar8 != (undefined8 *)0x0)) goto LAB_71011f02cc;
  }
  puVar8 = FUN_7100baff84();
LAB_71011f02cc:
  if ((*(int *)(puVar8 + 0x5b) == 2) &&
     (piVar5 = (int *)**(undefined8 **)(lVar2 + 0x28), *piVar5 < piVar5[1])) {
    puVar8 = *(undefined8 **)(piVar5 + 4);
    if (puVar8 != (undefined8 *)0x0) {
      *(undefined8 *)(piVar5 + 4) = *puVar8;
    }
    *puVar8 = 0xffffffffffffffff;
    *(int *)puVar8 = (int)*param_2;
    *(undefined4 *)((long)puVar8 + 4) = *(undefined4 *)((long)param_2 + 4);
    if (*piVar5 < piVar5[1]) {
      *(undefined8 **)(*(long *)(piVar5 + 2) + (long)*piVar5 * 8) = puVar8;
      *piVar5 = *piVar5 + 1;
    }
  }
  return 0;
}



void FUN_71011f0360(long param_1)

{
  long *plVar1;
  
  if (*DAT_7103a65db8 == 0) {
    FUN_71005fbbd0(param_1);
    return;
  }
  plVar1 = FUN_71024ef490(*DAT_7103a65db8,param_1);
  if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071011f03a0. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
    return;
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_71011f03c0(void)

{
  int iVar1;
  
  DAT_710406a340 = (undefined8 *)0x0;
  DAT_710406a328 = 0xdefb1680;
  DAT_710406a330 = FUN_71011ef6c8;
  DAT_710406a338 = (undefined8 *)0x0;
  if (((DAT_710405c890 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710405c890), iVar1 != 0))
  {
    DAT_710405c878 = &DAT_710405c878;
    DAT_710405c880 = &DAT_710405c878;
    _DAT_710405c888 = 0xffffffff00000000;
    thunk_EXT_FUN_02e95df0(DAT_7103a5fe28);
  }
  DAT_710406a338 = DAT_710405c878;
  DAT_710405c88c = 0x10;
  DAT_710405c878 = &DAT_710406a338;
  DAT_710406a340 = &DAT_710405c878;
  if (DAT_710406a338 != (undefined8 *)0x0) {
    DAT_710406a338[1] = &DAT_710406a338;
  }
  _DAT_710405c888 = CONCAT44(DAT_710405c88c,DAT_710405c888 + 1);
  return;
}



void FUN_71011f0478(long *param_1)

{
  long lVar1;
  long lVar2;
  undefined8 *puVar3;
  
  lVar1 = DAT_7105a06420;
  if (DAT_7105a06420 == 0) {
    puVar3 = (undefined8 *)FUN_71005fbcb0(8,0x40);
  }
  else {
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar3 = (undefined8 *)(lVar1 + 8);
      if (lVar2 != 0) {
        puVar3 = (undefined8 *)(lVar2 + 0x88);
      }
      param_1 = (long *)*puVar3;
    }
    puVar3 = (undefined8 *)(**(code **)(*param_1 + 0x30))(param_1,0x40,8);
  }
  puVar3[2] = 0;
  puVar3[3] = 0;
  *(undefined1 *)((long)puVar3 + 0x1e) = 0xff;
  *puVar3 = &DAT_71038fd840;
  puVar3[1] = 0;
  puVar3[4] = 0;
  puVar3[5] = 0;
  puVar3[6] = 0;
  puVar3[7] = 0;
  return;
}



void FUN_71011f0510(long param_1)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  
  iVar1 = *(int *)(*(ulong *)(param_1 + 0x30) & 0xfffffffffffffffc) +
          *(int *)(*(ulong *)(param_1 + 0x28) & 0xfffffffffffffffc);
  if ((((((uint)*(ulong *)(param_1 + 0x38) >> 1 & 1) != 0) &&
       (piVar2 = (int *)(*(ulong *)(param_1 + 0x38) & 0xfffffffffffffffc), piVar2 != (int *)0x0)) &&
      (*piVar2 != iVar1)) &&
     (iVar3 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a094a8 + 0x54)), iVar3 < 0)) {
    thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a094a8 + 0x54),0x80000001);
  }
  *(int *)(*(ulong *)(param_1 + 0x38) & 0xfffffffffffffffc) = iVar1;
  return;
}



void FUN_71011f0820(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if ((DAT_710406a380 & 1) == 0) {
    iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a380);
    if (iVar1 != 0) {
      DAT_710406a378 = DAT_7103a60348 + 0x10;
      thunk_EXT_FUN_02e95df0(&DAT_710406a380);
    }
  }
  if (param_2 != &DAT_710406a378) {
    FUN_710101133c(param_1,param_2);
    return;
  }
  return;
}



undefined8 * FUN_71011f08ac(void)

{
  int iVar1;
  
  if (((DAT_710406a380 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a380), iVar1 != 0))
  {
    DAT_710406a378 = DAT_7103a60348 + 0x10;
    thunk_EXT_FUN_02e95df0(&DAT_710406a380);
  }
  return &DAT_710406a378;
}



void FUN_71011f0908(long *param_1)

{
  long *plVar1;
  
  *param_1 = DAT_7103a72c80 + 0x10;
  if ((long *)param_1[2] != (long *)0x0) {
    (**(code **)(*(long *)param_1[2] + 8))();
  }
  if (DAT_7105a06420 != 0) {
    plVar1 = FUN_71024ef490(DAT_7105a06420,param_1);
    if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071011f096c. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
      return;
    }
    return;
  }
  FUN_71005fbbd0((long)param_1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_71011f09b0(void)

{
  int iVar1;
  
  DAT_710406a370 = (undefined8 *)0x0;
  DAT_710406a358 = 0xd07f1021;
  DAT_710406a360 = FUN_71011f0478;
  DAT_710406a368 = (undefined8 *)0x0;
  if (((DAT_710405c890 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710405c890), iVar1 != 0))
  {
    DAT_710405c878 = &DAT_710405c878;
    DAT_710405c880 = &DAT_710405c878;
    _DAT_710405c888 = 0xffffffff00000000;
    thunk_EXT_FUN_02e95df0(DAT_7103a5fe28);
  }
  DAT_710406a368 = DAT_710405c878;
  DAT_710405c88c = 0x10;
  DAT_710405c878 = &DAT_710406a368;
  DAT_710406a370 = &DAT_710405c878;
  if (DAT_710406a368 != (undefined8 *)0x0) {
    DAT_710406a368[1] = &DAT_710406a368;
  }
  _DAT_710405c888 = CONCAT44(DAT_710405c88c,DAT_710405c888 + 1);
  return;
}



void FUN_71011f0a68(long *param_1)

{
  long lVar1;
  long lVar2;
  undefined8 *puVar3;
  
  lVar1 = DAT_7105a06420;
  if (DAT_7105a06420 == 0) {
    puVar3 = (undefined8 *)FUN_71005fbcb0(8,0x50);
  }
  else {
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar3 = (undefined8 *)(lVar1 + 8);
      if (lVar2 != 0) {
        puVar3 = (undefined8 *)(lVar2 + 0x88);
      }
      param_1 = (long *)*puVar3;
    }
    puVar3 = (undefined8 *)(**(code **)(*param_1 + 0x30))(param_1,0x50,8);
  }
  puVar3[2] = 0;
  puVar3[3] = 0;
  *(undefined1 *)((long)puVar3 + 0x1e) = 0xff;
  *puVar3 = &DAT_71038fd978;
  puVar3[1] = 0;
  puVar3[4] = 0;
  puVar3[5] = 0;
  puVar3[6] = 0;
  puVar3[7] = 0;
  puVar3[8] = 0;
  puVar3[9] = 0;
  return;
}



void FUN_71011f0ca8(long *param_1)

{
  uint uVar1;
  long lVar2;
  undefined8 *puVar3;
  undefined8 in_x5;
  undefined8 in_x6;
  ulong uVar4;
  undefined8 in_x7;
  undefined8 uVar5;
  long lVar6;
  char *local_40;
  uint local_38;
  ushort local_34 [2];
  ushort local_18 [2];
  uint local_14;
  
  local_40 = "Prop_OnlyOnEnter";
  FUN_7101012e40(param_1,(long *)&local_40,param_1 + 5,1,0,in_x5,in_x6,in_x7);
  local_14 = 0;
  local_40 = "Vec3s";
  local_18[0] = 0xffff;
  local_34[0] = 0xffff;
  lVar6 = *(long *)(param_1[1] + 0x10);
  local_38 = 0;
  lVar2 = (**(code **)(*param_1 + 0xa0))(param_1);
  puVar3 = FUN_71011f0f70(lVar6,(long *)&local_40,lVar2 + 0x30,local_18,local_34,&local_14,
                          (long)param_1,(undefined1 *)0x0,&local_38);
  uVar4 = (ulong)local_34[0];
  uVar5 = 0;
  FUN_71011f11d0((long)param_1,(long *)&local_40,param_1 + 6,0,(ulong)local_14,(ulong)local_18[0],
                 uVar4,0,(ulong)puVar3,local_38);
  local_14 = local_14 & 0xffffff00;
  local_40 = "Result";
  lVar6 = *(long *)(param_1[1] + 0x10);
  lVar2 = (**(code **)(*param_1 + 0xa0))(param_1);
  uVar1 = FUN_7102963610(lVar6,(long *)&local_40,lVar2 + 0x30,param_1,(byte *)&local_14,
                         (undefined1 *)0x0,uVar4,uVar5);
  FUN_7102962d38((long)param_1,(ulong *)(param_1 + 9),uVar1,local_14 & 0xff);
  return;
}



void FUN_71011f0de0(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if ((DAT_710406a3b0 & 1) == 0) {
    iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a3b0);
    if (iVar1 != 0) {
      DAT_710406a3a8 = DAT_7103a60348 + 0x10;
      thunk_EXT_FUN_02e95df0(&DAT_710406a3b0);
    }
  }
  if (param_2 != &DAT_710406a3a8) {
    FUN_710101133c(param_1,param_2);
    return;
  }
  return;
}



undefined8 * FUN_71011f0e6c(void)

{
  int iVar1;
  
  if (((DAT_710406a3b0 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a3b0), iVar1 != 0))
  {
    DAT_710406a3a8 = DAT_7103a60348 + 0x10;
    thunk_EXT_FUN_02e95df0(&DAT_710406a3b0);
  }
  return &DAT_710406a3a8;
}



void FUN_71011f0ec8(long *param_1)

{
  long *plVar1;
  
  *param_1 = DAT_7103a72c80 + 0x10;
  if ((long *)param_1[2] != (long *)0x0) {
    (**(code **)(*(long *)param_1[2] + 8))();
  }
  if (DAT_7105a06420 != 0) {
    plVar1 = FUN_71024ef490(DAT_7105a06420,param_1);
    if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071011f0f2c. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
      return;
    }
    return;
  }
  FUN_71005fbbd0((long)param_1);
  return;
}



undefined8 *
FUN_71011f0f70(long param_1,long *param_2,long param_3,ushort *param_4,ushort *param_5,uint *param_6
              ,long param_7,undefined1 *param_8,undefined4 *param_9)

{
  long lVar1;
  uint uVar2;
  uint uVar3;
  char cVar4;
  ushort uVar5;
  bool bVar6;
  int iVar7;
  long lVar8;
  long lVar9;
  ulong uVar10;
  ulong uVar11;
  long lVar12;
  uint *puVar13;
  ushort *puVar14;
  undefined1 *local_170;
  undefined4 local_168;
  undefined1 local_164 [255];
  undefined1 local_65;
  
  lVar8 = *(long *)(param_1 + 0x10);
  if (0 < (int)*(uint *)(param_3 + 0x44)) {
    uVar11 = 0;
    lVar12 = lVar8 + *(int *)(*(long *)(param_1 + 0x28) + 0x20) +
             (long)*(int *)(param_3 + 0x40) * 0x18;
    lVar9 = *param_2;
    do {
      lVar1 = lVar8 + *(int *)(lVar8 + 0x24) + (long)*(int *)(lVar12 + uVar11 * 0x18);
      if (lVar9 == lVar1) {
LAB_71011f1070:
        if (param_9 != (undefined4 *)0x0) {
          *param_9 = *(undefined4 *)(lVar12 + uVar11 * 0x18 + 8);
        }
        lVar8 = lVar12 + uVar11 * 0x18;
        puVar13 = (uint *)(lVar8 + 8);
        uVar3 = *puVar13;
        puVar14 = (ushort *)(lVar8 + 4);
        bVar6 = FUN_7102963914(*(long *)(param_7 + 8),(int)(short)*puVar14,param_3,param_4,param_5,
                               param_6,param_7,param_8);
        if ((!bVar6) && (uVar5 = *puVar14, uVar5 < 0xff9d)) {
          *param_4 = uVar5;
          *param_5 = *(ushort *)(lVar12 + uVar11 * 0x18 + 6) & 0x7fff;
          if ((uVar3 & 0xc2000000) != 0xc2000000) {
            return (undefined8 *)0x0;
          }
          *param_6 = *puVar13 & 0xfe7fffff;
          return (undefined8 *)0x0;
        }
        uVar2 = *puVar13;
        *param_6 = uVar2 & 0xfe7fffff;
        if ((uVar2 & 0xfe7fffff) != 0 && (uVar3 & 0xc2000000) != 0xc2000000) {
          return (undefined8 *)0x0;
        }
        return (undefined8 *)(lVar12 + uVar11 * 0x18 + 0xc);
      }
      bVar6 = true;
      for (uVar10 = 0; *(char *)(lVar9 + uVar10) == *(char *)(lVar1 + uVar10); uVar10 = uVar10 + 2)
      {
        if (*(char *)(lVar9 + uVar10) == '\0') {
LAB_71011f0fe8:
          if (bVar6) goto LAB_71011f1070;
          break;
        }
        if ((uVar10 == 0x400000) ||
           (cVar4 = *(char *)(lVar9 + uVar10 + 1), cVar4 != *(char *)(lVar1 + uVar10 + 1))) break;
        if (cVar4 == '\0') {
          bVar6 = uVar10 < 0x400000;
          goto LAB_71011f0fe8;
        }
        bVar6 = uVar10 + 1 < 0x400000;
      }
      uVar11 = uVar11 + 1;
    } while (uVar11 != *(uint *)(param_3 + 0x44));
  }
  if (param_8 == (undefined1 *)0x0) {
    local_65 = 0;
    local_170 = local_164;
    local_164[0] = 0;
    local_168 = 0x100;
    FUN_7100bc08f0((long *)&local_170,"%s.ain",
                   lVar8 + *(int *)(lVar8 + 0x24) + (long)*(int *)(lVar8 + 8),param_4,param_5,
                   param_6,param_7,0);
  }
  else {
    *param_8 = 1;
  }
  if (((DAT_710406a3f8 & 1) == 0) && (iVar7 = thunk_EXT_FUN_02e95df0(&DAT_710406a3f8), iVar7 != 0))
  {
    DAT_710406a3e8 = 0;
    DAT_710406a3f0 = 0;
    thunk_EXT_FUN_02e95df0(DAT_7103a60818);
  }
  return &DAT_710406a3e8;
}



uint FUN_71011f11d0(long param_1,long *param_2,long *param_3,ulong param_4,undefined8 param_5,
                   ulong param_6,ulong param_7,ulong param_8,ulong param_9,uint param_10)

{
  int iVar1;
  char cVar2;
  ushort uVar3;
  short sVar4;
  uint uVar5;
  undefined8 *puVar6;
  bool bVar7;
  bool bVar8;
  uint uVar9;
  uint *puVar10;
  undefined4 *puVar11;
  int *piVar12;
  long *plVar13;
  ulong uVar14;
  ulong uVar15;
  uint uVar16;
  int iVar17;
  ulong uVar18;
  long lVar19;
  long *plVar20;
  long lVar21;
  ulong uVar22;
  long lVar23;
  undefined4 uVar24;
  ulong uVar25;
  long *plVar26;
  undefined8 *puVar27;
  undefined1 *local_178;
  undefined4 local_170;
  undefined1 local_16c [255];
  undefined1 local_6d;
  
  uVar25 = param_8 & 0xffffffff;
  sVar4 = (short)param_6;
  uVar9 = (uint)param_8;
  if (-100 < sVar4) {
    uVar9 = FUN_71011f1930(param_1,param_2,(ulong *)(param_3 + 2),(ulong)((uint)param_4 & 1),param_5
                           ,param_6 & 0xffffffff,param_7 & 0xffffffff,(ulong)(uVar9 & 1),param_9,
                           param_10);
    return uVar9;
  }
  uVar15 = param_7;
  if ((*DAT_7103a60828 & 1) == 0) {
    param_4 = param_4 & 0xffffffff;
    iVar17 = thunk_EXT_FUN_02e95df0(DAT_7103a60828);
    puVar6 = DAT_7103a60820;
    if (iVar17 != 0) {
      *(undefined4 *)(DAT_7103a60820 + 1) = 0;
      *puVar6 = 0;
      thunk_EXT_FUN_02e95df0(DAT_7103a60828);
    }
  }
  uVar5 = (uint)(short)param_7;
  bVar8 = *param_3 != 0;
  lVar23 = *(long *)(*(long *)(*(long *)(param_1 + 8) + 0x10) + 0x10);
  iVar17 = *(int *)(lVar23 + 0x38);
  uVar14 = param_4;
  if (bVar8 || (param_4 & 1) != 0) {
    if (*param_3 == 0) {
      puVar10 = (uint *)(**(code **)(**(long **)(param_1 + 0x10) + 0x70))();
      if ((int)*puVar10 < 1) {
        uVar24 = 0xffffffff;
      }
      else {
        lVar19 = *param_2;
        uVar18 = 0;
        uVar24 = 0xffffffff;
        do {
          lVar21 = *(long *)(*(long *)(puVar10 + 2) + uVar18 * 8);
          if (lVar19 == lVar21) {
LAB_71011f1404:
            uVar24 = (undefined4)uVar18;
            break;
          }
          bVar7 = true;
          for (uVar22 = 0; *(char *)(lVar19 + uVar22) == *(char *)(lVar21 + uVar22);
              uVar22 = uVar22 + 2) {
            if (*(char *)(lVar19 + uVar22) == '\0') {
LAB_71011f1330:
              if (bVar7) goto LAB_71011f1404;
              break;
            }
            if ((uVar22 == 0x400000) ||
               (cVar2 = *(char *)(lVar19 + uVar22 + 1), cVar2 != *(char *)(lVar21 + uVar22 + 1)))
            break;
            if (cVar2 == '\0') {
              bVar7 = uVar22 < 0x400000;
              goto LAB_71011f1330;
            }
            bVar7 = uVar22 + 1 < 0x400000;
          }
          uVar18 = uVar18 + 1;
        } while (uVar18 != *puVar10);
      }
      lVar19 = (**(code **)(**(long **)(param_1 + 0x10) + 0x68))();
      *(undefined4 *)(param_3 + 1) = uVar24;
      *(uint *)((long)param_3 + 0xc) = uVar5;
      *param_3 = lVar19;
    }
LAB_71011f1424:
    puVar6 = DAT_7103a60820;
    if (0 < (int)uVar5) {
      uVar18 = 0;
      lVar23 = lVar23 + iVar17 + (-100 - (long)sVar4) * 8;
      do {
        sVar4 = *(short *)(lVar23 + uVar18 * 8);
        iVar17 = (int)sVar4;
        lVar19 = *(long *)(param_1 + 8);
        uVar9 = *(uint *)(lVar19 + 0x60);
        if (uVar9 == (int)sVar4 || (int)uVar9 < (int)sVar4) {
          local_6d = 0;
          local_170 = 0x100;
          local_16c[0] = 0;
          lVar19 = *(long *)(*(long *)(lVar19 + 0x10) + 0x10);
          local_178 = local_16c;
          FUN_7100bc08f0((long *)&local_178,"%s.ain",
                         lVar19 + *(int *)(lVar19 + 0x24) + (long)*(int *)(lVar19 + 8),uVar14,
                         param_5,param_6,uVar15,param_8);
          lVar19 = *(long *)(param_1 + 8);
LAB_71011f1564:
          local_6d = 0;
          local_170 = 0x100;
          local_16c[0] = 0;
          lVar19 = *(long *)(*(long *)(lVar19 + 0x10) + 0x10);
          local_178 = local_16c;
          FUN_7100bc08f0((long *)&local_178,"%s.ain",
                         lVar19 + *(int *)(lVar19 + 0x24) + (long)*(int *)(lVar19 + 8),uVar14,
                         param_5,param_6,uVar15,param_8);
          uVar25 = 1;
          puVar27 = puVar6;
LAB_71011f15a8:
          if (bVar8 || (param_4 & 1) != 0) goto LAB_71011f15ac;
LAB_71011f1810:
          piVar12 = (int *)*param_3;
          if (*piVar12 < piVar12[1]) {
            *(undefined8 **)(*(long *)(piVar12 + 2) + (long)*piVar12 * 8) = puVar27;
            *piVar12 = *piVar12 + 1;
          }
          if (uVar18 != 0) {
            piVar12 = (int *)(**(code **)(**(long **)(param_1 + 0x10) + 0x70))();
            if (*piVar12 < piVar12[1]) {
              *(undefined8 *)(*(long *)(piVar12 + 2) + (long)*piVar12 * 8) = 0;
              *piVar12 = *piVar12 + 1;
            }
          }
        }
        else {
          if (uVar9 < (uint)(int)sVar4 || uVar9 == (int)sVar4) {
            iVar17 = 0;
          }
          plVar26 = *(long **)(*(long *)(lVar19 + 0x68) + (long)iVar17 * 8);
          if (plVar26 == (long *)0x0) goto LAB_71011f1564;
          lVar19 = lVar23 + uVar18 * 8;
          sVar4 = *(short *)(lVar19 + 2);
          lVar21 = (**(code **)(*plVar26 + 0xa0))(plVar26);
          puVar10 = (uint *)(lVar19 + 4);
          uVar16 = *puVar10;
          uVar9 = uVar16 & 0xc2000000;
          iVar17 = (int)sVar4;
          if (uVar9 != 0xc2000000) {
switchD_71011f1518_caseD_7:
            iVar17 = iVar17 * 0xc + *(int *)(lVar21 + 0x6c) * 8 +
                     (*(int *)(lVar21 + 0x4c) + *(int *)(lVar21 + 0x3c) + *(int *)(lVar21 + 0x5c)) *
                     4;
            goto LAB_71011f1600;
          }
          uVar16 = uVar16 & 0xffff;
          lVar19 = *(long *)(*(long *)(*(long *)(param_1 + 8) + 0x10) + 0x50);
          piVar12 = (int *)(lVar19 + (ulong)*(uint *)(lVar19 + 0x18));
          if ((int)uVar16 < *piVar12) {
            switch(*(undefined2 *)((long)piVar12 + (ulong)uVar16 * 0x1c + 0x1e)) {
            case 2:
              iVar17 = (*(int *)(lVar21 + 0x3c) + iVar17) * 4;
              break;
            case 3:
            case 4:
              iVar17 = iVar17 << 2;
              break;
            case 5:
              iVar17 = (*(int *)(lVar21 + 0x3c) + iVar17 + *(int *)(lVar21 + 0x4c)) * 4;
              break;
            case 6:
              iVar17 = (*(int *)(lVar21 + 0x4c) + *(int *)(lVar21 + 0x3c) + *(int *)(lVar21 + 0x5c))
                       * 4 + iVar17 * 8;
              break;
            case 7:
              goto switchD_71011f1518_caseD_7;
            default:
              goto switchD_71011f1518_default;
            }
          }
          else {
switchD_71011f1518_default:
            iVar17 = 0;
          }
LAB_71011f1600:
          lVar19 = 0;
          if ((long *)plVar26[2] != (long *)0x0) {
            lVar19 = (**(code **)(*(long *)plVar26[2] + 0x10))();
          }
          puVar27 = (undefined8 *)(lVar19 + iVar17);
          if (uVar9 != 0xc2000000) goto LAB_71011f15a8;
          if (!bVar8 && (param_4 & 1) == 0) {
            uVar3 = *(ushort *)puVar10;
            (**(code **)(**(long **)(param_1 + 0x10) + 0x58))();
            piVar12 = (int *)(**(code **)(**(long **)(param_1 + 0x10) + 0x58))();
            plVar26 = *(long **)(piVar12 + 4);
            if (plVar26 != (long *)0x0) {
              *(long *)(piVar12 + 4) = *plVar26;
            }
            plVar26[6] = 0xffffffff;
            lVar19 = DAT_7103a59fe0;
            plVar26[2] = 0;
            plVar26[3] = 0;
            plVar26[4] = 0;
            plVar26[5] = 0;
            *plVar26 = lVar19;
            plVar26[1] = 0;
            if (*piVar12 < piVar12[1]) {
              *(long **)(*(long *)(piVar12 + 2) + (long)*piVar12 * 8) = plVar26;
              *piVar12 = *piVar12 + 1;
            }
            lVar19 = *param_2;
            *(uint *)(plVar26 + 5) = (uint)uVar3;
            *(undefined4 *)((long)plVar26 + 0x2c) = 7;
            *plVar26 = lVar19;
            plVar26[1] = (long)puVar27;
            lVar19 = (**(code **)(**(long **)(param_1 + 0x10) + 0x50))();
            if (lVar19 == 0) {
              puVar27 = (undefined8 *)0x0;
            }
            else {
              plVar13 = (long *)(**(code **)(**(long **)(param_1 + 0x10) + 0x50))();
              uVar9 = (int)plVar13[2] - 2;
              if (uVar9 < *(uint *)((long)plVar13 + 0x14)) {
                puVar27 = (undefined8 *)0x0;
              }
              else {
                *(int *)(plVar13 + 2) = (int)plVar13[2] + -3;
                puVar27 = (undefined8 *)(*plVar13 + (ulong)uVar9 * 4);
              }
            }
            plVar26[2] = (long)puVar27;
            *(int *)(plVar26 + 6) = (int)uVar18;
            goto LAB_71011f1810;
          }
          piVar12 = (int *)(**(code **)(**(long **)(param_1 + 0x10) + 0x58))();
          if (*piVar12 != 0) {
            plVar26 = *(long **)(piVar12 + 2);
            plVar13 = plVar26 + *piVar12;
            lVar19 = *param_2;
            do {
              plVar20 = (long *)*plVar26;
              lVar21 = *plVar20;
              if (lVar21 == lVar19) {
LAB_71011f1664:
                if (*(int *)((long)plVar20 + 0x2c) == 7 && uVar18 == *(uint *)(plVar20 + 6)) {
                  puVar27 = (undefined8 *)plVar20[2];
                  break;
                }
              }
              else {
                bVar7 = true;
                for (uVar22 = 0; *(char *)(lVar21 + uVar22) == *(char *)(lVar19 + uVar22);
                    uVar22 = uVar22 + 2) {
                  if (*(char *)(lVar21 + uVar22) == '\0') {
LAB_71011f16f4:
                    if (bVar7) goto LAB_71011f1664;
                    break;
                  }
                  if ((uVar22 == 0x400000) ||
                     (cVar2 = *(char *)(lVar21 + uVar22 + 1),
                     cVar2 != *(char *)(lVar19 + uVar22 + 1))) break;
                  if (cVar2 == '\0') {
                    bVar7 = uVar22 < 0x400000;
                    goto LAB_71011f16f4;
                  }
                  bVar7 = uVar22 + 1 < 0x400000;
                }
              }
              plVar26 = plVar26 + 1;
            } while (plVar26 != plVar13);
            goto LAB_71011f15a8;
          }
LAB_71011f15ac:
          uVar9 = (int)param_3[1] + (int)uVar18;
          if (uVar9 < *(uint *)*param_3) {
            *(undefined8 **)(*(long *)((uint *)*param_3 + 2) + (long)(int)uVar9 * 8) = puVar27;
          }
        }
        uVar9 = (uint)uVar25;
        uVar18 = uVar18 + 1;
      } while (uVar18 != uVar5);
    }
    uVar9 = uVar9 ^ 1;
  }
  else {
    lVar19 = (**(code **)(**(long **)(param_1 + 0x10) + 0x68))();
    if (lVar19 != 0) {
      lVar19 = (**(code **)(**(long **)(param_1 + 0x10) + 0x68))();
      iVar1 = *(int *)(lVar19 + 4);
      piVar12 = (int *)(**(code **)(**(long **)(param_1 + 0x10) + 0x68))();
      if ((int)uVar5 <= iVar1 - *piVar12) {
        puVar11 = (undefined4 *)(**(code **)(**(long **)(param_1 + 0x10) + 0x68))();
        *param_3 = (long)puVar11;
        *(undefined4 *)(param_3 + 1) = *puVar11;
        *(uint *)((long)param_3 + 0xc) = uVar5;
        piVar12 = (int *)(**(code **)(**(long **)(param_1 + 0x10) + 0x70))();
        if (*piVar12 < piVar12[1]) {
          *(long *)(*(long *)(piVar12 + 2) + (long)*piVar12 * 8) = *param_2;
          *piVar12 = *piVar12 + 1;
        }
        goto LAB_71011f1424;
      }
    }
    uVar9 = 0;
  }
  return uVar9 & 1;
}



uint FUN_71011f1930(long param_1,long *param_2,ulong *param_3,ulong param_4,undefined8 param_5,
                   ulong param_6,undefined8 param_7,undefined8 param_8,ulong param_9,uint param_10)

{
  uint uVar1;
  char cVar2;
  short sVar3;
  bool bVar4;
  int iVar5;
  int *piVar6;
  long *plVar7;
  uint uVar8;
  ulong uVar9;
  ulong uVar10;
  uint uVar11;
  ulong uVar12;
  uint uVar13;
  undefined8 *puVar14;
  long lVar15;
  long *plVar16;
  long lVar17;
  long *plVar18;
  ulong uVar19;
  undefined1 *local_178;
  undefined4 local_170;
  undefined1 local_16c [255];
  undefined1 local_6d;
  
  uVar13 = (uint)param_8;
  uVar11 = (uint)param_5;
  uVar19 = *param_3;
  uVar1 = uVar11 & 0xc2000000;
  if (param_9 == 0) {
    sVar3 = (short)param_7;
    if ((uVar11 == 0) || (uVar1 == 0xc2000000)) {
      uVar10 = param_4;
      uVar12 = param_6;
      if ((*DAT_7103a60838 & 1) == 0) {
        iVar5 = thunk_EXT_FUN_02e95df0(DAT_7103a60838);
        puVar14 = DAT_7103a60830;
        uVar10 = param_4 & 0xffffffff;
        if (iVar5 != 0) {
          *(undefined4 *)(DAT_7103a60830 + 1) = 0;
          *puVar14 = 0;
          thunk_EXT_FUN_02e95df0(DAT_7103a60838);
          uVar10 = param_4 & 0xffffffff;
        }
      }
      if (((uint)param_6 >> 0xf & 1) == 0) {
        lVar15 = *(long *)(param_1 + 8);
        uVar9 = uVar10;
        if ((int)((uint)param_6 & 0xffff) < *(int *)(lVar15 + 0x60)) {
          plVar18 = *(long **)(*(long *)(lVar15 + 0x68) + (param_6 & 0xffff) * 8);
          if (plVar18 != (long *)0x0) {
            lVar15 = (**(code **)(*plVar18 + 0xa0))(plVar18);
            if (uVar1 == 0xc2000000) {
              lVar17 = *(long *)(*(long *)(*(long *)(param_1 + 8) + 0x10) + 0x50);
              piVar6 = (int *)(lVar17 + (ulong)*(uint *)(lVar17 + 0x18));
              if ((int)(uVar11 & 0xffff) < *piVar6) {
                uVar8 = (uint)*(ushort *)((long)piVar6 + (ulong)(uVar11 & 0xffff) * 0x1c + 0x1e);
              }
              else {
                uVar8 = 0;
              }
              iVar5 = FUN_7102962c90(lVar15 + 0x30,(int)sVar3,uVar8);
            }
            else {
              iVar5 = sVar3 * 0xc + *(int *)(lVar15 + 0x6c) * 8 +
                      (*(int *)(lVar15 + 0x4c) + *(int *)(lVar15 + 0x3c) + *(int *)(lVar15 + 0x5c))
                      * 4;
            }
            lVar15 = 0;
            if ((long *)plVar18[2] != (long *)0x0) {
              lVar15 = (**(code **)(*(long *)plVar18[2] + 0x10))();
            }
            param_4 = uVar10 & 0xffffffff;
            puVar14 = (undefined8 *)(lVar15 + iVar5 & 0xfffffffffffffffc);
            goto LAB_71011f1bb0;
          }
        }
        else {
          local_6d = 0;
          local_178 = local_16c;
          local_16c[0] = 0;
          local_170 = 0x100;
          lVar15 = *(long *)(*(long *)(lVar15 + 0x10) + 0x10);
          FUN_7100bc08f0((long *)&local_178,"%s.ain",
                         lVar15 + *(int *)(lVar15 + 0x24) + (long)*(int *)(lVar15 + 8),uVar10,
                         param_5,uVar12,param_7,param_8);
          lVar15 = *(long *)(param_1 + 8);
        }
        local_6d = 0;
        local_178 = local_16c;
        local_16c[0] = 0;
        local_170 = 0x100;
        lVar15 = *(long *)(*(long *)(lVar15 + 0x10) + 0x10);
        FUN_7100bc08f0((long *)&local_178,"%s.ain",
                       lVar15 + *(int *)(lVar15 + 0x24) + (long)*(int *)(lVar15 + 8),uVar9,param_5,
                       uVar12,param_7,param_8);
        uVar13 = 1;
        param_4 = uVar10 & 0xffffffff;
        puVar14 = DAT_7103a60830;
      }
      else {
        local_6d = 0;
        local_178 = local_16c;
        local_16c[0] = 0;
        local_170 = 0x100;
        param_4 = uVar10 & 0xffffffff;
        lVar15 = *(long *)(*(long *)(*(long *)(param_1 + 8) + 0x10) + 0x10);
        FUN_7100bc08f0((long *)&local_178,"%s.ain",
                       lVar15 + *(int *)(lVar15 + 0x24) + (long)*(int *)(lVar15 + 8),uVar10,param_5,
                       uVar12,param_7,param_8);
        uVar13 = 1;
        puVar14 = DAT_7103a60830;
      }
LAB_71011f1bb0:
      *param_3 = (ulong)puVar14;
      goto LAB_71011f1bb4;
    }
    plVar18 = *(long **)(*(long *)(param_1 + 8) + 0x20);
    uVar19 = (**(code **)(*plVar18 + 0x148))(plVar18,uVar11 & 0xffff);
  }
  else {
    puVar14 = (undefined8 *)(param_9 & 0xfffffffffffffffc | (ulong)(param_10 >> 0x18 & 1));
    *param_3 = (ulong)puVar14;
    if ((param_10 >> 0x17 & 1) != 0) {
      puVar14 = (undefined8 *)((ulong)puVar14 | 2);
      goto LAB_71011f1bb0;
    }
LAB_71011f1bb4:
    if (uVar1 != 0xc2000000) goto LAB_71011f1d5c;
    if ((3 < uVar19) || ((param_4 & 1) != 0)) {
      piVar6 = (int *)(**(code **)(**(long **)(param_1 + 0x10) + 0x58))();
      if (*piVar6 != 0) {
        plVar18 = *(long **)(piVar6 + 2);
        plVar7 = plVar18 + *piVar6;
        lVar15 = *param_2;
        do {
          plVar16 = (long *)*plVar18;
          if ((*(int *)((long)plVar16 + 0x2c) == 7) && (-1 < (int)plVar16[6])) {
            lVar17 = *plVar16;
            if (lVar17 == lVar15) {
LAB_71011f1d84:
              if ((param_4 & 1) == 0) {
                plVar16[1] = *param_3 & 0xfffffffffffffffc;
              }
              uVar19 = plVar16[2];
              goto LAB_71011f1d54;
            }
            bVar4 = true;
            for (uVar19 = 0; *(char *)(lVar17 + uVar19) == *(char *)(lVar15 + uVar19);
                uVar19 = uVar19 + 2) {
              if (*(char *)(lVar17 + uVar19) == '\0') {
LAB_71011f1cb0:
                if (bVar4) goto LAB_71011f1d84;
                break;
              }
              if ((uVar19 == 0x400000) ||
                 (cVar2 = *(char *)(lVar17 + uVar19 + 1), cVar2 != *(char *)(lVar15 + uVar19 + 1)))
              break;
              if (cVar2 == '\0') {
                bVar4 = uVar19 < 0x400000;
                goto LAB_71011f1cb0;
              }
              bVar4 = uVar19 + 1 < 0x400000;
            }
          }
          plVar18 = plVar18 + 1;
        } while (plVar18 != plVar7);
      }
      goto LAB_71011f1d5c;
    }
    piVar6 = (int *)(**(code **)(**(long **)(param_1 + 0x10) + 0x58))();
    plVar18 = *(long **)(piVar6 + 4);
    if (plVar18 != (long *)0x0) {
      *(long *)(piVar6 + 4) = *plVar18;
    }
    plVar18[6] = 0xffffffff;
    lVar15 = DAT_7103a59fe0;
    plVar18[2] = 0;
    plVar18[3] = 0;
    plVar18[4] = 0;
    plVar18[5] = 0;
    *plVar18 = lVar15;
    plVar18[1] = 0;
    if (*piVar6 < piVar6[1]) {
      *(long **)(*(long *)(piVar6 + 2) + (long)*piVar6 * 8) = plVar18;
      *piVar6 = *piVar6 + 1;
    }
    lVar15 = *param_2;
    *(uint *)(plVar18 + 5) = uVar11 & 0xffff;
    *(undefined4 *)((long)plVar18 + 0x2c) = 7;
    *plVar18 = lVar15;
    plVar18[1] = (ulong)puVar14 & 0xfffffffffffffffc;
    lVar15 = (**(code **)(**(long **)(param_1 + 0x10) + 0x50))();
    uVar19 = 0;
    if (lVar15 != 0) {
      plVar7 = (long *)(**(code **)(**(long **)(param_1 + 0x10) + 0x50))();
      uVar1 = (int)plVar7[2] - 2;
      if (uVar1 < *(uint *)((long)plVar7 + 0x14)) {
        uVar19 = 0;
      }
      else {
        *(int *)(plVar7 + 2) = (int)plVar7[2] + -3;
        uVar19 = *plVar7 + (ulong)uVar1 * 4;
      }
    }
    plVar18[2] = uVar19;
    *(undefined4 *)(plVar18 + 6) = 0;
  }
LAB_71011f1d54:
  *param_3 = uVar19 & 0xfffffffffffffffc;
LAB_71011f1d5c:
  return (uVar13 ^ 0xffffffff) & 1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_71011f1de0(void)

{
  int iVar1;
  
  DAT_710406a3a0 = (undefined8 *)0x0;
  DAT_710406a388 = 0x577c815b;
  DAT_710406a390 = FUN_71011f0a68;
  DAT_710406a398 = (undefined8 *)0x0;
  if (((DAT_710405c890 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710405c890), iVar1 != 0))
  {
    DAT_710405c878 = &DAT_710405c878;
    DAT_710405c880 = &DAT_710405c878;
    _DAT_710405c888 = 0xffffffff00000000;
    thunk_EXT_FUN_02e95df0(DAT_7103a5fe28);
  }
  DAT_710406a398 = DAT_710405c878;
  DAT_710405c88c = 0x10;
  DAT_710405c878 = &DAT_710406a398;
  DAT_710406a3a0 = &DAT_710405c878;
  if (DAT_710406a398 != (undefined8 *)0x0) {
    DAT_710406a398[1] = &DAT_710406a398;
  }
  _DAT_710405c888 = CONCAT44(DAT_710405c88c,DAT_710405c888 + 1);
  return;
}



void FUN_71011f1e98(long *param_1)

{
  long lVar1;
  long lVar2;
  undefined8 *puVar3;
  
  lVar1 = DAT_7105a06420;
  if (DAT_7105a06420 == 0) {
    puVar3 = (undefined8 *)FUN_71005fbcb0(8,0x48);
  }
  else {
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar3 = (undefined8 *)(lVar1 + 8);
      if (lVar2 != 0) {
        puVar3 = (undefined8 *)(lVar2 + 0x88);
      }
      param_1 = (long *)*puVar3;
    }
    puVar3 = (undefined8 *)(**(code **)(*param_1 + 0x30))(param_1,0x48,8);
  }
  puVar3[8] = 0;
  puVar3[2] = 0;
  puVar3[3] = 0;
  *(undefined1 *)((long)puVar3 + 0x1e) = 0xff;
  puVar3[4] = 0;
  puVar3[5] = 0;
  *puVar3 = &DAT_71038fdab0;
  puVar3[1] = 0;
  puVar3[6] = 0;
  puVar3[7] = 0;
  return;
}



void FUN_71011f2134(long *param_1)

{
  uint uVar1;
  long lVar2;
  undefined1 *puVar3;
  undefined8 uVar4;
  undefined *puVar5;
  long lVar6;
  char *local_40;
  uint local_38;
  ushort local_34 [2];
  ushort local_18 [2];
  uint local_14;
  
  local_14 = 0;
  local_40 = "AIName";
  local_18[0] = 0xffff;
  local_34[0] = 0xffff;
  lVar6 = *(long *)(param_1[1] + 0x10);
  local_38 = 0;
  lVar2 = (**(code **)(*param_1 + 0xa0))();
  puVar3 = FUN_7102963c00(lVar6,(long *)&local_40,lVar2 + 0x30,local_18,local_34,&local_14,
                          (long)param_1,(undefined1 *)0x0,&local_38);
  uVar4 = 0;
  FUN_710101ead0((long)param_1,(long *)&local_40,(ulong *)(param_1 + 6),0,(ulong)local_14,
                 (ulong)local_18[0],(ulong)local_34[0],0,(ulong)puVar3,local_38);
  local_14 = local_14 & 0xffffff00;
  local_40 = "AIStringId";
  lVar6 = *(long *)(param_1[1] + 0x10);
  lVar2 = (**(code **)(*param_1 + 0xa0))(param_1);
  uVar1 = FUN_7102963780(lVar6,(long *)&local_40,lVar2 + 0x30,param_1,(undefined1 *)&local_14,
                         (undefined1 *)0x0,(long *)0x0,uVar4);
  if ((int)uVar1 < 0) {
    puVar5 = &DAT_7105a09400;
  }
  else {
    param_1[8] = 0;
    lVar2 = 0;
    if ((long *)param_1[2] != (long *)0x0) {
      lVar2 = (**(code **)(*(long *)param_1[2] + 0x10))();
    }
    puVar5 = (undefined *)(lVar2 + (ulong)uVar1 & 0xfffffffffffffffc);
  }
  param_1[8] = (long)puVar5;
  if ((char)local_14 != '\0') {
    puVar5 = (undefined *)((ulong)puVar5 | 1);
    param_1[8] = (long)puVar5;
  }
  if ((*(byte *)(*(long *)(param_1[1] + 8) + 0x1ac) & 1) != 0) {
    param_1[8] = (ulong)puVar5 | 2;
  }
  return;
}



void FUN_71011f2294(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if ((DAT_710406a428 & 1) == 0) {
    iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a428);
    if (iVar1 != 0) {
      DAT_710406a420 = DAT_7103a60348 + 0x10;
      thunk_EXT_FUN_02e95df0(&DAT_710406a428);
    }
  }
  if (param_2 != &DAT_710406a420) {
    FUN_710101133c(param_1,param_2);
    return;
  }
  return;
}



undefined8 * FUN_71011f2320(void)

{
  int iVar1;
  
  if (((DAT_710406a428 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a428), iVar1 != 0))
  {
    DAT_710406a420 = DAT_7103a60348 + 0x10;
    thunk_EXT_FUN_02e95df0(&DAT_710406a428);
  }
  return &DAT_710406a420;
}



void FUN_71011f237c(long *param_1)

{
  long *plVar1;
  
  *param_1 = DAT_7103a72c80 + 0x10;
  if ((long *)param_1[2] != (long *)0x0) {
    (**(code **)(*(long *)param_1[2] + 8))();
  }
  if (DAT_7105a06420 != 0) {
    plVar1 = FUN_71024ef490(DAT_7105a06420,param_1);
    if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071011f23e0. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
      return;
    }
    return;
  }
  FUN_71005fbbd0((long)param_1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_71011f2420(void)

{
  int iVar1;
  
  DAT_710406a418 = (undefined8 *)0x0;
  DAT_710406a400 = 0x5c37e7b;
  DAT_710406a408 = FUN_71011f1e98;
  DAT_710406a410 = (undefined8 *)0x0;
  if (((DAT_710405c890 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710405c890), iVar1 != 0))
  {
    DAT_710405c878 = &DAT_710405c878;
    DAT_710405c880 = &DAT_710405c878;
    _DAT_710405c888 = 0xffffffff00000000;
    thunk_EXT_FUN_02e95df0(DAT_7103a5fe28);
  }
  DAT_710406a410 = DAT_710405c878;
  DAT_710405c88c = 0x10;
  DAT_710405c878 = &DAT_710406a410;
  DAT_710406a418 = &DAT_710405c878;
  if (DAT_710406a410 != (undefined8 *)0x0) {
    DAT_710406a410[1] = &DAT_710406a410;
  }
  _DAT_710405c888 = CONCAT44(DAT_710405c88c,DAT_710405c888 + 1);
  return;
}



void FUN_71011f24d8(long *param_1)

{
  long lVar1;
  long lVar2;
  undefined8 *puVar3;
  
  lVar1 = DAT_7105a06420;
  if (DAT_7105a06420 == 0) {
    puVar3 = (undefined8 *)FUN_71005fbcb0(8,0x38);
  }
  else {
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar3 = (undefined8 *)(lVar1 + 8);
      if (lVar2 != 0) {
        puVar3 = (undefined8 *)(lVar2 + 0x88);
      }
      param_1 = (long *)*puVar3;
    }
    puVar3 = (undefined8 *)(**(code **)(*param_1 + 0x30))(param_1,0x38,8);
  }
  puVar3[6] = 0;
  puVar3[2] = 0;
  puVar3[3] = 0;
  *(undefined1 *)((long)puVar3 + 0x1e) = 0xff;
  puVar3[4] = 0;
  puVar3[5] = 0;
  *puVar3 = &DAT_71038fdbe8;
  puVar3[1] = 0;
  return;
}



void FUN_71011f2570(long param_1)

{
  int iVar1;
  ulong uVar2;
  undefined8 *puVar3;
  undefined4 *puVar4;
  
  puVar4 = (undefined4 *)(param_1 + 0x28);
  *puVar4 = 0xffffffff;
  uVar2 = *(ulong *)(param_1 + 0x30);
  if (((uVar2 & 1) != 0) &&
     (puVar3 = (undefined8 *)(uVar2 & 0xfffffffffffffffc),
     puVar3 != (undefined8 *)0x0 && puVar3 != (undefined8 *)&DAT_7105a09400)) {
    if ((((uint)uVar2 >> 1 & 1) != 0) &&
       (((undefined4 *)*puVar3 != puVar4 &&
        (iVar1 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a094a8 + 0x54)), iVar1 < 0)))) {
      thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a094a8 + 0x54),0x80000001);
    }
    *(undefined4 **)(*(ulong *)(param_1 + 0x30) & 0xfffffffffffffffc) = puVar4;
  }
  return;
}



void FUN_71011f260c(long *param_1)

{
  uint uVar1;
  long lVar2;
  undefined8 in_x7;
  undefined *puVar3;
  long lVar4;
  char *local_30;
  char local_24 [4];
  
  local_24[0] = '\0';
  local_30 = "Exceptions";
  lVar4 = *(long *)(param_1[1] + 0x10);
  lVar2 = (**(code **)(*param_1 + 0xa0))();
  uVar1 = FUN_7102963780(lVar4,(long *)&local_30,lVar2 + 0x30,param_1,local_24,(undefined1 *)0x0,
                         (long *)0x0,in_x7);
  if ((int)uVar1 < 0) {
    puVar3 = &DAT_7105a09400;
  }
  else {
    param_1[6] = 0;
    lVar2 = 0;
    if ((long *)param_1[2] != (long *)0x0) {
      lVar2 = (**(code **)(*(long *)param_1[2] + 0x10))();
    }
    puVar3 = (undefined *)(lVar2 + (ulong)uVar1 & 0xfffffffffffffffc);
  }
  param_1[6] = (long)puVar3;
  if (local_24[0] != '\0') {
    puVar3 = (undefined *)((ulong)puVar3 | 1);
    param_1[6] = (long)puVar3;
  }
  if ((*(byte *)(*(long *)(param_1[1] + 8) + 0x1ac) & 1) != 0) {
    param_1[6] = (ulong)puVar3 | 2;
  }
  return;
}



void FUN_71011f26d0(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if ((DAT_710406a458 & 1) == 0) {
    iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a458);
    if (iVar1 != 0) {
      DAT_710406a450 = DAT_7103a60348 + 0x10;
      thunk_EXT_FUN_02e95df0(&DAT_710406a458);
    }
  }
  if (param_2 != &DAT_710406a450) {
    FUN_710101133c(param_1,param_2);
    return;
  }
  return;
}



undefined8 * FUN_71011f275c(void)

{
  int iVar1;
  
  if (((DAT_710406a458 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a458), iVar1 != 0))
  {
    DAT_710406a450 = DAT_7103a60348 + 0x10;
    thunk_EXT_FUN_02e95df0(&DAT_710406a458);
  }
  return &DAT_710406a450;
}



void FUN_71011f27b8(long *param_1)

{
  long *plVar1;
  
  *param_1 = DAT_7103a72c80 + 0x10;
  if ((long *)param_1[2] != (long *)0x0) {
    (**(code **)(*(long *)param_1[2] + 8))();
  }
  if (DAT_7105a06420 != 0) {
    plVar1 = FUN_71024ef490(DAT_7105a06420,param_1);
    if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071011f281c. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
      return;
    }
    return;
  }
  FUN_71005fbbd0((long)param_1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_71011f2860(void)

{
  int iVar1;
  
  DAT_710406a448 = (undefined8 *)0x0;
  DAT_710406a430 = 0x997bae49;
  DAT_710406a438 = FUN_71011f24d8;
  DAT_710406a440 = (undefined8 *)0x0;
  if (((DAT_710405c890 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710405c890), iVar1 != 0))
  {
    DAT_710405c878 = &DAT_710405c878;
    DAT_710405c880 = &DAT_710405c878;
    _DAT_710405c888 = 0xffffffff00000000;
    thunk_EXT_FUN_02e95df0(DAT_7103a5fe28);
  }
  DAT_710406a440 = DAT_710405c878;
  DAT_710405c88c = 0x10;
  DAT_710405c878 = &DAT_710406a440;
  DAT_710406a448 = &DAT_710405c878;
  if (DAT_710406a440 != (undefined8 *)0x0) {
    DAT_710406a440[1] = &DAT_710406a440;
  }
  _DAT_710405c888 = CONCAT44(DAT_710405c88c,DAT_710405c888 + 1);
  return;
}



void FUN_71011f2918(long *param_1)

{
  long lVar1;
  long lVar2;
  undefined8 *puVar3;
  
  lVar1 = DAT_7105a06420;
  if (DAT_7105a06420 == 0) {
    puVar3 = (undefined8 *)FUN_71005fbcb0(8,0x40);
  }
  else {
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar3 = (undefined8 *)(lVar1 + 8);
      if (lVar2 != 0) {
        puVar3 = (undefined8 *)(lVar2 + 0x88);
      }
      param_1 = (long *)*puVar3;
    }
    puVar3 = (undefined8 *)(**(code **)(*param_1 + 0x30))(param_1,0x40,8);
  }
  puVar3[2] = 0;
  puVar3[3] = 0;
  *(undefined1 *)((long)puVar3 + 0x1e) = 0xff;
  *puVar3 = &DAT_71038fdd20;
  puVar3[1] = 0;
  puVar3[4] = 0;
  puVar3[5] = 0;
  puVar3[6] = 0;
  puVar3[7] = 0;
  return;
}



void FUN_71011f2e84(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if ((DAT_710406a488 & 1) == 0) {
    iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a488);
    if (iVar1 != 0) {
      DAT_710406a480 = DAT_7103a60348 + 0x10;
      thunk_EXT_FUN_02e95df0(&DAT_710406a488);
    }
  }
  if (param_2 != &DAT_710406a480) {
    FUN_710101133c(param_1,param_2);
    return;
  }
  return;
}



undefined8 * FUN_71011f2f10(void)

{
  int iVar1;
  
  if (((DAT_710406a488 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a488), iVar1 != 0))
  {
    DAT_710406a480 = DAT_7103a60348 + 0x10;
    thunk_EXT_FUN_02e95df0(&DAT_710406a488);
  }
  return &DAT_710406a480;
}



void FUN_71011f2f6c(long *param_1)

{
  long *plVar1;
  
  *param_1 = DAT_7103a72c80 + 0x10;
  if ((long *)param_1[2] != (long *)0x0) {
    (**(code **)(*(long *)param_1[2] + 8))();
  }
  if (DAT_7105a06420 != 0) {
    plVar1 = FUN_71024ef490(DAT_7105a06420,param_1);
    if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071011f2fd0. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
      return;
    }
    return;
  }
  FUN_71005fbbd0((long)param_1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_71011f3010(void)

{
  int iVar1;
  
  DAT_710406a478 = (undefined8 *)0x0;
  DAT_710406a460 = 0xcf2bdefb;
  DAT_710406a468 = FUN_71011f2918;
  DAT_710406a470 = (undefined8 *)0x0;
  if (((DAT_710405c890 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710405c890), iVar1 != 0))
  {
    DAT_710405c878 = &DAT_710405c878;
    DAT_710405c880 = &DAT_710405c878;
    _DAT_710405c888 = 0xffffffff00000000;
    thunk_EXT_FUN_02e95df0(DAT_7103a5fe28);
  }
  DAT_710406a470 = DAT_710405c878;
  DAT_710405c88c = 0x10;
  DAT_710405c878 = &DAT_710406a470;
  DAT_710406a478 = &DAT_710405c878;
  if (DAT_710406a470 != (undefined8 *)0x0) {
    DAT_710406a470[1] = &DAT_710406a470;
  }
  _DAT_710405c888 = CONCAT44(DAT_710405c88c,DAT_710405c888 + 1);
  return;
}



void FUN_71011f30c8(long *param_1)

{
  long lVar1;
  long lVar2;
  undefined8 *puVar3;
  
  lVar1 = DAT_7105a06420;
  if (DAT_7105a06420 == 0) {
    puVar3 = (undefined8 *)FUN_71005fbcb0(8,0x38);
  }
  else {
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar3 = (undefined8 *)(lVar1 + 8);
      if (lVar2 != 0) {
        puVar3 = (undefined8 *)(lVar2 + 0x88);
      }
      param_1 = (long *)*puVar3;
    }
    puVar3 = (undefined8 *)(**(code **)(*param_1 + 0x30))(param_1,0x38,8);
  }
  puVar3[6] = 0;
  puVar3[2] = 0;
  puVar3[3] = 0;
  *(undefined1 *)((long)puVar3 + 0x1e) = 0xff;
  puVar3[4] = 0;
  puVar3[5] = 0;
  *puVar3 = &DAT_71038fde60;
  puVar3[1] = 0;
  return;
}



void FUN_71011f31f4(long *param_1)

{
  uint uVar1;
  long lVar2;
  undefined8 in_x7;
  undefined *puVar3;
  long lVar4;
  char *local_30;
  char local_24 [4];
  
  local_24[0] = '\0';
  local_30 = "AnimationCommandParam";
  lVar4 = *(long *)(param_1[1] + 0x10);
  lVar2 = (**(code **)(*param_1 + 0xa0))();
  uVar1 = FUN_7102963780(lVar4,(long *)&local_30,lVar2 + 0x30,param_1,local_24,(undefined1 *)0x0,
                         (long *)0x0,in_x7);
  if ((int)uVar1 < 0) {
    puVar3 = &DAT_7105a09400;
  }
  else {
    param_1[6] = 0;
    lVar2 = 0;
    if ((long *)param_1[2] != (long *)0x0) {
      lVar2 = (**(code **)(*(long *)param_1[2] + 0x10))();
    }
    puVar3 = (undefined *)(lVar2 + (ulong)uVar1 & 0xfffffffffffffffc);
  }
  param_1[6] = (long)puVar3;
  if (local_24[0] != '\0') {
    puVar3 = (undefined *)((ulong)puVar3 | 1);
    param_1[6] = (long)puVar3;
  }
  if ((*(byte *)(*(long *)(param_1[1] + 8) + 0x1ac) & 1) != 0) {
    param_1[6] = (ulong)puVar3 | 2;
  }
  return;
}



void FUN_71011f32b8(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if ((DAT_710406a4b8 & 1) == 0) {
    iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a4b8);
    if (iVar1 != 0) {
      DAT_710406a4b0 = DAT_7103a60348 + 0x10;
      thunk_EXT_FUN_02e95df0(&DAT_710406a4b8);
    }
  }
  if (param_2 != &DAT_710406a4b0) {
    FUN_710101133c(param_1,param_2);
    return;
  }
  return;
}



undefined8 * FUN_71011f3344(void)

{
  int iVar1;
  
  if (((DAT_710406a4b8 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a4b8), iVar1 != 0))
  {
    DAT_710406a4b0 = DAT_7103a60348 + 0x10;
    thunk_EXT_FUN_02e95df0(&DAT_710406a4b8);
  }
  return &DAT_710406a4b0;
}



void FUN_71011f33a0(long *param_1)

{
  long *plVar1;
  
  *param_1 = DAT_7103a72c80 + 0x10;
  if ((long *)param_1[2] != (long *)0x0) {
    (**(code **)(*(long *)param_1[2] + 8))();
  }
  if (DAT_7105a06420 != 0) {
    plVar1 = FUN_71024ef490(DAT_7105a06420,param_1);
    if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071011f3404. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
      return;
    }
    return;
  }
  FUN_71005fbbd0((long)param_1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_71011f3440(void)

{
  int iVar1;
  
  DAT_710406a4a8 = (undefined8 *)0x0;
  DAT_710406a490 = 0x1b18f154;
  DAT_710406a498 = FUN_71011f30c8;
  DAT_710406a4a0 = (undefined8 *)0x0;
  if (((DAT_710405c890 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710405c890), iVar1 != 0))
  {
    DAT_710405c878 = &DAT_710405c878;
    DAT_710405c880 = &DAT_710405c878;
    _DAT_710405c888 = 0xffffffff00000000;
    thunk_EXT_FUN_02e95df0(DAT_7103a5fe28);
  }
  DAT_710406a4a0 = DAT_710405c878;
  DAT_710405c88c = 0x10;
  DAT_710405c878 = &DAT_710406a4a0;
  DAT_710406a4a8 = &DAT_710405c878;
  if (DAT_710406a4a0 != (undefined8 *)0x0) {
    DAT_710406a4a0[1] = &DAT_710406a4a0;
  }
  _DAT_710405c888 = CONCAT44(DAT_710405c88c,DAT_710405c888 + 1);
  return;
}



void FUN_71011f34f8(long *param_1)

{
  long lVar1;
  long lVar2;
  undefined8 *puVar3;
  
  lVar1 = DAT_7105a06420;
  if (DAT_7105a06420 == 0) {
    puVar3 = (undefined8 *)FUN_71005fbcb0(8,0x38);
  }
  else {
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar3 = (undefined8 *)(lVar1 + 8);
      if (lVar2 != 0) {
        puVar3 = (undefined8 *)(lVar2 + 0x88);
      }
      param_1 = (long *)*puVar3;
    }
    puVar3 = (undefined8 *)(**(code **)(*param_1 + 0x30))(param_1,0x38,8);
  }
  puVar3[6] = 0;
  puVar3[2] = 0;
  puVar3[3] = 0;
  *(undefined1 *)((long)puVar3 + 0x1e) = 0xff;
  *puVar3 = &DAT_71038fdf98;
  puVar3[1] = 0;
  puVar3[4] = 0;
  puVar3[5] = 0;
  return;
}



void FUN_71011f3590(long param_1)

{
  int *piVar1;
  uint *puVar2;
  int iVar3;
  uint uVar4;
  long lVar5;
  
  if ((((((uint)*(ulong *)(param_1 + 0x30) >> 1 & 1) != 0) &&
       (piVar1 = (int *)(*(ulong *)(param_1 + 0x30) & 0xfffffffffffffffc), piVar1 != (int *)0x0)) &&
      (*piVar1 != 1)) &&
     (iVar3 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a094a8 + 0x54)), iVar3 < 0)) {
    thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a094a8 + 0x54),0x80000001);
  }
  *(undefined4 *)(*(ulong *)(param_1 + 0x30) & 0xfffffffffffffffc) = 1;
  if (**(long **)(param_1 + 0x28) != 0) {
    lVar5 = *(long *)(**(long **)(param_1 + 0x28) + 0x30);
    uVar4 = (uint)(*(float *)(lVar5 + 0x14) - *(float *)(lVar5 + 0x10));
    uVar4 = uVar4 & ((int)uVar4 >> 0x1f ^ 0xffffffffU);
    if (((((uint)*(ulong *)(param_1 + 0x30) >> 1 & 1) != 0) &&
        (puVar2 = (uint *)(*(ulong *)(param_1 + 0x30) & 0xfffffffffffffffc), puVar2 != (uint *)0x0))
       && ((*puVar2 != uVar4 &&
           (iVar3 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a094a8 + 0x54)), iVar3 < 0)))) {
      thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a094a8 + 0x54),0x80000001);
    }
    *(uint *)(*(ulong *)(param_1 + 0x30) & 0xfffffffffffffffc) = uVar4;
  }
  return;
}



void FUN_71011f3710(long *param_1)

{
  char *pcVar1;
  long lVar2;
  long lVar3;
  uint uVar4;
  undefined8 uVar5;
  undefined8 uVar6;
  undefined8 uVar7;
  undefined8 in_x6;
  undefined8 in_x7;
  long lVar8;
  long lVar9;
  char *local_140;
  undefined4 local_138;
  char local_134 [255];
  undefined1 local_35;
  
  local_140 = "HoldEvent";
  uVar5 = 1;
  uVar6 = 0;
  uVar7 = 0;
  FUN_710101275c(param_1,(long *)&local_140,param_1 + 5,1,(long *)0x0);
  lVar9 = *(long *)(param_1[1] + 0x10);
  lVar2 = (**(code **)(*param_1 + 0xa0))(param_1);
  if (0 < (int)*(uint *)(lVar2 + 0x3c)) {
    lVar3 = 0;
    lVar8 = *(long *)(lVar9 + 0x10);
    do {
      uVar4 = *(uint *)(lVar8 + *(int *)(*(long *)(lVar9 + 0x28) + 4) +
                        (long)*(int *)(lVar2 + 0x38) * 4 + lVar3);
      pcVar1 = (char *)(lVar8 + *(int *)(lVar8 + 0x24) + ((ulong)uVar4 & 0x7fffffff));
      if ((pcVar1 == "Frame") ||
         ((((*pcVar1 == 'F' && (pcVar1[1] == 'r')) && (pcVar1[2] == 'a')) &&
          (((pcVar1[3] == 'm' && (pcVar1[4] == 'e')) && (pcVar1[5] == '\0')))))) {
        uVar4 = uVar4 >> 0x1f;
        goto LAB_71011f3854;
      }
      lVar3 = lVar3 + 4;
    } while ((ulong)*(uint *)(lVar2 + 0x3c) * 4 - lVar3 != 0);
  }
  local_140 = local_134;
  local_35 = 0;
  local_138 = 0x100;
  lVar2 = *(long *)(lVar9 + 0x10);
  local_134[0] = '\0';
  FUN_7100bc08f0((long *)&local_140,"%s.ain",
                 lVar2 + *(int *)(lVar2 + 0x24) + (long)*(int *)(lVar2 + 8),uVar5,uVar6,uVar7,in_x6,
                 in_x7);
  uVar4 = 0;
  lVar3 = 0xffffffff;
LAB_71011f3854:
  FUN_7101095f98((long)param_1,(ulong *)(param_1 + 6),(uint)lVar3,uVar4);
  return;
}



void FUN_71011f3874(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if ((DAT_710406a4e8 & 1) == 0) {
    iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a4e8);
    if (iVar1 != 0) {
      DAT_710406a4e0 = DAT_7103a60348 + 0x10;
      thunk_EXT_FUN_02e95df0(&DAT_710406a4e8);
    }
  }
  if (param_2 != &DAT_710406a4e0) {
    FUN_710101133c(param_1,param_2);
    return;
  }
  return;
}



undefined8 * FUN_71011f3900(void)

{
  int iVar1;
  
  if (((DAT_710406a4e8 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a4e8), iVar1 != 0))
  {
    DAT_710406a4e0 = DAT_7103a60348 + 0x10;
    thunk_EXT_FUN_02e95df0(&DAT_710406a4e8);
  }
  return &DAT_710406a4e0;
}



void FUN_71011f395c(long *param_1)

{
  long *plVar1;
  
  *param_1 = DAT_7103a72c80 + 0x10;
  if ((long *)param_1[2] != (long *)0x0) {
    (**(code **)(*(long *)param_1[2] + 8))();
  }
  if (DAT_7105a06420 != 0) {
    plVar1 = FUN_71024ef490(DAT_7105a06420,param_1);
    if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071011f39c0. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
      return;
    }
    return;
  }
  FUN_71005fbbd0((long)param_1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_71011f3a00(void)

{
  int iVar1;
  
  DAT_710406a4d8 = (undefined8 *)0x0;
  DAT_710406a4c0 = 0xc0220c53;
  DAT_710406a4c8 = FUN_71011f34f8;
  DAT_710406a4d0 = (undefined8 *)0x0;
  if (((DAT_710405c890 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710405c890), iVar1 != 0))
  {
    DAT_710405c878 = &DAT_710405c878;
    DAT_710405c880 = &DAT_710405c878;
    _DAT_710405c888 = 0xffffffff00000000;
    thunk_EXT_FUN_02e95df0(DAT_7103a5fe28);
  }
  DAT_710406a4d0 = DAT_710405c878;
  DAT_710405c88c = 0x10;
  DAT_710405c878 = &DAT_710406a4d0;
  DAT_710406a4d8 = &DAT_710405c878;
  if (DAT_710406a4d0 != (undefined8 *)0x0) {
    DAT_710406a4d0[1] = &DAT_710406a4d0;
  }
  _DAT_710405c888 = CONCAT44(DAT_710405c88c,DAT_710405c888 + 1);
  return;
}



void FUN_71011f3ab8(long *param_1)

{
  long lVar1;
  long lVar2;
  undefined8 *puVar3;
  
  lVar1 = DAT_7105a06420;
  if (DAT_7105a06420 == 0) {
    puVar3 = (undefined8 *)FUN_71005fbcb0(8,0x40);
  }
  else {
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar3 = (undefined8 *)(lVar1 + 8);
      if (lVar2 != 0) {
        puVar3 = (undefined8 *)(lVar2 + 0x88);
      }
      param_1 = (long *)*puVar3;
    }
    puVar3 = (undefined8 *)(**(code **)(*param_1 + 0x30))(param_1,0x40,8);
  }
  puVar3[4] = 0;
  puVar3[5] = 0;
  puVar3[2] = 0;
  puVar3[3] = 0;
  *(undefined1 *)((long)puVar3 + 0x1e) = 0xff;
  *puVar3 = &DAT_71038fe0d0;
  puVar3[1] = 0;
  puVar3[6] = 0;
  puVar3[7] = 0;
  return;
}



void FUN_71011f3b54(long param_1,long param_2)

{
  char *pcVar1;
  long *plVar2;
  int iVar3;
  undefined8 *puVar4;
  long lVar5;
  float fVar6;
  
  plVar2 = DAT_7103a5c670;
  if ((((((uint)*(ulong *)(param_1 + 0x38) >> 1 & 1) != 0) &&
       (pcVar1 = (char *)(*(ulong *)(param_1 + 0x38) & 0xfffffffffffffffc), pcVar1 != (char *)0x0))
      && (*pcVar1 != '\0')) &&
     (iVar3 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(*DAT_7103a5c670 + 0x54)), iVar3 < 0)) {
    thunk_EXT_FUN_02e95df0(*(undefined4 *)(*plVar2 + 0x54),0x80000001);
  }
  *(undefined1 *)(*(ulong *)(param_1 + 0x38) & 0xfffffffffffffffc) = 0;
  if (*(uint *)(*DAT_7103a65d78 + 0x178) < 3) {
    puVar4 = (undefined8 *)0x0;
  }
  else {
    puVar4 = *(undefined8 **)(*(long *)(*DAT_7103a65d78 + 0x180) + 0x10);
  }
  if (((*DAT_7103a65d30 & 1) == 0) && (iVar3 = thunk_EXT_FUN_02e95df0(DAT_7103a65d30), iVar3 != 0))
  {
    *DAT_7103a65d28 = DAT_7103a65d38 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a65d30);
  }
  lVar5 = (**(code **)*puVar4)(puVar4,DAT_7103a65d28);
  if (((*(int *)(lVar5 + 8) != 0) ||
      (0.040000003 <
       *(float *)(lVar5 + 0x124) * *(float *)(lVar5 + 0x124) +
       *(float *)(lVar5 + 0x120) * *(float *)(lVar5 + 0x120))) ||
     (0.040000003 <
      *(float *)(lVar5 + 300) * *(float *)(lVar5 + 300) +
      *(float *)(lVar5 + 0x128) * *(float *)(lVar5 + 0x128))) {
    *(undefined4 *)(param_1 + 0x28) = 0;
  }
  else {
    fVar6 = *(float *)(param_1 + 0x28) + (float)(int)*(float *)(param_2 + 8);
    *(float *)(param_1 + 0x28) = fVar6;
    plVar2 = DAT_7103a5c670;
    if (*(float *)(*(ulong *)(param_1 + 0x30) & 0xfffffffffffffffc) * 30.0 < fVar6) {
      if ((((((uint)*(ulong *)(param_1 + 0x38) >> 1 & 1) != 0) &&
           (pcVar1 = (char *)(*(ulong *)(param_1 + 0x38) & 0xfffffffffffffffc),
           pcVar1 != (char *)0x0)) && (*pcVar1 == '\0')) &&
         (iVar3 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(*DAT_7103a5c670 + 0x54)), iVar3 < 0)) {
        thunk_EXT_FUN_02e95df0(*(undefined4 *)(*plVar2 + 0x54),0x80000001);
      }
      *(undefined1 *)(*(ulong *)(param_1 + 0x38) & 0xfffffffffffffffc) = 1;
    }
  }
  return;
}



void FUN_71011f3f68(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if ((DAT_710406a518 & 1) == 0) {
    iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a518);
    if (iVar1 != 0) {
      DAT_710406a510 = DAT_7103a60348 + 0x10;
      thunk_EXT_FUN_02e95df0(&DAT_710406a518);
    }
  }
  if (param_2 != &DAT_710406a510) {
    FUN_710101133c(param_1,param_2);
    return;
  }
  return;
}



undefined8 * FUN_71011f3ff4(void)

{
  int iVar1;
  
  if (((DAT_710406a518 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a518), iVar1 != 0))
  {
    DAT_710406a510 = DAT_7103a60348 + 0x10;
    thunk_EXT_FUN_02e95df0(&DAT_710406a518);
  }
  return &DAT_710406a510;
}



void FUN_71011f4050(long *param_1)

{
  long *plVar1;
  
  *param_1 = DAT_7103a72c80 + 0x10;
  if ((long *)param_1[2] != (long *)0x0) {
    (**(code **)(*(long *)param_1[2] + 8))();
  }
  if (DAT_7105a06420 != 0) {
    plVar1 = FUN_71024ef490(DAT_7105a06420,param_1);
    if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071011f40b4. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
      return;
    }
    return;
  }
  FUN_71005fbbd0((long)param_1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_71011f40f0(void)

{
  int iVar1;
  
  DAT_710406a508 = (undefined8 *)0x0;
  DAT_710406a4f0 = 0x28ccd8cb;
  DAT_710406a4f8 = FUN_71011f3ab8;
  DAT_710406a500 = (undefined8 *)0x0;
  if (((DAT_710405c890 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710405c890), iVar1 != 0))
  {
    DAT_710405c878 = &DAT_710405c878;
    DAT_710405c880 = &DAT_710405c878;
    _DAT_710405c888 = 0xffffffff00000000;
    thunk_EXT_FUN_02e95df0(DAT_7103a5fe28);
  }
  DAT_710406a500 = DAT_710405c878;
  DAT_710405c88c = 0x10;
  DAT_710405c878 = &DAT_710406a500;
  DAT_710406a508 = &DAT_710405c878;
  if (DAT_710406a500 != (undefined8 *)0x0) {
    DAT_710406a500[1] = &DAT_710406a500;
  }
  _DAT_710405c888 = CONCAT44(DAT_710405c88c,DAT_710405c888 + 1);
  return;
}



void FUN_71011f41a8(long *param_1)

{
  long lVar1;
  long lVar2;
  undefined8 *puVar3;
  
  lVar1 = DAT_7105a06420;
  if (DAT_7105a06420 == 0) {
    puVar3 = (undefined8 *)FUN_71005fbcb0(8,0x50);
  }
  else {
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar3 = (undefined8 *)(lVar1 + 8);
      if (lVar2 != 0) {
        puVar3 = (undefined8 *)(lVar2 + 0x88);
      }
      param_1 = (long *)*puVar3;
    }
    puVar3 = (undefined8 *)(**(code **)(*param_1 + 0x30))(param_1,0x50,8);
  }
  puVar3[2] = 0;
  puVar3[3] = 0;
  *(undefined1 *)((long)puVar3 + 0x1e) = 0xff;
  *puVar3 = &DAT_71038fe208;
  puVar3[1] = 0;
  puVar3[4] = 0;
  puVar3[5] = 0;
  puVar3[6] = 0;
  puVar3[7] = 0;
  puVar3[8] = 0;
  puVar3[9] = 0;
  return;
}



void FUN_71011f46a4(long *param_1)

{
  uint uVar1;
  long lVar2;
  undefined8 *puVar3;
  undefined8 in_x5;
  undefined8 in_x6;
  ulong uVar4;
  undefined8 in_x7;
  undefined8 uVar5;
  long lVar6;
  char *local_48;
  uint local_40;
  ushort local_3c [2];
  ushort local_38 [2];
  uint local_34;
  
  local_48 = "IsEnterOnly";
  FUN_7101012e40(param_1,(long *)&local_48,param_1 + 5,1,0,in_x5,in_x6,in_x7);
  local_48 = "IsRotationOnly";
  FUN_7101012e40(param_1,(long *)&local_48,param_1 + 6,1,0,in_x5,in_x6,in_x7);
  local_48 = "ActorHandle";
  FUN_710101275c(param_1,(long *)&local_48,param_1 + 7,1,(long *)0x0);
  local_38[0] = 0xffff;
  local_3c[0] = 0xffff;
  local_48 = "Vector3";
  local_34 = 0;
  lVar6 = *(long *)(param_1[1] + 0x10);
  local_40 = 0;
  lVar2 = (**(code **)(*param_1 + 0xa0))(param_1);
  puVar3 = FUN_71011f0f70(lVar6,(long *)&local_48,lVar2 + 0x30,local_38,local_3c,&local_34,
                          (long)param_1,(undefined1 *)0x0,&local_40);
  uVar4 = (ulong)local_3c[0];
  uVar5 = 0;
  FUN_71011f1930((long)param_1,(long *)&local_48,(ulong *)(param_1 + 8),0,(ulong)local_34,
                 (ulong)local_38[0],uVar4,0,(ulong)puVar3,local_40);
  local_48 = "Vector3";
  local_34 = local_34 & 0xffffff00;
  lVar6 = *(long *)(param_1[1] + 0x10);
  lVar2 = (**(code **)(*param_1 + 0xa0))(param_1);
  uVar1 = FUN_7102963610(lVar6,(long *)&local_48,lVar2 + 0x30,param_1,(byte *)&local_34,
                         (undefined1 *)0x0,uVar4,uVar5);
  FUN_7102962d38((long)param_1,(ulong *)(param_1 + 9),uVar1,local_34 & 0xff);
  return;
}



void FUN_71011f4820(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if ((DAT_710406a548 & 1) == 0) {
    iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a548);
    if (iVar1 != 0) {
      DAT_710406a540 = DAT_7103a60348 + 0x10;
      thunk_EXT_FUN_02e95df0(&DAT_710406a548);
    }
  }
  if (param_2 != &DAT_710406a540) {
    FUN_710101133c(param_1,param_2);
    return;
  }
  return;
}



undefined8 * FUN_71011f48ac(void)

{
  int iVar1;
  
  if (((DAT_710406a548 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a548), iVar1 != 0))
  {
    DAT_710406a540 = DAT_7103a60348 + 0x10;
    thunk_EXT_FUN_02e95df0(&DAT_710406a548);
  }
  return &DAT_710406a540;
}



void FUN_71011f4908(long *param_1)

{
  long *plVar1;
  
  *param_1 = DAT_7103a72c80 + 0x10;
  if ((long *)param_1[2] != (long *)0x0) {
    (**(code **)(*(long *)param_1[2] + 8))();
  }
  if (DAT_7105a06420 != 0) {
    plVar1 = FUN_71024ef490(DAT_7105a06420,param_1);
    if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071011f496c. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
      return;
    }
    return;
  }
  FUN_71005fbbd0((long)param_1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_71011f49b0(void)

{
  int iVar1;
  
  DAT_710406a538 = (undefined8 *)0x0;
  DAT_710406a520 = 0xaaeb2f0b;
  DAT_710406a528 = FUN_71011f41a8;
  DAT_710406a530 = (undefined8 *)0x0;
  if (((DAT_710405c890 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710405c890), iVar1 != 0))
  {
    DAT_710405c878 = &DAT_710405c878;
    DAT_710405c880 = &DAT_710405c878;
    _DAT_710405c888 = 0xffffffff00000000;
    thunk_EXT_FUN_02e95df0(DAT_7103a5fe28);
  }
  DAT_710406a530 = DAT_710405c878;
  DAT_710405c88c = 0x10;
  DAT_710405c878 = &DAT_710406a530;
  DAT_710406a538 = &DAT_710405c878;
  if (DAT_710406a530 != (undefined8 *)0x0) {
    DAT_710406a530[1] = &DAT_710406a530;
  }
  _DAT_710405c888 = CONCAT44(DAT_710405c88c,DAT_710405c888 + 1);
  return;
}



void FUN_71011f4a68(long *param_1)

{
  long lVar1;
  long lVar2;
  undefined8 *puVar3;
  
  lVar1 = DAT_7105a06420;
  if (DAT_7105a06420 == 0) {
    puVar3 = (undefined8 *)FUN_71005fbcb0(8,0x38);
  }
  else {
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar3 = (undefined8 *)(lVar1 + 8);
      if (lVar2 != 0) {
        puVar3 = (undefined8 *)(lVar2 + 0x88);
      }
      param_1 = (long *)*puVar3;
    }
    puVar3 = (undefined8 *)(**(code **)(*param_1 + 0x30))(param_1,0x38,8);
  }
  puVar3[6] = 0;
  puVar3[2] = 0;
  puVar3[3] = 0;
  *(undefined1 *)((long)puVar3 + 0x1e) = 0xff;
  *puVar3 = &DAT_71038fe340;
  puVar3[1] = 0;
  puVar3[4] = 0;
  puVar3[5] = 0;
  return;
}



ulong FUN_71011f4b00(long *param_1)

{
  long *plVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  ulong uVar7;
  long lVar8;
  long lVar9;
  undefined8 local_90;
  undefined8 local_88;
  undefined1 *puStack_80;
  undefined4 local_78;
  undefined1 local_74 [63];
  undefined1 local_35;
  
  if (*(uint **)param_1[5] == (uint *)0x0) {
    lVar9 = *(long *)(*(long *)(param_1[1] + 8) + 0x1d8);
    (**(code **)(*param_1 + 0x90))(param_1);
    lVar8 = *(long *)(*(long *)(param_1[1] + 0x10) + 0x48) +
            (ulong)*(ushort *)((long)param_1 + 0x1c) * 0x3c;
    puStack_80 = local_74;
    local_90 = *(undefined8 *)(lVar8 + 0x2c);
    local_88 = *(undefined8 *)(lVar8 + 0x34);
    local_35 = 0;
    local_74[0] = 0;
    local_78 = 0x40;
    uVar6 = FUN_7100f700b0((long *)&puStack_80,0x7103176cba,(uint *)&local_90);
    for (lVar8 = *(long *)(lVar9 + 0x30); lVar8 != lVar9 + 0x28; lVar8 = *(long *)(lVar8 + 8)) {
      *(uint *)(*(long *)(lVar8 + 0x10) + 0x20) = *(uint *)(*(long *)(lVar8 + 0x10) + 0x20) | 4;
    }
  }
  else {
    uVar6 = **(uint **)param_1[5];
    uVar7 = FUN_7100cf0750(DAT_710407a3f8);
    if ((uVar6 != 0) && (uVar2 = *(uint *)(uVar7 + 0x2c), uVar2 != 0)) {
      uVar4 = 0;
      if (uVar2 != 0) {
        uVar4 = uVar6 / uVar2;
      }
      uVar4 = uVar6 - uVar4 * uVar2;
      uVar5 = uVar4;
      do {
        uVar3 = *(uint *)(*(long *)(uVar7 + 0x20) +
                         (-(ulong)(uVar5 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar5 << 4));
        if (uVar3 == uVar6) {
          lVar8 = *(long *)(*(long *)(uVar7 + 0x20) + (long)(int)uVar5 * 0x10 + 8);
          if (lVar8 != 0) {
            lVar9 = *(long *)(lVar8 + 8);
            lVar8 = DAT_7103a59fe0;
            if (lVar9 != 0) {
              lVar8 = lVar9;
            }
            if ((((((uint)param_1[6] >> 1 & 1) != 0) &&
                 (plVar1 = (long *)(param_1[6] & 0xfffffffffffffffc), plVar1 != (long *)0x0)) &&
                (lVar9 = *plVar1, lVar9 != lVar8 || lVar9 == 0)) &&
               (uVar7 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a094a8 + 0x54)),
               (int)uVar7 < 0)) {
              uVar7 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a094a8 + 0x54),0x80000001);
            }
            *(long *)(param_1[6] & 0xfffffffffffffffc) = lVar8;
            return uVar7;
          }
          break;
        }
        if (uVar3 == 0) break;
        uVar3 = 0;
        if ((int)(uVar5 + 1) < (int)uVar2) {
          uVar3 = uVar5 + 1;
        }
        uVar5 = uVar3;
      } while (uVar3 != uVar4);
    }
    lVar9 = *(long *)(*(long *)(param_1[1] + 8) + 0x1d8);
    (**(code **)(*param_1 + 0x90))(param_1);
    lVar8 = *(long *)(*(long *)(param_1[1] + 0x10) + 0x48) +
            (ulong)*(ushort *)((long)param_1 + 0x1c) * 0x3c;
    puStack_80 = local_74;
    local_90 = *(undefined8 *)(lVar8 + 0x2c);
    local_88 = *(undefined8 *)(lVar8 + 0x34);
    local_35 = 0;
    local_74[0] = 0;
    local_78 = 0x40;
    uVar6 = FUN_7100f700b0((long *)&puStack_80,0x7103176cba,(uint *)&local_90);
    for (lVar8 = *(long *)(lVar9 + 0x30); lVar8 != lVar9 + 0x28; lVar8 = *(long *)(lVar8 + 8)) {
      *(uint *)(*(long *)(lVar8 + 0x10) + 0x20) = *(uint *)(*(long *)(lVar8 + 0x10) + 0x20) | 4;
    }
  }
  if ((*(uint *)(lVar9 + 0x20) >> 2 & 1) == 0) {
    *(uint *)(lVar9 + 0x20) = *(uint *)(lVar9 + 0x20) | 4;
  }
  return (ulong)uVar6;
}



void FUN_71011f4d5c(long *param_1)

{
  uint uVar1;
  long lVar2;
  undefined8 in_x6;
  undefined8 in_x7;
  long lVar3;
  char *local_38;
  byte local_14 [4];
  
  local_38 = "AttributeLookId";
  FUN_710101275c(param_1,(long *)&local_38,param_1 + 5,1,(long *)0x0);
  local_14[0] = 0;
  local_38 = "String";
  lVar3 = *(long *)(param_1[1] + 0x10);
  lVar2 = (**(code **)(*param_1 + 0xa0))(param_1);
  uVar1 = FUN_71029634b0(lVar3,(long *)&local_38,lVar2 + 0x30,param_1,local_14,(undefined1 *)0x0,
                         in_x6,in_x7);
  FUN_7102962e4c((long)param_1,(ulong *)(param_1 + 6),uVar1,(uint)local_14[0]);
  return;
}



void FUN_71011f4e04(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if ((DAT_710406a578 & 1) == 0) {
    iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a578);
    if (iVar1 != 0) {
      DAT_710406a570 = DAT_7103a60348 + 0x10;
      thunk_EXT_FUN_02e95df0(&DAT_710406a578);
    }
  }
  if (param_2 != &DAT_710406a570) {
    FUN_710101133c(param_1,param_2);
    return;
  }
  return;
}



undefined8 * FUN_71011f4e90(void)

{
  int iVar1;
  
  if (((DAT_710406a578 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a578), iVar1 != 0))
  {
    DAT_710406a570 = DAT_7103a60348 + 0x10;
    thunk_EXT_FUN_02e95df0(&DAT_710406a578);
  }
  return &DAT_710406a570;
}



void FUN_71011f4eec(long *param_1)

{
  long *plVar1;
  
  *param_1 = DAT_7103a72c80 + 0x10;
  if ((long *)param_1[2] != (long *)0x0) {
    (**(code **)(*(long *)param_1[2] + 8))();
  }
  if (DAT_7105a06420 != 0) {
    plVar1 = FUN_71024ef490(DAT_7105a06420,param_1);
    if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071011f4f50. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
      return;
    }
    return;
  }
  FUN_71005fbbd0((long)param_1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_71011f4f90(void)

{
  int iVar1;
  
  DAT_710406a568 = (undefined8 *)0x0;
  DAT_710406a550 = 0xd6cbe28e;
  DAT_710406a558 = FUN_71011f4a68;
  DAT_710406a560 = (undefined8 *)0x0;
  if (((DAT_710405c890 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710405c890), iVar1 != 0))
  {
    DAT_710405c878 = &DAT_710405c878;
    DAT_710405c880 = &DAT_710405c878;
    _DAT_710405c888 = 0xffffffff00000000;
    thunk_EXT_FUN_02e95df0(DAT_7103a5fe28);
  }
  DAT_710406a560 = DAT_710405c878;
  DAT_710405c88c = 0x10;
  DAT_710405c878 = &DAT_710406a560;
  DAT_710406a568 = &DAT_710405c878;
  if (DAT_710406a560 != (undefined8 *)0x0) {
    DAT_710406a560[1] = &DAT_710406a560;
  }
  _DAT_710405c888 = CONCAT44(DAT_710405c88c,DAT_710405c888 + 1);
  return;
}



void FUN_71011f5048(long *param_1)

{
  long lVar1;
  long lVar2;
  undefined8 *puVar3;
  
  lVar1 = DAT_7105a06420;
  if (DAT_7105a06420 == 0) {
    puVar3 = (undefined8 *)FUN_71005fbcb0(8,0x38);
  }
  else {
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar3 = (undefined8 *)(lVar1 + 8);
      if (lVar2 != 0) {
        puVar3 = (undefined8 *)(lVar2 + 0x88);
      }
      param_1 = (long *)*puVar3;
    }
    puVar3 = (undefined8 *)(**(code **)(*param_1 + 0x30))(param_1,0x38,8);
  }
  puVar3[6] = 0;
  puVar3[2] = 0;
  puVar3[3] = 0;
  *(undefined1 *)((long)puVar3 + 0x1e) = 0xff;
  *puVar3 = &DAT_71038fe478;
  puVar3[1] = 0;
  puVar3[4] = 0;
  puVar3[5] = 0;
  return;
}



ulong FUN_71011f50e0(long *param_1)

{
  long *plVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  ulong uVar7;
  long lVar8;
  long lVar9;
  undefined8 local_90;
  undefined8 local_88;
  undefined1 *puStack_80;
  undefined4 local_78;
  undefined1 local_74 [63];
  undefined1 local_35;
  
  if (*(uint **)param_1[5] == (uint *)0x0) {
    lVar9 = *(long *)(*(long *)(param_1[1] + 8) + 0x1d8);
    (**(code **)(*param_1 + 0x90))(param_1);
    lVar8 = *(long *)(*(long *)(param_1[1] + 0x10) + 0x48) +
            (ulong)*(ushort *)((long)param_1 + 0x1c) * 0x3c;
    puStack_80 = local_74;
    local_90 = *(undefined8 *)(lVar8 + 0x2c);
    local_88 = *(undefined8 *)(lVar8 + 0x34);
    local_35 = 0;
    local_74[0] = 0;
    local_78 = 0x40;
    uVar6 = FUN_7100f700b0((long *)&puStack_80,0x7103176cba,(uint *)&local_90);
    for (lVar8 = *(long *)(lVar9 + 0x30); lVar8 != lVar9 + 0x28; lVar8 = *(long *)(lVar8 + 8)) {
      *(uint *)(*(long *)(lVar8 + 0x10) + 0x20) = *(uint *)(*(long *)(lVar8 + 0x10) + 0x20) | 4;
    }
  }
  else {
    uVar6 = **(uint **)param_1[5];
    uVar7 = FUN_7100cf04d0(DAT_710407a3f8);
    if ((uVar6 != 0) && (uVar2 = *(uint *)(uVar7 + 0x2c), uVar2 != 0)) {
      uVar4 = 0;
      if (uVar2 != 0) {
        uVar4 = uVar6 / uVar2;
      }
      uVar4 = uVar6 - uVar4 * uVar2;
      uVar5 = uVar4;
      do {
        uVar3 = *(uint *)(*(long *)(uVar7 + 0x20) +
                         (-(ulong)(uVar5 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar5 << 4));
        if (uVar3 == uVar6) {
          lVar8 = *(long *)(*(long *)(uVar7 + 0x20) + (long)(int)uVar5 * 0x10 + 8);
          if (lVar8 != 0) {
            lVar9 = *(long *)(lVar8 + 8);
            lVar8 = DAT_7103a59fe0;
            if (lVar9 != 0) {
              lVar8 = lVar9;
            }
            if ((((((uint)param_1[6] >> 1 & 1) != 0) &&
                 (plVar1 = (long *)(param_1[6] & 0xfffffffffffffffc), plVar1 != (long *)0x0)) &&
                (lVar9 = *plVar1, lVar9 != lVar8 || lVar9 == 0)) &&
               (uVar7 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a094a8 + 0x54)),
               (int)uVar7 < 0)) {
              uVar7 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a094a8 + 0x54),0x80000001);
            }
            *(long *)(param_1[6] & 0xfffffffffffffffc) = lVar8;
            return uVar7;
          }
          break;
        }
        if (uVar3 == 0) break;
        uVar3 = 0;
        if ((int)(uVar5 + 1) < (int)uVar2) {
          uVar3 = uVar5 + 1;
        }
        uVar5 = uVar3;
      } while (uVar3 != uVar4);
    }
    lVar9 = *(long *)(*(long *)(param_1[1] + 8) + 0x1d8);
    (**(code **)(*param_1 + 0x90))(param_1);
    lVar8 = *(long *)(*(long *)(param_1[1] + 0x10) + 0x48) +
            (ulong)*(ushort *)((long)param_1 + 0x1c) * 0x3c;
    puStack_80 = local_74;
    local_90 = *(undefined8 *)(lVar8 + 0x2c);
    local_88 = *(undefined8 *)(lVar8 + 0x34);
    local_35 = 0;
    local_74[0] = 0;
    local_78 = 0x40;
    uVar6 = FUN_7100f700b0((long *)&puStack_80,0x7103176cba,(uint *)&local_90);
    for (lVar8 = *(long *)(lVar9 + 0x30); lVar8 != lVar9 + 0x28; lVar8 = *(long *)(lVar8 + 8)) {
      *(uint *)(*(long *)(lVar8 + 0x10) + 0x20) = *(uint *)(*(long *)(lVar8 + 0x10) + 0x20) | 4;
    }
  }
  if ((*(uint *)(lVar9 + 0x20) >> 2 & 1) == 0) {
    *(uint *)(lVar9 + 0x20) = *(uint *)(lVar9 + 0x20) | 4;
  }
  return (ulong)uVar6;
}



void FUN_71011f533c(long *param_1)

{
  uint uVar1;
  long lVar2;
  undefined8 in_x6;
  undefined8 in_x7;
  long lVar3;
  char *local_38;
  byte local_14 [4];
  
  local_38 = "AttributeSmellId";
  FUN_710101275c(param_1,(long *)&local_38,param_1 + 5,1,(long *)0x0);
  local_14[0] = 0;
  local_38 = "String";
  lVar3 = *(long *)(param_1[1] + 0x10);
  lVar2 = (**(code **)(*param_1 + 0xa0))(param_1);
  uVar1 = FUN_71029634b0(lVar3,(long *)&local_38,lVar2 + 0x30,param_1,local_14,(undefined1 *)0x0,
                         in_x6,in_x7);
  FUN_7102962e4c((long)param_1,(ulong *)(param_1 + 6),uVar1,(uint)local_14[0]);
  return;
}



void FUN_71011f53e4(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if ((DAT_710406a5a8 & 1) == 0) {
    iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a5a8);
    if (iVar1 != 0) {
      DAT_710406a5a0 = DAT_7103a60348 + 0x10;
      thunk_EXT_FUN_02e95df0(&DAT_710406a5a8);
    }
  }
  if (param_2 != &DAT_710406a5a0) {
    FUN_710101133c(param_1,param_2);
    return;
  }
  return;
}



undefined8 * FUN_71011f5470(void)

{
  int iVar1;
  
  if (((DAT_710406a5a8 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a5a8), iVar1 != 0))
  {
    DAT_710406a5a0 = DAT_7103a60348 + 0x10;
    thunk_EXT_FUN_02e95df0(&DAT_710406a5a8);
  }
  return &DAT_710406a5a0;
}



void FUN_71011f54cc(long *param_1)

{
  long *plVar1;
  
  *param_1 = DAT_7103a72c80 + 0x10;
  if ((long *)param_1[2] != (long *)0x0) {
    (**(code **)(*(long *)param_1[2] + 8))();
  }
  if (DAT_7105a06420 != 0) {
    plVar1 = FUN_71024ef490(DAT_7105a06420,param_1);
    if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071011f5530. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
      return;
    }
    return;
  }
  FUN_71005fbbd0((long)param_1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_71011f5570(void)

{
  int iVar1;
  
  DAT_710406a598 = (undefined8 *)0x0;
  DAT_710406a580 = 0x267687c9;
  DAT_710406a588 = FUN_71011f5048;
  DAT_710406a590 = (undefined8 *)0x0;
  if (((DAT_710405c890 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710405c890), iVar1 != 0))
  {
    DAT_710405c878 = &DAT_710405c878;
    DAT_710405c880 = &DAT_710405c878;
    _DAT_710405c888 = 0xffffffff00000000;
    thunk_EXT_FUN_02e95df0(DAT_7103a5fe28);
  }
  DAT_710406a590 = DAT_710405c878;
  DAT_710405c88c = 0x10;
  DAT_710405c878 = &DAT_710406a590;
  DAT_710406a598 = &DAT_710405c878;
  if (DAT_710406a590 != (undefined8 *)0x0) {
    DAT_710406a590[1] = &DAT_710406a590;
  }
  _DAT_710405c888 = CONCAT44(DAT_710405c88c,DAT_710405c888 + 1);
  return;
}



void FUN_71011f5628(long *param_1)

{
  long lVar1;
  long lVar2;
  undefined8 *puVar3;
  
  lVar1 = DAT_7105a06420;
  if (DAT_7105a06420 == 0) {
    puVar3 = (undefined8 *)FUN_71005fbcb0(8,0x38);
  }
  else {
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar3 = (undefined8 *)(lVar1 + 8);
      if (lVar2 != 0) {
        puVar3 = (undefined8 *)(lVar2 + 0x88);
      }
      param_1 = (long *)*puVar3;
    }
    puVar3 = (undefined8 *)(**(code **)(*param_1 + 0x30))(param_1,0x38,8);
  }
  puVar3[6] = 0;
  puVar3[2] = 0;
  puVar3[3] = 0;
  *(undefined1 *)((long)puVar3 + 0x1e) = 0xff;
  *puVar3 = &DAT_71038fe5b0;
  puVar3[1] = 0;
  puVar3[4] = 0;
  puVar3[5] = 0;
  return;
}



ulong FUN_71011f56c0(long *param_1)

{
  long *plVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  ulong uVar7;
  long lVar8;
  long lVar9;
  undefined8 local_90;
  undefined8 local_88;
  undefined1 *puStack_80;
  undefined4 local_78;
  undefined1 local_74 [63];
  undefined1 local_35;
  
  if (*(uint **)param_1[5] == (uint *)0x0) {
    lVar9 = *(long *)(*(long *)(param_1[1] + 8) + 0x1d8);
    (**(code **)(*param_1 + 0x90))(param_1);
    lVar8 = *(long *)(*(long *)(param_1[1] + 0x10) + 0x48) +
            (ulong)*(ushort *)((long)param_1 + 0x1c) * 0x3c;
    puStack_80 = local_74;
    local_90 = *(undefined8 *)(lVar8 + 0x2c);
    local_88 = *(undefined8 *)(lVar8 + 0x34);
    local_35 = 0;
    local_74[0] = 0;
    local_78 = 0x40;
    uVar6 = FUN_7100f700b0((long *)&puStack_80,0x7103176cba,(uint *)&local_90);
    for (lVar8 = *(long *)(lVar9 + 0x30); lVar8 != lVar9 + 0x28; lVar8 = *(long *)(lVar8 + 8)) {
      *(uint *)(*(long *)(lVar8 + 0x10) + 0x20) = *(uint *)(*(long *)(lVar8 + 0x10) + 0x20) | 4;
    }
  }
  else {
    uVar6 = **(uint **)param_1[5];
    uVar7 = FUN_7100cf0610(DAT_710407a3f8);
    if ((uVar6 != 0) && (uVar2 = *(uint *)(uVar7 + 0x2c), uVar2 != 0)) {
      uVar4 = 0;
      if (uVar2 != 0) {
        uVar4 = uVar6 / uVar2;
      }
      uVar4 = uVar6 - uVar4 * uVar2;
      uVar5 = uVar4;
      do {
        uVar3 = *(uint *)(*(long *)(uVar7 + 0x20) +
                         (-(ulong)(uVar5 >> 0x1f) & 0xfffffff000000000 | (ulong)uVar5 << 4));
        if (uVar3 == uVar6) {
          lVar8 = *(long *)(*(long *)(uVar7 + 0x20) + (long)(int)uVar5 * 0x10 + 8);
          if (lVar8 != 0) {
            lVar9 = *(long *)(lVar8 + 8);
            lVar8 = DAT_7103a59fe0;
            if (lVar9 != 0) {
              lVar8 = lVar9;
            }
            if ((((((uint)param_1[6] >> 1 & 1) != 0) &&
                 (plVar1 = (long *)(param_1[6] & 0xfffffffffffffffc), plVar1 != (long *)0x0)) &&
                (lVar9 = *plVar1, lVar9 != lVar8 || lVar9 == 0)) &&
               (uVar7 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a094a8 + 0x54)),
               (int)uVar7 < 0)) {
              uVar7 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a094a8 + 0x54),0x80000001);
            }
            *(long *)(param_1[6] & 0xfffffffffffffffc) = lVar8;
            return uVar7;
          }
          break;
        }
        if (uVar3 == 0) break;
        uVar3 = 0;
        if ((int)(uVar5 + 1) < (int)uVar2) {
          uVar3 = uVar5 + 1;
        }
        uVar5 = uVar3;
      } while (uVar3 != uVar4);
    }
    lVar9 = *(long *)(*(long *)(param_1[1] + 8) + 0x1d8);
    (**(code **)(*param_1 + 0x90))(param_1);
    lVar8 = *(long *)(*(long *)(param_1[1] + 0x10) + 0x48) +
            (ulong)*(ushort *)((long)param_1 + 0x1c) * 0x3c;
    puStack_80 = local_74;
    local_90 = *(undefined8 *)(lVar8 + 0x2c);
    local_88 = *(undefined8 *)(lVar8 + 0x34);
    local_35 = 0;
    local_74[0] = 0;
    local_78 = 0x40;
    uVar6 = FUN_7100f700b0((long *)&puStack_80,0x7103176cba,(uint *)&local_90);
    for (lVar8 = *(long *)(lVar9 + 0x30); lVar8 != lVar9 + 0x28; lVar8 = *(long *)(lVar8 + 8)) {
      *(uint *)(*(long *)(lVar8 + 0x10) + 0x20) = *(uint *)(*(long *)(lVar8 + 0x10) + 0x20) | 4;
    }
  }
  if ((*(uint *)(lVar9 + 0x20) >> 2 & 1) == 0) {
    *(uint *)(lVar9 + 0x20) = *(uint *)(lVar9 + 0x20) | 4;
  }
  return (ulong)uVar6;
}



void FUN_71011f591c(long *param_1)

{
  uint uVar1;
  long lVar2;
  undefined8 in_x6;
  undefined8 in_x7;
  long lVar3;
  char *local_38;
  byte local_14 [4];
  
  local_38 = "AttributeTouchId";
  FUN_710101275c(param_1,(long *)&local_38,param_1 + 5,1,(long *)0x0);
  local_14[0] = 0;
  local_38 = "String";
  lVar3 = *(long *)(param_1[1] + 0x10);
  lVar2 = (**(code **)(*param_1 + 0xa0))(param_1);
  uVar1 = FUN_71029634b0(lVar3,(long *)&local_38,lVar2 + 0x30,param_1,local_14,(undefined1 *)0x0,
                         in_x6,in_x7);
  FUN_7102962e4c((long)param_1,(ulong *)(param_1 + 6),uVar1,(uint)local_14[0]);
  return;
}



void FUN_71011f59c4(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if ((DAT_710406a5d8 & 1) == 0) {
    iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a5d8);
    if (iVar1 != 0) {
      DAT_710406a5d0 = DAT_7103a60348 + 0x10;
      thunk_EXT_FUN_02e95df0(&DAT_710406a5d8);
    }
  }
  if (param_2 != &DAT_710406a5d0) {
    FUN_710101133c(param_1,param_2);
    return;
  }
  return;
}



undefined8 * FUN_71011f5a50(void)

{
  int iVar1;
  
  if (((DAT_710406a5d8 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a5d8), iVar1 != 0))
  {
    DAT_710406a5d0 = DAT_7103a60348 + 0x10;
    thunk_EXT_FUN_02e95df0(&DAT_710406a5d8);
  }
  return &DAT_710406a5d0;
}



void FUN_71011f5aac(long *param_1)

{
  long *plVar1;
  
  *param_1 = DAT_7103a72c80 + 0x10;
  if ((long *)param_1[2] != (long *)0x0) {
    (**(code **)(*(long *)param_1[2] + 8))();
  }
  if (DAT_7105a06420 != 0) {
    plVar1 = FUN_71024ef490(DAT_7105a06420,param_1);
    if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071011f5b10. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
      return;
    }
    return;
  }
  FUN_71005fbbd0((long)param_1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_71011f5b50(void)

{
  int iVar1;
  
  DAT_710406a5c8 = (undefined8 *)0x0;
  DAT_710406a5b0 = 0xfcb7ab3c;
  DAT_710406a5b8 = FUN_71011f5628;
  DAT_710406a5c0 = (undefined8 *)0x0;
  if (((DAT_710405c890 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710405c890), iVar1 != 0))
  {
    DAT_710405c878 = &DAT_710405c878;
    DAT_710405c880 = &DAT_710405c878;
    _DAT_710405c888 = 0xffffffff00000000;
    thunk_EXT_FUN_02e95df0(DAT_7103a5fe28);
  }
  DAT_710406a5c0 = DAT_710405c878;
  DAT_710405c88c = 0x10;
  DAT_710405c878 = &DAT_710406a5c0;
  DAT_710406a5c8 = &DAT_710405c878;
  if (DAT_710406a5c0 != (undefined8 *)0x0) {
    DAT_710406a5c0[1] = &DAT_710406a5c0;
  }
  _DAT_710405c888 = CONCAT44(DAT_710405c88c,DAT_710405c888 + 1);
  return;
}



void FUN_71011f5c08(long *param_1)

{
  long lVar1;
  long lVar2;
  undefined8 *puVar3;
  
  lVar1 = DAT_7105a06420;
  if (DAT_7105a06420 == 0) {
    puVar3 = (undefined8 *)FUN_71005fbcb0(8,0x50);
  }
  else {
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar3 = (undefined8 *)(lVar1 + 8);
      if (lVar2 != 0) {
        puVar3 = (undefined8 *)(lVar2 + 0x88);
      }
      param_1 = (long *)*puVar3;
    }
    puVar3 = (undefined8 *)(**(code **)(*param_1 + 0x30))(param_1,0x50,8);
  }
  puVar3[2] = 0;
  puVar3[3] = 0;
  *(undefined1 *)((long)puVar3 + 0x1e) = 0xff;
  *puVar3 = &DAT_71038fe6e8;
  puVar3[1] = 0;
  puVar3[4] = 0;
  puVar3[5] = 0;
  puVar3[6] = 0;
  puVar3[7] = 0;
  puVar3[8] = 0;
  puVar3[9] = 0;
  return;
}



void FUN_71011f5e60(long *param_1)

{
  uint uVar1;
  long lVar2;
  undefined8 *puVar3;
  undefined8 in_x5;
  undefined8 in_x6;
  ulong uVar4;
  undefined8 in_x7;
  undefined8 uVar5;
  long lVar6;
  char *local_40;
  uint local_38;
  ushort local_34 [2];
  ushort local_18 [2];
  uint local_14;
  
  local_40 = "Prop_OnlyOnEnter";
  FUN_7101012e40(param_1,(long *)&local_40,param_1 + 5,1,0,in_x5,in_x6,in_x7);
  local_14 = 0;
  local_40 = "Vec3s";
  local_18[0] = 0xffff;
  local_34[0] = 0xffff;
  lVar6 = *(long *)(param_1[1] + 0x10);
  local_38 = 0;
  lVar2 = (**(code **)(*param_1 + 0xa0))(param_1);
  puVar3 = FUN_71011f0f70(lVar6,(long *)&local_40,lVar2 + 0x30,local_18,local_34,&local_14,
                          (long)param_1,(undefined1 *)0x0,&local_38);
  uVar4 = (ulong)local_34[0];
  uVar5 = 0;
  FUN_71011f11d0((long)param_1,(long *)&local_40,param_1 + 6,0,(ulong)local_14,(ulong)local_18[0],
                 uVar4,0,(ulong)puVar3,local_38);
  local_14 = local_14 & 0xffffff00;
  local_40 = "Result";
  lVar6 = *(long *)(param_1[1] + 0x10);
  lVar2 = (**(code **)(*param_1 + 0xa0))(param_1);
  uVar1 = FUN_7102963610(lVar6,(long *)&local_40,lVar2 + 0x30,param_1,(byte *)&local_14,
                         (undefined1 *)0x0,uVar4,uVar5);
  FUN_7102962d38((long)param_1,(ulong *)(param_1 + 9),uVar1,local_14 & 0xff);
  return;
}



void FUN_71011f5f98(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if ((DAT_710406a608 & 1) == 0) {
    iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a608);
    if (iVar1 != 0) {
      DAT_710406a600 = DAT_7103a60348 + 0x10;
      thunk_EXT_FUN_02e95df0(&DAT_710406a608);
    }
  }
  if (param_2 != &DAT_710406a600) {
    FUN_710101133c(param_1,param_2);
    return;
  }
  return;
}



undefined8 * FUN_71011f6024(void)

{
  int iVar1;
  
  if (((DAT_710406a608 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a608), iVar1 != 0))
  {
    DAT_710406a600 = DAT_7103a60348 + 0x10;
    thunk_EXT_FUN_02e95df0(&DAT_710406a608);
  }
  return &DAT_710406a600;
}



void FUN_71011f6080(long *param_1)

{
  long *plVar1;
  
  *param_1 = DAT_7103a72c80 + 0x10;
  if ((long *)param_1[2] != (long *)0x0) {
    (**(code **)(*(long *)param_1[2] + 8))();
  }
  if (DAT_7105a06420 != 0) {
    plVar1 = FUN_71024ef490(DAT_7105a06420,param_1);
    if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071011f60e4. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
      return;
    }
    return;
  }
  FUN_71005fbbd0((long)param_1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_71011f6120(void)

{
  int iVar1;
  
  DAT_710406a5f8 = (undefined8 *)0x0;
  DAT_710406a5e0 = 0xb6f93f87;
  DAT_710406a5e8 = FUN_71011f5c08;
  DAT_710406a5f0 = (undefined8 *)0x0;
  if (((DAT_710405c890 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710405c890), iVar1 != 0))
  {
    DAT_710405c878 = &DAT_710405c878;
    DAT_710405c880 = &DAT_710405c878;
    _DAT_710405c888 = 0xffffffff00000000;
    thunk_EXT_FUN_02e95df0(DAT_7103a5fe28);
  }
  DAT_710406a5f0 = DAT_710405c878;
  DAT_710405c88c = 0x10;
  DAT_710405c878 = &DAT_710406a5f0;
  DAT_710406a5f8 = &DAT_710405c878;
  if (DAT_710406a5f0 != (undefined8 *)0x0) {
    DAT_710406a5f0[1] = &DAT_710406a5f0;
  }
  _DAT_710405c888 = CONCAT44(DAT_710405c88c,DAT_710405c888 + 1);
  return;
}



void FUN_71011f61d8(long *param_1)

{
  long lVar1;
  long lVar2;
  undefined8 *puVar3;
  
  lVar1 = DAT_7105a06420;
  if (DAT_7105a06420 == 0) {
    puVar3 = (undefined8 *)FUN_71005fbcb0(8,0x40);
  }
  else {
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar3 = (undefined8 *)(lVar1 + 8);
      if (lVar2 != 0) {
        puVar3 = (undefined8 *)(lVar2 + 0x88);
      }
      param_1 = (long *)*puVar3;
    }
    puVar3 = (undefined8 *)(**(code **)(*param_1 + 0x30))(param_1,0x40,8);
  }
  puVar3[2] = 0;
  puVar3[3] = 0;
  *(undefined1 *)((long)puVar3 + 0x1e) = 0xff;
  *puVar3 = &DAT_71038fe820;
  puVar3[1] = 0;
  puVar3[4] = 0;
  puVar3[5] = 0;
  puVar3[6] = 0;
  puVar3[7] = 0;
  return;
}



long * FUN_71011f6270(long *param_1)

{
  long *plVar1;
  uint uVar2;
  long *plVar3;
  long lVar4;
  ulong uVar5;
  undefined8 *puVar6;
  int *piVar7;
  long lVar8;
  undefined8 local_90;
  undefined8 local_88;
  undefined1 *puStack_80;
  undefined4 local_78;
  undefined1 local_74 [63];
  undefined1 local_35;
  
  plVar3 = (long *)param_1[5];
  if (plVar3 == (long *)0x0 || plVar3 == (long *)&DAT_7105a09400) {
    lVar8 = *(long *)(*(long *)(param_1[1] + 8) + 0x1d8);
    (**(code **)(*param_1 + 0x90))(param_1);
    lVar4 = *(long *)(*(long *)(param_1[1] + 0x10) + 0x48) +
            (ulong)*(ushort *)((long)param_1 + 0x1c) * 0x3c;
    puStack_80 = local_74;
    local_90 = *(undefined8 *)(lVar4 + 0x2c);
    local_88 = *(undefined8 *)(lVar4 + 0x34);
    local_35 = 0;
    local_74[0] = 0;
    local_78 = 0x40;
    uVar2 = FUN_7100f700b0((long *)&puStack_80,0x7103176cba,(uint *)&local_90);
    plVar3 = (long *)(ulong)uVar2;
    for (lVar4 = *(long *)(lVar8 + 0x30); lVar4 != lVar8 + 0x28; lVar4 = *(long *)(lVar4 + 8)) {
      *(uint *)(*(long *)(lVar4 + 0x10) + 0x20) = *(uint *)(*(long *)(lVar4 + 0x10) + 0x20) | 4;
    }
  }
  else {
    lVar4 = *plVar3;
    if (lVar4 == 0) {
      lVar8 = *(long *)(*(long *)(param_1[1] + 8) + 0x1d8);
      (**(code **)(*param_1 + 0x90))(param_1);
      lVar4 = *(long *)(*(long *)(param_1[1] + 0x10) + 0x48) +
              (ulong)*(ushort *)((long)param_1 + 0x1c) * 0x3c;
      puStack_80 = local_74;
      local_90 = *(undefined8 *)(lVar4 + 0x2c);
      local_88 = *(undefined8 *)(lVar4 + 0x34);
      local_35 = 0;
      local_74[0] = 0;
      local_78 = 0x40;
      uVar2 = FUN_7100f700b0((long *)&puStack_80,0x7103176cba,(uint *)&local_90);
      plVar3 = (long *)(ulong)uVar2;
      for (lVar4 = *(long *)(lVar8 + 0x30); lVar4 != lVar8 + 0x28; lVar4 = *(long *)(lVar4 + 8)) {
        *(uint *)(*(long *)(lVar4 + 0x10) + 0x20) = *(uint *)(*(long *)(lVar4 + 0x10) + 0x20) | 4;
      }
    }
    else {
      uVar5 = param_1[7];
      plVar3 = param_1;
      if ((((uVar5 & 1) != 0) &&
          (plVar1 = (long *)(uVar5 & 0xfffffffffffffffc), plVar1 != (long *)0x0)) &&
         (plVar1 != (long *)&DAT_7105a09400)) {
        if (((((uint)uVar5 >> 1 & 1) != 0) && (*plVar1 != lVar4)) &&
           (plVar3 = (long *)thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a094a8 + 0x54)),
           (int)plVar3 < 0)) {
          plVar3 = (long *)thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a094a8 + 0x54),0x80000001)
          ;
        }
        *(long *)(param_1[7] & 0xfffffffffffffffc) = lVar4;
      }
      puVar6 = (undefined8 *)param_1[6];
      if ((puVar6 == (undefined8 *)0x0) || (puVar6 == (undefined8 *)&DAT_7105a09400)) {
        lVar8 = *(long *)(*(long *)(param_1[1] + 8) + 0x1d8);
        (**(code **)(*param_1 + 0x90))(param_1);
        lVar4 = *(long *)(*(long *)(param_1[1] + 0x10) + 0x48) +
                (ulong)*(ushort *)((long)param_1 + 0x1c) * 0x3c;
        puStack_80 = local_74;
        local_90 = *(undefined8 *)(lVar4 + 0x2c);
        local_88 = *(undefined8 *)(lVar4 + 0x34);
        local_35 = 0;
        local_74[0] = 0;
        local_78 = 0x40;
        uVar2 = FUN_7100f700b0((long *)&puStack_80,0x7103176cba,(uint *)&local_90);
        plVar3 = (long *)(ulong)uVar2;
        for (lVar4 = *(long *)(lVar8 + 0x30); lVar4 != lVar8 + 0x28; lVar4 = *(long *)(lVar4 + 8)) {
          *(uint *)(*(long *)(lVar4 + 0x10) + 0x20) = *(uint *)(*(long *)(lVar4 + 0x10) + 0x20) | 4;
        }
      }
      else {
        piVar7 = (int *)*puVar6;
        if (piVar7 != (int *)0x0) {
          if (*piVar7 == 4) {
            if (piVar7[2] != 2) {
              return plVar3;
            }
          }
          else {
            if (*piVar7 != 3) {
              return plVar3;
            }
            if (piVar7[2] != 1) {
              return plVar3;
            }
          }
          *(int *)(*(long *)param_1[5] + 0x600) = piVar7[1];
          return plVar3;
        }
        lVar8 = *(long *)(*(long *)(param_1[1] + 8) + 0x1d8);
        (**(code **)(*param_1 + 0x90))(param_1);
        lVar4 = *(long *)(*(long *)(param_1[1] + 0x10) + 0x48) +
                (ulong)*(ushort *)((long)param_1 + 0x1c) * 0x3c;
        puStack_80 = local_74;
        local_90 = *(undefined8 *)(lVar4 + 0x2c);
        local_88 = *(undefined8 *)(lVar4 + 0x34);
        local_35 = 0;
        local_74[0] = 0;
        local_78 = 0x40;
        uVar2 = FUN_7100f700b0((long *)&puStack_80,0x7103176cba,(uint *)&local_90);
        plVar3 = (long *)(ulong)uVar2;
        for (lVar4 = *(long *)(lVar8 + 0x30); lVar4 != lVar8 + 0x28; lVar4 = *(long *)(lVar4 + 8)) {
          *(uint *)(*(long *)(lVar4 + 0x10) + 0x20) = *(uint *)(*(long *)(lVar4 + 0x10) + 0x20) | 4;
        }
      }
    }
  }
  if ((*(uint *)(lVar8 + 0x20) >> 2 & 1) == 0) {
    *(uint *)(lVar8 + 0x20) = *(uint *)(lVar8 + 0x20) | 4;
  }
  return plVar3;
}



void FUN_71011f6600(long *param_1)

{
  uint uVar1;
  long lVar2;
  undefined8 in_x7;
  undefined *puVar3;
  long lVar4;
  char *local_30;
  char local_24 [4];
  
  local_30 = "MessageParam";
  FUN_710101275c(param_1,(long *)&local_30,param_1 + 5,1,(long *)0x0);
  local_30 = "TalkMediator";
  FUN_710101275c(param_1,(long *)&local_30,param_1 + 6,1,(long *)0x0);
  local_30 = "MessageParam";
  local_24[0] = '\0';
  lVar4 = *(long *)(param_1[1] + 0x10);
  lVar2 = (**(code **)(*param_1 + 0xa0))(param_1);
  uVar1 = FUN_7102963780(lVar4,(long *)&local_30,lVar2 + 0x30,param_1,local_24,(undefined1 *)0x0,
                         (long *)0x0,in_x7);
  if ((int)uVar1 < 0) {
    puVar3 = &DAT_7105a09400;
  }
  else {
    param_1[7] = 0;
    lVar2 = 0;
    if ((long *)param_1[2] != (long *)0x0) {
      lVar2 = (**(code **)(*(long *)param_1[2] + 0x10))();
    }
    puVar3 = (undefined *)(lVar2 + (ulong)uVar1 & 0xfffffffffffffffc);
  }
  param_1[7] = (long)puVar3;
  if (local_24[0] != '\0') {
    puVar3 = (undefined *)((ulong)puVar3 | 1);
    param_1[7] = (long)puVar3;
  }
  if ((*(byte *)(*(long *)(param_1[1] + 8) + 0x1ac) & 1) != 0) {
    param_1[7] = (ulong)puVar3 | 2;
  }
  return;
}



void FUN_71011f670c(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if ((DAT_710406a638 & 1) == 0) {
    iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a638);
    if (iVar1 != 0) {
      DAT_710406a630 = DAT_7103a60348 + 0x10;
      thunk_EXT_FUN_02e95df0(&DAT_710406a638);
    }
  }
  if (param_2 != &DAT_710406a630) {
    FUN_710101133c(param_1,param_2);
    return;
  }
  return;
}



undefined8 * FUN_71011f6798(void)

{
  int iVar1;
  
  if (((DAT_710406a638 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a638), iVar1 != 0))
  {
    DAT_710406a630 = DAT_7103a60348 + 0x10;
    thunk_EXT_FUN_02e95df0(&DAT_710406a638);
  }
  return &DAT_710406a630;
}



void FUN_71011f67f4(long *param_1)

{
  long *plVar1;
  
  *param_1 = DAT_7103a72c80 + 0x10;
  if ((long *)param_1[2] != (long *)0x0) {
    (**(code **)(*(long *)param_1[2] + 8))();
  }
  if (DAT_7105a06420 != 0) {
    plVar1 = FUN_71024ef490(DAT_7105a06420,param_1);
    if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071011f6858. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
      return;
    }
    return;
  }
  FUN_71005fbbd0((long)param_1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_71011f6890(void)

{
  int iVar1;
  
  DAT_710406a628 = (undefined8 *)0x0;
  DAT_710406a610 = 0x879c38f9;
  DAT_710406a618 = FUN_71011f61d8;
  DAT_710406a620 = (undefined8 *)0x0;
  if (((DAT_710405c890 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710405c890), iVar1 != 0))
  {
    DAT_710405c878 = &DAT_710405c878;
    DAT_710405c880 = &DAT_710405c878;
    _DAT_710405c888 = 0xffffffff00000000;
    thunk_EXT_FUN_02e95df0(DAT_7103a5fe28);
  }
  DAT_710406a620 = DAT_710405c878;
  DAT_710405c88c = 0x10;
  DAT_710405c878 = &DAT_710406a620;
  DAT_710406a628 = &DAT_710405c878;
  if (DAT_710406a620 != (undefined8 *)0x0) {
    DAT_710406a620[1] = &DAT_710406a620;
  }
  _DAT_710405c888 = CONCAT44(DAT_710405c88c,DAT_710405c888 + 1);
  return;
}



void FUN_71011f6948(long *param_1)

{
  long lVar1;
  long lVar2;
  undefined8 *puVar3;
  
  lVar1 = DAT_7105a06420;
  if (DAT_7105a06420 == 0) {
    puVar3 = (undefined8 *)FUN_71005fbcb0(8,0x50);
  }
  else {
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar3 = (undefined8 *)(lVar1 + 8);
      if (lVar2 != 0) {
        puVar3 = (undefined8 *)(lVar2 + 0x88);
      }
      param_1 = (long *)*puVar3;
    }
    puVar3 = (undefined8 *)(**(code **)(*param_1 + 0x30))(param_1,0x50,8);
  }
  puVar3[2] = 0;
  puVar3[3] = 0;
  *(undefined1 *)((long)puVar3 + 0x1e) = 0xff;
  *puVar3 = &DAT_71038fe958;
  puVar3[1] = 0;
  puVar3[4] = 0;
  puVar3[5] = 0;
  puVar3[6] = 0;
  puVar3[7] = 0;
  puVar3[8] = 0;
  puVar3[9] = 0;
  return;
}



void FUN_71011f6b30(long *param_1)

{
  char *pcVar1;
  bool bVar2;
  long lVar3;
  uint uVar4;
  long *plVar5;
  uint uVar6;
  undefined8 uVar7;
  undefined8 uVar8;
  ulong uVar9;
  undefined8 in_x5;
  undefined8 in_x6;
  ulong uVar10;
  undefined8 in_x7;
  long lVar11;
  undefined1 *puVar12;
  ulong uVar13;
  ulong uVar14;
  long lVar15;
  ushort *puVar16;
  char *local_160;
  undefined4 local_158;
  char local_154 [255];
  undefined1 local_55;
  char *local_38;
  
  local_160 = "Prop_OnUpdate";
  plVar5 = param_1 + 5;
  uVar7 = 1;
  uVar8 = 0;
  FUN_7101012e40(param_1,(long *)&local_160,plVar5,1,0,in_x5,in_x6,in_x7);
  local_38 = "Bools";
  lVar15 = *(long *)(param_1[1] + 0x10);
  lVar3 = (**(code **)(*param_1 + 0xa0))(param_1);
  uVar13 = (ulong)*(uint *)(lVar3 + 0x44);
  lVar11 = *(long *)(lVar15 + 0x10);
  if (0 < (int)*(uint *)(lVar3 + 0x44)) {
    puVar16 = (ushort *)
              ((long)*(int *)(*(long *)(lVar15 + 0x28) + 8) + (long)*(int *)(lVar3 + 0x40) * 0x10 +
               lVar11 + 6);
    do {
      pcVar1 = (char *)(lVar11 + *(int *)(lVar11 + 0x24) + (long)*(int *)(puVar16 + -3));
      if ((pcVar1 == "Bools") ||
         ((((*pcVar1 == 'B' && (pcVar1[1] == 'o')) && (pcVar1[2] == 'o')) &&
          (((pcVar1[3] == 'l' && (pcVar1[4] == 's')) && (pcVar1[5] == '\0')))))) {
        uVar6 = *(uint *)(puVar16 + 1);
        bVar2 = FUN_7102963914(param_1[1],(int)(short)puVar16[-1],plVar5,uVar7,uVar8,in_x5,in_x6,
                               in_x7);
        if ((!bVar2) && (uVar13 = (ulong)puVar16[-1], puVar16[-1] < 0xff9d)) {
          uVar10 = (ulong)(*puVar16 & 0x7fff);
          if ((uVar6 & 0xc2000000) == 0xc2000000) {
            puVar12 = (undefined1 *)0x0;
            uVar9 = (ulong)(*(uint *)(puVar16 + 1) & 0xfe7fffff);
          }
          else {
            uVar9 = 0;
            puVar12 = (undefined1 *)0x0;
          }
          goto LAB_71011f6ccc;
        }
        uVar9 = (ulong)(*(uint *)(puVar16 + 1) & 0xfe7fffff);
        if (((uVar6 & 0xc2000000) == 0xc2000000) || ((*(uint *)(puVar16 + 1) & 0xfe7fffff) == 0)) {
          puVar12 = DAT_7103a5fe70;
          if (*(int *)(puVar16 + 3) != 0) {
            puVar12 = DAT_7103a5fe78;
          }
        }
        else {
          puVar12 = (undefined1 *)0x0;
        }
        goto LAB_71011f6cc8;
      }
      puVar16 = puVar16 + 8;
      uVar13 = uVar13 - 1;
    } while (uVar13 != 0);
  }
  local_160 = local_154;
  local_55 = 0;
  local_158 = 0x100;
  local_154[0] = '\0';
  FUN_7100bc08f0((long *)&local_160,"%s.ain",
                 lVar11 + *(int *)(lVar11 + 0x24) + (long)*(int *)(lVar11 + 8),uVar7,uVar8,in_x5,
                 in_x6,in_x7);
  uVar9 = 0;
  puVar12 = DAT_7103a5fe68;
LAB_71011f6cc8:
  uVar13 = 0xffff;
  uVar10 = 0xffff;
LAB_71011f6ccc:
  uVar7 = 0;
  uVar8 = 0;
  FUN_71011f6ff0((long)param_1,(long *)&local_38,param_1 + 6,0,uVar9,uVar13,uVar10,0,puVar12);
  lVar11 = *(long *)(param_1[1] + 0x10);
  lVar3 = (**(code **)(*param_1 + 0xa0))(param_1);
  if (0 < (int)*(uint *)(lVar3 + 0x4c)) {
    uVar14 = 0;
    lVar15 = *(long *)(lVar11 + 0x10);
    do {
      uVar6 = *(uint *)(lVar15 + *(int *)(*(long *)(lVar11 + 0x28) + 0xc) +
                        (long)*(int *)(lVar3 + 0x48) * 4 + uVar14 * 4);
      pcVar1 = (char *)(lVar15 + *(int *)(lVar15 + 0x24) + ((ulong)uVar6 & 0x7fffffff));
      if ((pcVar1 == "Bool") ||
         ((((*pcVar1 == 'B' && (pcVar1[1] == 'o')) && (pcVar1[2] == 'o')) &&
          ((pcVar1[3] == 'l' && (pcVar1[4] == '\0')))))) {
        uVar6 = uVar6 >> 0x1f;
        uVar4 = (*(int *)(lVar3 + 0x3c) + (int)uVar14) * 4;
        goto LAB_71011f6df4;
      }
      uVar14 = uVar14 + 1;
    } while (*(uint *)(lVar3 + 0x4c) != uVar14);
  }
  local_55 = 0;
  local_160 = local_154;
  local_154[0] = '\0';
  local_158 = 0x100;
  lVar3 = *(long *)(lVar11 + 0x10);
  FUN_7100bc08f0((long *)&local_160,"%s.ain",
                 lVar3 + *(int *)(lVar3 + 0x24) + (long)*(int *)(lVar3 + 8),uVar7,uVar9,uVar13,
                 uVar10,uVar8);
  uVar6 = 0;
  uVar4 = 0xffffffff;
LAB_71011f6df4:
  FUN_7101075ff8((long)param_1,(ulong *)(param_1 + 9),uVar4,uVar6);
  return;
}



undefined8 * FUN_71011f6ef4(void)

{
  int iVar1;
  
  if (((DAT_710406a668 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a668), iVar1 != 0))
  {
    DAT_710406a660 = DAT_7103a60348 + 0x10;
    thunk_EXT_FUN_02e95df0(&DAT_710406a668);
  }
  return &DAT_710406a660;
}



void FUN_71011f6f50(long *param_1)

{
  long *plVar1;
  
  *param_1 = DAT_7103a72c80 + 0x10;
  if ((long *)param_1[2] != (long *)0x0) {
    (**(code **)(*(long *)param_1[2] + 8))();
  }
  if (DAT_7105a06420 != 0) {
    plVar1 = FUN_71024ef490(DAT_7105a06420,param_1);
    if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071011f6fb4. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
      return;
    }
    return;
  }
  FUN_71005fbbd0((long)param_1);
  return;
}



uint FUN_71011f6ff0(long param_1,long *param_2,long *param_3,ulong param_4,undefined8 param_5,
                   ulong param_6,ulong param_7,ulong param_8,undefined1 *param_9)

{
  int iVar1;
  char cVar2;
  ushort uVar3;
  short sVar4;
  uint uVar5;
  bool bVar6;
  bool bVar7;
  uint uVar8;
  uint *puVar9;
  undefined4 *puVar10;
  int *piVar11;
  long *plVar12;
  ulong uVar13;
  ulong uVar14;
  uint uVar15;
  int iVar16;
  ulong uVar17;
  long lVar18;
  long *plVar19;
  long lVar20;
  ulong uVar21;
  long lVar22;
  undefined1 *puVar23;
  undefined4 uVar24;
  ulong uVar25;
  long *plVar26;
  undefined1 *puVar27;
  undefined1 *local_178;
  undefined4 local_170;
  undefined1 local_16c [255];
  undefined1 local_6d;
  
  uVar25 = param_8 & 0xffffffff;
  sVar4 = (short)param_6;
  uVar8 = (uint)param_8;
  if (-100 < sVar4) {
    uVar8 = FUN_7101012300(param_1,param_2,param_3 + 2,(ulong)((uint)param_4 & 1),param_5,
                           param_6 & 0xffffffff,param_7 & 0xffffffff,(ulong)(uVar8 & 1),param_9);
    return uVar8;
  }
  uVar14 = param_7;
  if ((*DAT_7103a60848 & 1) == 0) {
    param_4 = param_4 & 0xffffffff;
    iVar16 = thunk_EXT_FUN_02e95df0(DAT_7103a60848);
    if (iVar16 != 0) {
      *DAT_7103a60840 = 0;
      thunk_EXT_FUN_02e95df0(DAT_7103a60848);
    }
  }
  uVar5 = (uint)(short)param_7;
  bVar7 = *param_3 != 0;
  lVar22 = *(long *)(*(long *)(*(long *)(param_1 + 8) + 0x10) + 0x10);
  iVar16 = *(int *)(lVar22 + 0x38);
  uVar13 = param_4;
  if (bVar7 || (param_4 & 1) != 0) {
    if (*param_3 == 0) {
      puVar9 = (uint *)(**(code **)(**(long **)(param_1 + 0x10) + 0x70))();
      if ((int)*puVar9 < 1) {
        uVar24 = 0xffffffff;
      }
      else {
        lVar18 = *param_2;
        uVar17 = 0;
        uVar24 = 0xffffffff;
        do {
          lVar20 = *(long *)(*(long *)(puVar9 + 2) + uVar17 * 8);
          if (lVar18 == lVar20) {
LAB_71011f7224:
            uVar24 = (undefined4)uVar17;
            break;
          }
          bVar6 = true;
          for (uVar21 = 0; *(char *)(lVar18 + uVar21) == *(char *)(lVar20 + uVar21);
              uVar21 = uVar21 + 2) {
            if (*(char *)(lVar18 + uVar21) == '\0') {
LAB_71011f7150:
              if (bVar6) goto LAB_71011f7224;
              break;
            }
            if ((uVar21 == 0x400000) ||
               (cVar2 = *(char *)(lVar18 + uVar21 + 1), cVar2 != *(char *)(lVar20 + uVar21 + 1)))
            break;
            if (cVar2 == '\0') {
              bVar6 = uVar21 < 0x400000;
              goto LAB_71011f7150;
            }
            bVar6 = uVar21 + 1 < 0x400000;
          }
          uVar17 = uVar17 + 1;
        } while (uVar17 != *puVar9);
      }
      lVar18 = (**(code **)(**(long **)(param_1 + 0x10) + 0x68))();
      *(undefined4 *)(param_3 + 1) = uVar24;
      *(uint *)((long)param_3 + 0xc) = uVar5;
      *param_3 = lVar18;
    }
LAB_71011f7244:
    if (0 < (int)uVar5) {
      uVar17 = 0;
      lVar22 = lVar22 + iVar16 + (-100 - (long)sVar4) * 8;
      puVar23 = DAT_7103a60840;
      do {
        sVar4 = *(short *)(lVar22 + uVar17 * 8);
        iVar16 = (int)sVar4;
        lVar18 = *(long *)(param_1 + 8);
        uVar8 = *(uint *)(lVar18 + 0x60);
        if (uVar8 == (int)sVar4 || (int)uVar8 < (int)sVar4) {
          local_6d = 0;
          local_170 = 0x100;
          local_16c[0] = 0;
          lVar18 = *(long *)(*(long *)(lVar18 + 0x10) + 0x10);
          local_178 = local_16c;
          FUN_7100bc08f0((long *)&local_178,"%s.ain",
                         lVar18 + *(int *)(lVar18 + 0x24) + (long)*(int *)(lVar18 + 8),uVar13,
                         param_5,param_6,uVar14,param_8);
          lVar18 = *(long *)(param_1 + 8);
LAB_71011f7384:
          local_6d = 0;
          local_170 = 0x100;
          local_16c[0] = 0;
          lVar18 = *(long *)(*(long *)(lVar18 + 0x10) + 0x10);
          local_178 = local_16c;
          FUN_7100bc08f0((long *)&local_178,"%s.ain",
                         lVar18 + *(int *)(lVar18 + 0x24) + (long)*(int *)(lVar18 + 8),uVar13,
                         param_5,param_6,uVar14,param_8);
          uVar25 = 1;
          puVar27 = puVar23;
LAB_71011f73c8:
          if (bVar7 || (param_4 & 1) != 0) goto LAB_71011f73cc;
LAB_71011f7630:
          piVar11 = (int *)*param_3;
          if (*piVar11 < piVar11[1]) {
            *(undefined1 **)(*(long *)(piVar11 + 2) + (long)*piVar11 * 8) = puVar27;
            *piVar11 = *piVar11 + 1;
          }
          if (uVar17 != 0) {
            piVar11 = (int *)(**(code **)(**(long **)(param_1 + 0x10) + 0x70))();
            if (*piVar11 < piVar11[1]) {
              *(undefined8 *)(*(long *)(piVar11 + 2) + (long)*piVar11 * 8) = 0;
              *piVar11 = *piVar11 + 1;
            }
          }
        }
        else {
          if (uVar8 < (uint)(int)sVar4 || uVar8 == (int)sVar4) {
            iVar16 = 0;
          }
          plVar26 = *(long **)(*(long *)(lVar18 + 0x68) + (long)iVar16 * 8);
          if (plVar26 == (long *)0x0) goto LAB_71011f7384;
          lVar18 = lVar22 + uVar17 * 8;
          sVar4 = *(short *)(lVar18 + 2);
          lVar20 = (**(code **)(*plVar26 + 0xa0))(plVar26);
          puVar9 = (uint *)(lVar18 + 4);
          uVar15 = *puVar9;
          uVar8 = uVar15 & 0xc2000000;
          iVar16 = (int)sVar4;
          if (uVar8 != 0xc2000000) {
switchD_71011f7338_caseD_2:
            iVar16 = *(int *)(lVar20 + 0x3c) + iVar16;
LAB_71011f73f8:
            iVar16 = iVar16 << 2;
            goto LAB_71011f7404;
          }
          uVar15 = uVar15 & 0xffff;
          lVar18 = *(long *)(*(long *)(*(long *)(param_1 + 8) + 0x10) + 0x50);
          piVar11 = (int *)(lVar18 + (ulong)*(uint *)(lVar18 + 0x18));
          if ((int)uVar15 < *piVar11) {
            switch(*(undefined2 *)((long)piVar11 + (ulong)uVar15 * 0x1c + 0x1e)) {
            case 2:
              goto switchD_71011f7338_caseD_2;
            case 3:
            case 4:
              iVar16 = iVar16 << 2;
              break;
            case 5:
              iVar16 = *(int *)(lVar20 + 0x3c) + iVar16 + *(int *)(lVar20 + 0x4c);
              goto LAB_71011f73f8;
            case 6:
              iVar16 = (*(int *)(lVar20 + 0x4c) + *(int *)(lVar20 + 0x3c) + *(int *)(lVar20 + 0x5c))
                       * 4 + iVar16 * 8;
              break;
            case 7:
              iVar16 = iVar16 * 0xc + *(int *)(lVar20 + 0x6c) * 8 +
                       (*(int *)(lVar20 + 0x4c) + *(int *)(lVar20 + 0x3c) + *(int *)(lVar20 + 0x5c))
                       * 4;
              break;
            default:
              goto switchD_71011f7338_default;
            }
          }
          else {
switchD_71011f7338_default:
            iVar16 = 0;
          }
LAB_71011f7404:
          lVar18 = 0;
          if ((long *)plVar26[2] != (long *)0x0) {
            lVar18 = (**(code **)(*(long *)plVar26[2] + 0x10))();
          }
          puVar27 = (undefined1 *)(lVar18 + iVar16);
          puVar23 = DAT_7103a60840;
          if (uVar8 != 0xc2000000) goto LAB_71011f73c8;
          if (!bVar7 && (param_4 & 1) == 0) {
            uVar3 = *(ushort *)puVar9;
            (**(code **)(**(long **)(param_1 + 0x10) + 0x58))();
            piVar11 = (int *)(**(code **)(**(long **)(param_1 + 0x10) + 0x58))();
            plVar26 = *(long **)(piVar11 + 4);
            if (plVar26 != (long *)0x0) {
              *(long *)(piVar11 + 4) = *plVar26;
            }
            plVar26[6] = 0xffffffff;
            lVar18 = DAT_7103a59fe0;
            plVar26[2] = 0;
            plVar26[3] = 0;
            plVar26[4] = 0;
            plVar26[5] = 0;
            *plVar26 = lVar18;
            plVar26[1] = 0;
            if (*piVar11 < piVar11[1]) {
              *(long **)(*(long *)(piVar11 + 2) + (long)*piVar11 * 8) = plVar26;
              *piVar11 = *piVar11 + 1;
            }
            lVar18 = *param_2;
            *(uint *)(plVar26 + 5) = (uint)uVar3;
            *(undefined4 *)((long)plVar26 + 0x2c) = 2;
            *plVar26 = lVar18;
            plVar26[1] = (long)puVar27;
            lVar18 = (**(code **)(**(long **)(param_1 + 0x10) + 0x50))();
            if (lVar18 == 0) {
              puVar27 = (undefined1 *)0x0;
            }
            else {
              plVar12 = (long *)(**(code **)(**(long **)(param_1 + 0x10) + 0x50))();
              uVar8 = *(uint *)(plVar12 + 2);
              if (uVar8 < *(uint *)((long)plVar12 + 0x14)) {
                puVar27 = (undefined1 *)0x0;
              }
              else {
                *(uint *)(plVar12 + 2) = uVar8 - 1;
                puVar27 = (undefined1 *)(*plVar12 + (ulong)uVar8 * 4);
              }
            }
            puVar23 = DAT_7103a60840;
            plVar26[2] = (long)puVar27;
            *(int *)(plVar26 + 6) = (int)uVar17;
            goto LAB_71011f7630;
          }
          piVar11 = (int *)(**(code **)(**(long **)(param_1 + 0x10) + 0x58))();
          puVar23 = DAT_7103a60840;
          if (*piVar11 != 0) {
            plVar26 = *(long **)(piVar11 + 2);
            plVar12 = plVar26 + *piVar11;
            lVar18 = *param_2;
            do {
              plVar19 = (long *)*plVar26;
              lVar20 = *plVar19;
              if (lVar20 == lVar18) {
LAB_71011f7470:
                if (*(int *)((long)plVar19 + 0x2c) == 2 && uVar17 == *(uint *)(plVar19 + 6)) {
                  puVar27 = (undefined1 *)plVar19[2];
                  break;
                }
              }
              else {
                bVar6 = true;
                for (uVar21 = 0; *(char *)(lVar20 + uVar21) == *(char *)(lVar18 + uVar21);
                    uVar21 = uVar21 + 2) {
                  if (*(char *)(lVar20 + uVar21) == '\0') {
LAB_71011f74f8:
                    if (bVar6) goto LAB_71011f7470;
                    break;
                  }
                  if ((uVar21 == 0x400000) ||
                     (cVar2 = *(char *)(lVar20 + uVar21 + 1),
                     cVar2 != *(char *)(lVar18 + uVar21 + 1))) break;
                  if (cVar2 == '\0') {
                    bVar6 = uVar21 < 0x400000;
                    goto LAB_71011f74f8;
                  }
                  bVar6 = uVar21 + 1 < 0x400000;
                }
              }
              plVar26 = plVar26 + 1;
            } while (plVar26 != plVar12);
            goto LAB_71011f73c8;
          }
LAB_71011f73cc:
          uVar8 = (int)param_3[1] + (int)uVar17;
          if (uVar8 < *(uint *)*param_3) {
            *(undefined1 **)(*(long *)((uint *)*param_3 + 2) + (long)(int)uVar8 * 8) = puVar27;
          }
        }
        uVar8 = (uint)uVar25;
        uVar17 = uVar17 + 1;
      } while (uVar17 != uVar5);
    }
    uVar8 = uVar8 ^ 1;
  }
  else {
    lVar18 = (**(code **)(**(long **)(param_1 + 0x10) + 0x68))();
    if (lVar18 != 0) {
      lVar18 = (**(code **)(**(long **)(param_1 + 0x10) + 0x68))();
      iVar1 = *(int *)(lVar18 + 4);
      piVar11 = (int *)(**(code **)(**(long **)(param_1 + 0x10) + 0x68))();
      if ((int)uVar5 <= iVar1 - *piVar11) {
        puVar10 = (undefined4 *)(**(code **)(**(long **)(param_1 + 0x10) + 0x68))();
        *param_3 = (long)puVar10;
        *(undefined4 *)(param_3 + 1) = *puVar10;
        *(uint *)((long)param_3 + 0xc) = uVar5;
        piVar11 = (int *)(**(code **)(**(long **)(param_1 + 0x10) + 0x70))();
        if (*piVar11 < piVar11[1]) {
          *(long *)(*(long *)(piVar11 + 2) + (long)*piVar11 * 8) = *param_2;
          *piVar11 = *piVar11 + 1;
        }
        goto LAB_71011f7244;
      }
    }
    uVar8 = 0;
  }
  return uVar8 & 1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_71011f7770(void)

{
  int iVar1;
  
  DAT_710406a658 = (undefined8 *)0x0;
  DAT_710406a640 = 0x546031f3;
  DAT_710406a648 = FUN_71011f6948;
  DAT_710406a650 = (undefined8 *)0x0;
  if (((DAT_710405c890 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710405c890), iVar1 != 0))
  {
    DAT_710405c878 = &DAT_710405c878;
    DAT_710405c880 = &DAT_710405c878;
    _DAT_710405c888 = 0xffffffff00000000;
    thunk_EXT_FUN_02e95df0(DAT_7103a5fe28);
  }
  DAT_710406a650 = DAT_710405c878;
  DAT_710405c88c = 0x10;
  DAT_710405c878 = &DAT_710406a650;
  DAT_710406a658 = &DAT_710405c878;
  if (DAT_710406a650 != (undefined8 *)0x0) {
    DAT_710406a650[1] = &DAT_710406a650;
  }
  _DAT_710405c888 = CONCAT44(DAT_710405c88c,DAT_710405c888 + 1);
  return;
}



void FUN_71011f7828(long *param_1)

{
  long lVar1;
  long lVar2;
  undefined8 *puVar3;
  
  lVar1 = DAT_7105a06420;
  if (DAT_7105a06420 == 0) {
    puVar3 = (undefined8 *)FUN_71005fbcb0(8,0x48);
  }
  else {
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar3 = (undefined8 *)(lVar1 + 8);
      if (lVar2 != 0) {
        puVar3 = (undefined8 *)(lVar2 + 0x88);
      }
      param_1 = (long *)*puVar3;
    }
    puVar3 = (undefined8 *)(**(code **)(*param_1 + 0x30))(param_1,0x48,8);
  }
  puVar3[2] = 0;
  puVar3[3] = 0;
  *(undefined1 *)((long)puVar3 + 0x1e) = 0xff;
  puVar3[8] = 0;
  *puVar3 = &DAT_71038fea90;
  puVar3[1] = 0;
  puVar3[4] = 0;
  puVar3[5] = 0;
  puVar3[6] = 0;
  puVar3[7] = 0;
  return;
}



undefined8 * FUN_71011f7da8(void)

{
  int iVar1;
  
  if (((DAT_710406a6a8 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a6a8), iVar1 != 0))
  {
    DAT_710406a6a0 = DAT_7103a60348 + 0x10;
    thunk_EXT_FUN_02e95df0(&DAT_710406a6a8);
  }
  return &DAT_710406a6a0;
}



void FUN_71011f7e04(long *param_1)

{
  long *plVar1;
  
  *param_1 = DAT_7103a72c80 + 0x10;
  if ((long *)param_1[2] != (long *)0x0) {
    (**(code **)(*(long *)param_1[2] + 8))();
  }
  if (DAT_7105a06420 != 0) {
    plVar1 = FUN_71024ef490(DAT_7105a06420,param_1);
    if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071011f7e68. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
      return;
    }
    return;
  }
  FUN_71005fbbd0((long)param_1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_71011f7ea0(void)

{
  int iVar1;
  
  DAT_710406a698 = (undefined8 *)0x0;
  DAT_710406a680 = 0xd4a1ca5f;
  DAT_710406a688 = FUN_71011f7828;
  DAT_710406a690 = (undefined8 *)0x0;
  if (((DAT_710405c890 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710405c890), iVar1 != 0))
  {
    DAT_710405c878 = &DAT_710405c878;
    DAT_710405c880 = &DAT_710405c878;
    _DAT_710405c888 = 0xffffffff00000000;
    thunk_EXT_FUN_02e95df0(DAT_7103a5fe28);
  }
  DAT_710406a690 = DAT_710405c878;
  DAT_710405c88c = 0x10;
  DAT_710405c878 = &DAT_710406a690;
  DAT_710406a698 = &DAT_710405c878;
  if (DAT_710406a690 != (undefined8 *)0x0) {
    DAT_710406a690[1] = &DAT_710406a690;
  }
  _DAT_710405c888 = CONCAT44(DAT_710405c88c,DAT_710405c888 + 1);
  return;
}



void FUN_71011f7f58(long *param_1)

{
  long lVar1;
  long lVar2;
  undefined8 *puVar3;
  
  lVar1 = DAT_7105a06420;
  if (DAT_7105a06420 == 0) {
    puVar3 = (undefined8 *)FUN_71005fbcb0(8,0x30);
  }
  else {
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar3 = (undefined8 *)(lVar1 + 8);
      if (lVar2 != 0) {
        puVar3 = (undefined8 *)(lVar2 + 0x88);
      }
      param_1 = (long *)*puVar3;
    }
    puVar3 = (undefined8 *)(**(code **)(*param_1 + 0x30))(param_1,0x30,8);
  }
  puVar3[2] = 0;
  puVar3[3] = 0;
  *(undefined1 *)((long)puVar3 + 0x1e) = 0xff;
  *puVar3 = &DAT_71038febc8;
  puVar3[1] = 0;
  puVar3[4] = 0;
  puVar3[5] = 0;
  return;
}



void FUN_71011f7fec(long param_1)

{
  uint uVar1;
  char *pcVar2;
  long *plVar3;
  int iVar4;
  undefined8 *puVar5;
  long lVar6;
  
  if (*(uint *)(*DAT_7103a65d78 + 0x178) < 3) {
    puVar5 = (undefined8 *)0x0;
  }
  else {
    puVar5 = *(undefined8 **)(*(long *)(*DAT_7103a65d78 + 0x180) + 0x10);
  }
  if (((*DAT_7103a65d30 & 1) == 0) && (iVar4 = thunk_EXT_FUN_02e95df0(DAT_7103a65d30), iVar4 != 0))
  {
    *DAT_7103a65d28 = DAT_7103a65d38 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a65d30);
  }
  lVar6 = (**(code **)*puVar5)(puVar5,DAT_7103a65d28);
  plVar3 = DAT_7103a5c670;
  uVar1 = *(uint *)(lVar6 + 8) & 0x8001;
  if (((((uint)*(ulong *)(param_1 + 0x28) >> 1 & 1) != 0) &&
      (pcVar2 = (char *)(*(ulong *)(param_1 + 0x28) & 0xfffffffffffffffc), pcVar2 != (char *)0x0))
     && ((bool)*pcVar2 != (uVar1 != 0))) {
    iVar4 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(*DAT_7103a5c670 + 0x54));
    if (iVar4 < 0) {
      thunk_EXT_FUN_02e95df0(*(undefined4 *)(*plVar3 + 0x54),0x80000001);
    }
  }
  *(bool *)(*(ulong *)(param_1 + 0x28) & 0xfffffffffffffffc) = uVar1 != 0;
  return;
}



void FUN_71011f8114(long param_1)

{
  uint uVar1;
  char *pcVar2;
  long *plVar3;
  int iVar4;
  undefined8 *puVar5;
  long lVar6;
  
  if (*(uint *)(*DAT_7103a65d78 + 0x178) < 3) {
    puVar5 = (undefined8 *)0x0;
  }
  else {
    puVar5 = *(undefined8 **)(*(long *)(*DAT_7103a65d78 + 0x180) + 0x10);
  }
  if (((*DAT_7103a65d30 & 1) == 0) && (iVar4 = thunk_EXT_FUN_02e95df0(DAT_7103a65d30), iVar4 != 0))
  {
    *DAT_7103a65d28 = DAT_7103a65d38 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a65d30);
  }
  lVar6 = (**(code **)*puVar5)(puVar5,DAT_7103a65d28);
  plVar3 = DAT_7103a5c670;
  uVar1 = *(uint *)(lVar6 + 8) & 0x8001;
  if (((((uint)*(ulong *)(param_1 + 0x28) >> 1 & 1) != 0) &&
      (pcVar2 = (char *)(*(ulong *)(param_1 + 0x28) & 0xfffffffffffffffc), pcVar2 != (char *)0x0))
     && ((bool)*pcVar2 != (uVar1 != 0))) {
    iVar4 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(*DAT_7103a5c670 + 0x54));
    if (iVar4 < 0) {
      thunk_EXT_FUN_02e95df0(*(undefined4 *)(*plVar3 + 0x54),0x80000001);
    }
  }
  *(bool *)(*(ulong *)(param_1 + 0x28) & 0xfffffffffffffffc) = uVar1 != 0;
  return;
}



void FUN_71011f8240(long *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                   undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  char *pcVar1;
  long lVar2;
  uint uVar3;
  uint uVar4;
  ulong uVar5;
  long lVar6;
  long lVar7;
  undefined1 *local_140;
  undefined4 local_138;
  undefined1 local_134 [255];
  undefined1 local_35;
  
  lVar7 = *(long *)(param_1[1] + 0x10);
  lVar2 = (**(code **)(*param_1 + 0xa0))();
  if (0 < (int)*(uint *)(lVar2 + 0x4c)) {
    uVar5 = 0;
    lVar6 = *(long *)(lVar7 + 0x10);
    do {
      uVar4 = *(uint *)(lVar6 + *(int *)(*(long *)(lVar7 + 0x28) + 0xc) +
                        (long)*(int *)(lVar2 + 0x48) * 4 + uVar5 * 4);
      pcVar1 = (char *)(lVar6 + *(int *)(lVar6 + 0x24) + ((ulong)uVar4 & 0x7fffffff));
      if ((pcVar1 == "Bool") ||
         ((((*pcVar1 == 'B' && (pcVar1[1] == 'o')) && (pcVar1[2] == 'o')) &&
          ((pcVar1[3] == 'l' && (pcVar1[4] == '\0')))))) {
        uVar4 = uVar4 >> 0x1f;
        uVar3 = (*(int *)(lVar2 + 0x3c) + (int)uVar5) * 4;
        goto LAB_71011f8358;
      }
      uVar5 = uVar5 + 1;
    } while (*(uint *)(lVar2 + 0x4c) != uVar5);
  }
  local_35 = 0;
  local_140 = local_134;
  local_134[0] = 0;
  local_138 = 0x100;
  lVar2 = *(long *)(lVar7 + 0x10);
  FUN_7100bc08f0((long *)&local_140,"%s.ain",
                 lVar2 + *(int *)(lVar2 + 0x24) + (long)*(int *)(lVar2 + 8),param_4,param_5,param_6,
                 param_7,param_8);
  uVar4 = 0;
  uVar3 = 0xffffffff;
LAB_71011f8358:
  FUN_7101075ff8((long)param_1,(ulong *)(param_1 + 5),uVar3,uVar4);
  return;
}



void FUN_71011f8378(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if ((DAT_710406a6d8 & 1) == 0) {
    iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a6d8);
    if (iVar1 != 0) {
      DAT_710406a6d0 = DAT_7103a60348 + 0x10;
      thunk_EXT_FUN_02e95df0(&DAT_710406a6d8);
    }
  }
  if (param_2 != &DAT_710406a6d0) {
    FUN_710101133c(param_1,param_2);
    return;
  }
  return;
}



undefined8 * FUN_71011f8404(void)

{
  int iVar1;
  
  if (((DAT_710406a6d8 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a6d8), iVar1 != 0))
  {
    DAT_710406a6d0 = DAT_7103a60348 + 0x10;
    thunk_EXT_FUN_02e95df0(&DAT_710406a6d8);
  }
  return &DAT_710406a6d0;
}



void FUN_71011f8460(long *param_1)

{
  long *plVar1;
  
  *param_1 = DAT_7103a72c80 + 0x10;
  if ((long *)param_1[2] != (long *)0x0) {
    (**(code **)(*(long *)param_1[2] + 8))();
  }
  if (DAT_7105a06420 != 0) {
    plVar1 = FUN_71024ef490(DAT_7105a06420,param_1);
    if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071011f84c4. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
      return;
    }
    return;
  }
  FUN_71005fbbd0((long)param_1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_71011f8500(void)

{
  int iVar1;
  
  DAT_710406a6c8 = (undefined8 *)0x0;
  DAT_710406a6b0 = 0xc53418df;
  DAT_710406a6b8 = FUN_71011f7f58;
  DAT_710406a6c0 = (undefined8 *)0x0;
  if (((DAT_710405c890 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710405c890), iVar1 != 0))
  {
    DAT_710405c878 = &DAT_710405c878;
    DAT_710405c880 = &DAT_710405c878;
    _DAT_710405c888 = 0xffffffff00000000;
    thunk_EXT_FUN_02e95df0(DAT_7103a5fe28);
  }
  DAT_710406a6c0 = DAT_710405c878;
  DAT_710405c88c = 0x10;
  DAT_710405c878 = &DAT_710406a6c0;
  DAT_710406a6c8 = &DAT_710405c878;
  if (DAT_710406a6c0 != (undefined8 *)0x0) {
    DAT_710406a6c0[1] = &DAT_710406a6c0;
  }
  _DAT_710405c888 = CONCAT44(DAT_710405c88c,DAT_710405c888 + 1);
  return;
}



void FUN_71011f85b8(long *param_1)

{
  long lVar1;
  long lVar2;
  undefined8 *puVar3;
  
  lVar1 = DAT_7105a06420;
  if (DAT_7105a06420 == 0) {
    puVar3 = (undefined8 *)FUN_71005fbcb0(8,0x38);
  }
  else {
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar3 = (undefined8 *)(lVar1 + 8);
      if (lVar2 != 0) {
        puVar3 = (undefined8 *)(lVar2 + 0x88);
      }
      param_1 = (long *)*puVar3;
    }
    puVar3 = (undefined8 *)(**(code **)(*param_1 + 0x30))(param_1,0x38,8);
  }
  puVar3[6] = 0;
  puVar3[2] = 0;
  puVar3[3] = 0;
  *(undefined1 *)((long)puVar3 + 0x1e) = 0xff;
  *puVar3 = &DAT_71038fed00;
  puVar3[1] = 0;
  puVar3[4] = 0;
  puVar3[5] = 0;
  return;
}



void FUN_71011f8650(long param_1)

{
  uint uVar1;
  char *pcVar2;
  long *plVar3;
  int iVar4;
  undefined8 *puVar5;
  long lVar6;
  
  if (*(uint *)(*DAT_7103a65d78 + 0x178) < 3) {
    puVar5 = (undefined8 *)0x0;
  }
  else {
    puVar5 = *(undefined8 **)(*(long *)(*DAT_7103a65d78 + 0x180) + 0x10);
  }
  if (((*DAT_7103a65d30 & 1) == 0) && (iVar4 = thunk_EXT_FUN_02e95df0(DAT_7103a65d30), iVar4 != 0))
  {
    *DAT_7103a65d28 = DAT_7103a65d38 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a65d30);
  }
  lVar6 = (**(code **)*puVar5)(puVar5,DAT_7103a65d28);
  plVar3 = DAT_7103a5c670;
  uVar1 = *(uint *)(lVar6 + 8) & **(uint **)(param_1 + 0x28);
  if (((((uint)*(ulong *)(param_1 + 0x30) >> 1 & 1) != 0) &&
      (pcVar2 = (char *)(*(ulong *)(param_1 + 0x30) & 0xfffffffffffffffc), pcVar2 != (char *)0x0))
     && ((bool)*pcVar2 != (uVar1 != 0))) {
    iVar4 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(*DAT_7103a5c670 + 0x54));
    if (iVar4 < 0) {
      thunk_EXT_FUN_02e95df0(*(undefined4 *)(*plVar3 + 0x54),0x80000001);
    }
  }
  *(bool *)(*(ulong *)(param_1 + 0x30) & 0xfffffffffffffffc) = uVar1 != 0;
  return;
}



void FUN_71011f8778(long param_1)

{
  uint uVar1;
  char *pcVar2;
  long *plVar3;
  int iVar4;
  undefined8 *puVar5;
  long lVar6;
  
  if (*(uint *)(*DAT_7103a65d78 + 0x178) < 3) {
    puVar5 = (undefined8 *)0x0;
  }
  else {
    puVar5 = *(undefined8 **)(*(long *)(*DAT_7103a65d78 + 0x180) + 0x10);
  }
  if (((*DAT_7103a65d30 & 1) == 0) && (iVar4 = thunk_EXT_FUN_02e95df0(DAT_7103a65d30), iVar4 != 0))
  {
    *DAT_7103a65d28 = DAT_7103a65d38 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a65d30);
  }
  lVar6 = (**(code **)*puVar5)(puVar5,DAT_7103a65d28);
  plVar3 = DAT_7103a5c670;
  uVar1 = *(uint *)(lVar6 + 8) & **(uint **)(param_1 + 0x28);
  if (((((uint)*(ulong *)(param_1 + 0x30) >> 1 & 1) != 0) &&
      (pcVar2 = (char *)(*(ulong *)(param_1 + 0x30) & 0xfffffffffffffffc), pcVar2 != (char *)0x0))
     && ((bool)*pcVar2 != (uVar1 != 0))) {
    iVar4 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(*DAT_7103a5c670 + 0x54));
    if (iVar4 < 0) {
      thunk_EXT_FUN_02e95df0(*(undefined4 *)(*plVar3 + 0x54),0x80000001);
    }
  }
  *(bool *)(*(ulong *)(param_1 + 0x30) & 0xfffffffffffffffc) = uVar1 != 0;
  return;
}



void FUN_71011f8a10(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if ((DAT_710406a708 & 1) == 0) {
    iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a708);
    if (iVar1 != 0) {
      DAT_710406a700 = DAT_7103a60348 + 0x10;
      thunk_EXT_FUN_02e95df0(&DAT_710406a708);
    }
  }
  if (param_2 != &DAT_710406a700) {
    FUN_710101133c(param_1,param_2);
    return;
  }
  return;
}



undefined8 * FUN_71011f8a9c(void)

{
  int iVar1;
  
  if (((DAT_710406a708 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a708), iVar1 != 0))
  {
    DAT_710406a700 = DAT_7103a60348 + 0x10;
    thunk_EXT_FUN_02e95df0(&DAT_710406a708);
  }
  return &DAT_710406a700;
}



void FUN_71011f8af8(long *param_1)

{
  long *plVar1;
  
  *param_1 = DAT_7103a72c80 + 0x10;
  if ((long *)param_1[2] != (long *)0x0) {
    (**(code **)(*(long *)param_1[2] + 8))();
  }
  if (DAT_7105a06420 != 0) {
    plVar1 = FUN_71024ef490(DAT_7105a06420,param_1);
    if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071011f8b5c. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
      return;
    }
    return;
  }
  FUN_71005fbbd0((long)param_1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_71011f8ba0(void)

{
  int iVar1;
  
  DAT_710406a6f8 = (undefined8 *)0x0;
  DAT_710406a6e0 = 0xf6ed68f7;
  DAT_710406a6e8 = FUN_71011f85b8;
  DAT_710406a6f0 = (undefined8 *)0x0;
  if (((DAT_710405c890 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710405c890), iVar1 != 0))
  {
    DAT_710405c878 = &DAT_710405c878;
    DAT_710405c880 = &DAT_710405c878;
    _DAT_710405c888 = 0xffffffff00000000;
    thunk_EXT_FUN_02e95df0(DAT_7103a5fe28);
  }
  DAT_710406a6f0 = DAT_710405c878;
  DAT_710405c88c = 0x10;
  DAT_710405c878 = &DAT_710406a6f0;
  DAT_710406a6f8 = &DAT_710405c878;
  if (DAT_710406a6f0 != (undefined8 *)0x0) {
    DAT_710406a6f0[1] = &DAT_710406a6f0;
  }
  _DAT_710405c888 = CONCAT44(DAT_710405c88c,DAT_710405c888 + 1);
  return;
}



void FUN_71011f8c58(long *param_1)

{
  long lVar1;
  long lVar2;
  undefined8 *puVar3;
  
  lVar1 = DAT_7105a06420;
  if (DAT_7105a06420 == 0) {
    puVar3 = (undefined8 *)FUN_71005fbcb0(8,0x38);
  }
  else {
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar3 = (undefined8 *)(lVar1 + 8);
      if (lVar2 != 0) {
        puVar3 = (undefined8 *)(lVar2 + 0x88);
      }
      param_1 = (long *)*puVar3;
    }
    puVar3 = (undefined8 *)(**(code **)(*param_1 + 0x30))(param_1,0x38,8);
  }
  puVar3[6] = 0;
  puVar3[2] = 0;
  puVar3[3] = 0;
  *(undefined1 *)((long)puVar3 + 0x1e) = 0xff;
  *puVar3 = &DAT_71038fee38;
  puVar3[1] = 0;
  puVar3[4] = 0;
  puVar3[5] = 0;
  return;
}



void FUN_71011f8cf4(long param_1)

{
  long *plVar1;
  bool bVar2;
  int iVar3;
  undefined8 *puVar4;
  long lVar5;
  uint uVar6;
  ulong uVar7;
  
  if (*(uint *)(*DAT_7103a65d78 + 0x178) < 3) {
    puVar4 = (undefined8 *)0x0;
  }
  else {
    puVar4 = *(undefined8 **)(*(long *)(*DAT_7103a65d78 + 0x180) + 0x10);
  }
  if (((*DAT_7103a65d30 & 1) == 0) && (iVar3 = thunk_EXT_FUN_02e95df0(DAT_7103a65d30), iVar3 != 0))
  {
    *DAT_7103a65d28 = DAT_7103a65d38 + 0x10;
    thunk_EXT_FUN_02e95df0(DAT_7103a65d30);
  }
  lVar5 = (**(code **)*puVar4)(puVar4,DAT_7103a65d28);
  plVar1 = DAT_7103a5c670;
  uVar6 = *(uint *)(*(ulong *)(param_1 + 0x28) & 0xfffffffffffffffc);
  if ((*(uint *)(lVar5 + 8) & uVar6) == 0) {
    bVar2 = (*(uint *)(lVar5 + 0x114) & uVar6) != 0;
    uVar7 = *(ulong *)(param_1 + 0x30);
    uVar6 = (uint)uVar7;
  }
  else {
    bVar2 = true;
    uVar7 = *(ulong *)(param_1 + 0x30);
    uVar6 = (uint)uVar7;
  }
  if (((((uVar6 >> 1 & 1) != 0) && ((char *)(uVar7 & 0xfffffffffffffffc) != (char *)0x0)) &&
      ((bool)*(char *)(uVar7 & 0xfffffffffffffffc) != bVar2)) &&
     (iVar3 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(*DAT_7103a5c670 + 0x54)), iVar3 < 0)) {
    thunk_EXT_FUN_02e95df0(*(undefined4 *)(*plVar1 + 0x54),0x80000001);
  }
  *(bool *)(*(ulong *)(param_1 + 0x30) & 0xfffffffffffffffc) = bVar2;
  return;
}



void FUN_71011f9068(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if ((DAT_710406a738 & 1) == 0) {
    iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a738);
    if (iVar1 != 0) {
      DAT_710406a730 = DAT_7103a60348 + 0x10;
      thunk_EXT_FUN_02e95df0(&DAT_710406a738);
    }
  }
  if (param_2 != &DAT_710406a730) {
    FUN_710101133c(param_1,param_2);
    return;
  }
  return;
}



undefined8 * FUN_71011f90f4(void)

{
  int iVar1;
  
  if (((DAT_710406a738 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a738), iVar1 != 0))
  {
    DAT_710406a730 = DAT_7103a60348 + 0x10;
    thunk_EXT_FUN_02e95df0(&DAT_710406a738);
  }
  return &DAT_710406a730;
}



void FUN_71011f9150(long *param_1)

{
  long *plVar1;
  
  *param_1 = DAT_7103a72c80 + 0x10;
  if ((long *)param_1[2] != (long *)0x0) {
    (**(code **)(*(long *)param_1[2] + 8))();
  }
  if (DAT_7105a06420 != 0) {
    plVar1 = FUN_71024ef490(DAT_7105a06420,param_1);
    if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071011f91b4. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
      return;
    }
    return;
  }
  FUN_71005fbbd0((long)param_1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_71011f91f0(void)

{
  int iVar1;
  
  DAT_710406a728 = (undefined8 *)0x0;
  DAT_710406a710 = 0xf91c85e6;
  DAT_710406a718 = FUN_71011f8c58;
  DAT_710406a720 = (undefined8 *)0x0;
  if (((DAT_710405c890 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710405c890), iVar1 != 0))
  {
    DAT_710405c878 = &DAT_710405c878;
    DAT_710405c880 = &DAT_710405c878;
    _DAT_710405c888 = 0xffffffff00000000;
    thunk_EXT_FUN_02e95df0(DAT_7103a5fe28);
  }
  DAT_710406a720 = DAT_710405c878;
  DAT_710405c88c = 0x10;
  DAT_710405c878 = &DAT_710406a720;
  DAT_710406a728 = &DAT_710405c878;
  if (DAT_710406a720 != (undefined8 *)0x0) {
    DAT_710406a720[1] = &DAT_710406a720;
  }
  _DAT_710405c888 = CONCAT44(DAT_710405c88c,DAT_710405c888 + 1);
  return;
}



undefined8 * FUN_71011f92a8(long *param_1)

{
  long lVar1;
  long lVar2;
  undefined8 *puVar3;
  
  lVar1 = DAT_7105a06420;
  if (DAT_7105a06420 == 0) {
    puVar3 = (undefined8 *)FUN_71005fbcb0(8,0x20e8);
  }
  else {
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar3 = (undefined8 *)(lVar1 + 8);
      if (lVar2 != 0) {
        puVar3 = (undefined8 *)(lVar2 + 0x88);
      }
      param_1 = (long *)*puVar3;
    }
    puVar3 = (undefined8 *)(**(code **)(*param_1 + 0x30))(param_1,0x20e8,8);
  }
  thunk_EXT_FUN_02e95df0(puVar3 + 1,0,0x20c8);
  *(undefined1 *)((long)puVar3 + 0x1e) = 0xff;
  puVar3[8] = puVar3 + 10;
  *(undefined4 *)(puVar3 + 9) = 10;
  puVar3[0x41a] = 0;
  puVar3[7] = &DAT_7103896d78;
  *puVar3 = &DAT_71038fef70;
  puVar3[0x41b] = 0;
  puVar3[0x41c] = 0;
  puVar3[5] = &DAT_7103895f78;
  puVar3[6] = puVar3 + 7;
  return puVar3;
}



void FUN_71011f9874(long *param_1)

{
  uint uVar1;
  long lVar2;
  undefined8 *puVar3;
  undefined8 uVar4;
  undefined *puVar5;
  long lVar6;
  char *local_40;
  uint local_38;
  ushort local_34 [2];
  ushort local_18 [2];
  uint local_14;
  
  local_40 = "ActorHandleList";
  FUN_710101275c(param_1,(long *)&local_40,param_1 + 0x41a,1,(long *)0x0);
  local_14 = 0;
  local_40 = "LookAtPosition";
  local_38 = 0;
  local_18[0] = 0xffff;
  local_34[0] = 0xffff;
  lVar6 = *(long *)(param_1[1] + 0x10);
  lVar2 = (**(code **)(*param_1 + 0xa0))(param_1);
  puVar3 = FUN_71011f0f70(lVar6,(long *)&local_40,lVar2 + 0x30,local_18,local_34,&local_14,
                          (long)param_1,(undefined1 *)0x0,&local_38);
  uVar4 = 0;
  FUN_71011f1930((long)param_1,(long *)&local_40,(ulong *)(param_1 + 0x41b),0,(ulong)local_14,
                 (ulong)local_18[0],(ulong)local_34[0],0,(ulong)puVar3,local_38);
  local_14 = local_14 & 0xffffff00;
  local_40 = "PairOfSlaveAndGeneralGoalStateList";
  lVar6 = *(long *)(param_1[1] + 0x10);
  lVar2 = (**(code **)(*param_1 + 0xa0))(param_1);
  uVar1 = FUN_7102963780(lVar6,(long *)&local_40,lVar2 + 0x30,param_1,(undefined1 *)&local_14,
                         (undefined1 *)0x0,(long *)0x0,uVar4);
  if ((int)uVar1 < 0) {
    puVar5 = &DAT_7105a09400;
  }
  else {
    param_1[0x41c] = 0;
    lVar2 = 0;
    if ((long *)param_1[2] != (long *)0x0) {
      lVar2 = (**(code **)(*(long *)param_1[2] + 0x10))();
    }
    puVar5 = (undefined *)(lVar2 + (ulong)uVar1 & 0xfffffffffffffffc);
  }
  param_1[0x41c] = (long)puVar5;
  if ((char)local_14 != '\0') {
    puVar5 = (undefined *)((ulong)puVar5 | 1);
    param_1[0x41c] = (long)puVar5;
  }
  if ((*(byte *)(*(long *)(param_1[1] + 8) + 0x1ac) & 1) != 0) {
    param_1[0x41c] = (ulong)puVar5 | 2;
  }
  return;
}



void FUN_71011f9a04(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if ((DAT_710406a780 & 1) == 0) {
    iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a780);
    if (iVar1 != 0) {
      DAT_710406a778 = DAT_7103a60348 + 0x10;
      thunk_EXT_FUN_02e95df0(&DAT_710406a780);
    }
  }
  if (param_2 != &DAT_710406a778) {
    FUN_710101133c(param_1,param_2);
    return;
  }
  return;
}



undefined8 * FUN_71011f9a90(void)

{
  int iVar1;
  
  if (((DAT_710406a780 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a780), iVar1 != 0))
  {
    DAT_710406a778 = DAT_7103a60348 + 0x10;
    thunk_EXT_FUN_02e95df0(&DAT_710406a780);
  }
  return &DAT_710406a778;
}



void FUN_71011f9aec(undefined8 *param_1)

{
  long lVar1;
  
  *param_1 = &DAT_71038fef70;
  param_1[5] = DAT_7103a5ee78 + 0x10;
  FUN_7100f4bc70(param_1[6]);
  lVar1 = DAT_7103a5ee88;
  param_1[6] = 0;
  param_1[7] = lVar1 + 0x10;
  FUN_7100f4bc70((long)(param_1 + 7));
  *param_1 = &DAT_7103a27638;
  if ((long *)param_1[2] != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071011f9b64. Too many branches
                    // WARNING: Treating indirect jump as call
    (**(code **)(*(long *)param_1[2] + 8))();
    return;
  }
  return;
}



void FUN_71011f9b74(undefined8 *param_1)

{
  long lVar1;
  long *plVar2;
  
  *param_1 = &DAT_71038fef70;
  param_1[5] = DAT_7103a5ee78 + 0x10;
  FUN_7100f4bc70(param_1[6]);
  lVar1 = DAT_7103a5ee88;
  param_1[6] = 0;
  param_1[7] = lVar1 + 0x10;
  FUN_7100f4bc70((long)(param_1 + 7));
  *param_1 = &DAT_7103a27638;
  if ((long *)param_1[2] != (long *)0x0) {
    (**(code **)(*(long *)param_1[2] + 8))();
  }
  if (DAT_7105a06420 != 0) {
    plVar2 = FUN_71024ef490(DAT_7105a06420,param_1);
    if (plVar2 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071011f9c18. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*plVar2 + 0x38))(plVar2,param_1);
      return;
    }
    return;
  }
  FUN_71005fbbd0((long)param_1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_71011f9c50(void)

{
  int iVar1;
  long *plVar2;
  
  DAT_710406a740 = 0x6a24df;
  DAT_710406a744 = 0x7fc000007fc00000;
  DAT_710406a750 = 0;
  DAT_710406a74c = 0x7fc00000;
  DAT_710406a758 = 0xcb422874;
  DAT_710406a770 = (long *)0x0;
  DAT_710406a760 = FUN_71011f92a8;
  DAT_710406a768 = 0;
  plVar2 = DAT_7103a5fe20;
  if ((DAT_710405c890 & 1) == 0) {
    iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710405c890);
    plVar2 = (long *)&DAT_710405c878;
    if (iVar1 != 0) {
      DAT_710405c878 = &DAT_710405c878;
      DAT_710405c880 = &DAT_710405c878;
      _DAT_710405c888 = 0xffffffff00000000;
      thunk_EXT_FUN_02e95df0(DAT_7103a5fe28);
      plVar2 = (long *)&DAT_710405c878;
    }
  }
  *(undefined4 *)((long)plVar2 + 0x14) = 0x10;
  DAT_710406a768 = *plVar2;
  *plVar2 = (long)&DAT_710406a768;
  DAT_710406a770 = plVar2;
  if (DAT_710406a768 != 0) {
    *(long **)(DAT_710406a768 + 8) = &DAT_710406a768;
  }
  *(int *)(plVar2 + 2) = (int)plVar2[2] + 1;
  return;
}



void FUN_71011f9d34(long *param_1)

{
  long lVar1;
  long lVar2;
  undefined8 *puVar3;
  
  lVar1 = DAT_7105a06420;
  if (DAT_7105a06420 == 0) {
    puVar3 = (undefined8 *)FUN_71005fbcb0(8,0x38);
  }
  else {
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar3 = (undefined8 *)(lVar1 + 8);
      if (lVar2 != 0) {
        puVar3 = (undefined8 *)(lVar2 + 0x88);
      }
      param_1 = (long *)*puVar3;
    }
    puVar3 = (undefined8 *)(**(code **)(*param_1 + 0x30))(param_1,0x38,8);
  }
  puVar3[6] = 0;
  puVar3[2] = 0;
  puVar3[3] = 0;
  *(undefined1 *)((long)puVar3 + 0x1e) = 0xff;
  *puVar3 = &DAT_71038ff0f0;
  puVar3[1] = 0;
  puVar3[4] = 0;
  puVar3[5] = 0;
  return;
}



void FUN_71011fa1d4(long *param_1)

{
  uint uVar1;
  long lVar2;
  undefined8 in_x6;
  undefined8 in_x7;
  long lVar3;
  char *local_38;
  byte local_14 [4];
  
  local_38 = "ActorHandleList";
  FUN_710101275c(param_1,(long *)&local_38,param_1 + 5,1,(long *)0x0);
  local_14[0] = 0;
  local_38 = "Position";
  lVar3 = *(long *)(param_1[1] + 0x10);
  lVar2 = (**(code **)(*param_1 + 0xa0))(param_1);
  uVar1 = FUN_7102963610(lVar3,(long *)&local_38,lVar2 + 0x30,param_1,local_14,(undefined1 *)0x0,
                         in_x6,in_x7);
  FUN_7102962d38((long)param_1,(ulong *)(param_1 + 6),uVar1,(uint)local_14[0]);
  return;
}



void FUN_71011fa27c(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if ((DAT_710406a7b0 & 1) == 0) {
    iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a7b0);
    if (iVar1 != 0) {
      DAT_710406a7a8 = DAT_7103a60348 + 0x10;
      thunk_EXT_FUN_02e95df0(&DAT_710406a7b0);
    }
  }
  if (param_2 != &DAT_710406a7a8) {
    FUN_710101133c(param_1,param_2);
    return;
  }
  return;
}



undefined8 * FUN_71011fa308(void)

{
  int iVar1;
  
  if (((DAT_710406a7b0 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a7b0), iVar1 != 0))
  {
    DAT_710406a7a8 = DAT_7103a60348 + 0x10;
    thunk_EXT_FUN_02e95df0(&DAT_710406a7b0);
  }
  return &DAT_710406a7a8;
}



void FUN_71011fa364(long *param_1)

{
  long *plVar1;
  
  *param_1 = DAT_7103a72c80 + 0x10;
  if ((long *)param_1[2] != (long *)0x0) {
    (**(code **)(*(long *)param_1[2] + 8))();
  }
  if (DAT_7105a06420 != 0) {
    plVar1 = FUN_71024ef490(DAT_7105a06420,param_1);
    if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071011fa3c8. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
      return;
    }
    return;
  }
  FUN_71005fbbd0((long)param_1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_71011fa400(void)

{
  int iVar1;
  
  DAT_710406a7a0 = (undefined8 *)0x0;
  DAT_710406a788 = 0xd67869cb;
  DAT_710406a790 = FUN_71011f9d34;
  DAT_710406a798 = (undefined8 *)0x0;
  if (((DAT_710405c890 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710405c890), iVar1 != 0))
  {
    DAT_710405c878 = &DAT_710405c878;
    DAT_710405c880 = &DAT_710405c878;
    _DAT_710405c888 = 0xffffffff00000000;
    thunk_EXT_FUN_02e95df0(DAT_7103a5fe28);
  }
  DAT_710406a798 = DAT_710405c878;
  DAT_710405c88c = 0x10;
  DAT_710405c878 = &DAT_710406a798;
  DAT_710406a7a0 = &DAT_710405c878;
  if (DAT_710406a798 != (undefined8 *)0x0) {
    DAT_710406a798[1] = &DAT_710406a798;
  }
  _DAT_710405c888 = CONCAT44(DAT_710405c88c,DAT_710405c888 + 1);
  return;
}



void FUN_71011fa4b8(long *param_1)

{
  long lVar1;
  long lVar2;
  undefined8 *puVar3;
  
  lVar1 = DAT_7105a06420;
  if (DAT_7105a06420 == 0) {
    puVar3 = (undefined8 *)FUN_71005fbcb0(8,0x48);
  }
  else {
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar3 = (undefined8 *)(lVar1 + 8);
      if (lVar2 != 0) {
        puVar3 = (undefined8 *)(lVar2 + 0x88);
      }
      param_1 = (long *)*puVar3;
    }
    puVar3 = (undefined8 *)(**(code **)(*param_1 + 0x30))(param_1,0x48,8);
  }
  puVar3[2] = 0;
  puVar3[3] = 0;
  *(undefined1 *)((long)puVar3 + 0x1e) = 0xff;
  puVar3[8] = 0;
  *puVar3 = &DAT_71038ff228;
  puVar3[1] = 0;
  puVar3[4] = 0;
  puVar3[5] = 0;
  puVar3[6] = 0;
  puVar3[7] = 0;
  return;
}



void FUN_71011faf0c(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if ((DAT_710406a7e0 & 1) == 0) {
    iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a7e0);
    if (iVar1 != 0) {
      DAT_710406a7d8 = DAT_7103a60348 + 0x10;
      thunk_EXT_FUN_02e95df0(&DAT_710406a7e0);
    }
  }
  if (param_2 != &DAT_710406a7d8) {
    FUN_710101133c(param_1,param_2);
    return;
  }
  return;
}



undefined8 * FUN_71011faf98(void)

{
  int iVar1;
  
  if (((DAT_710406a7e0 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a7e0), iVar1 != 0))
  {
    DAT_710406a7d8 = DAT_7103a60348 + 0x10;
    thunk_EXT_FUN_02e95df0(&DAT_710406a7e0);
  }
  return &DAT_710406a7d8;
}



void FUN_71011faff4(long *param_1)

{
  long *plVar1;
  
  *param_1 = DAT_7103a72c80 + 0x10;
  if ((long *)param_1[2] != (long *)0x0) {
    (**(code **)(*(long *)param_1[2] + 8))();
  }
  if (DAT_7105a06420 != 0) {
    plVar1 = FUN_71024ef490(DAT_7105a06420,param_1);
    if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071011fb058. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
      return;
    }
    return;
  }
  FUN_71005fbbd0((long)param_1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_71011fb090(void)

{
  int iVar1;
  
  DAT_710406a7d0 = (undefined8 *)0x0;
  DAT_710406a7b8 = 0xefffcb85;
  DAT_710406a7c0 = FUN_71011fa4b8;
  DAT_710406a7c8 = (undefined8 *)0x0;
  if (((DAT_710405c890 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710405c890), iVar1 != 0))
  {
    DAT_710405c878 = &DAT_710405c878;
    DAT_710405c880 = &DAT_710405c878;
    _DAT_710405c888 = 0xffffffff00000000;
    thunk_EXT_FUN_02e95df0(DAT_7103a5fe28);
  }
  DAT_710406a7c8 = DAT_710405c878;
  DAT_710405c88c = 0x10;
  DAT_710405c878 = &DAT_710406a7c8;
  DAT_710406a7d0 = &DAT_710405c878;
  if (DAT_710406a7c8 != (undefined8 *)0x0) {
    DAT_710406a7c8[1] = &DAT_710406a7c8;
  }
  _DAT_710405c888 = CONCAT44(DAT_710405c88c,DAT_710405c888 + 1);
  return;
}



void FUN_71011fb148(long *param_1)

{
  long lVar1;
  long lVar2;
  undefined8 *puVar3;
  
  lVar1 = DAT_7105a06420;
  if (DAT_7105a06420 == 0) {
    puVar3 = (undefined8 *)FUN_71005fbcb0(8,0x38);
  }
  else {
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar3 = (undefined8 *)(lVar1 + 8);
      if (lVar2 != 0) {
        puVar3 = (undefined8 *)(lVar2 + 0x88);
      }
      param_1 = (long *)*puVar3;
    }
    puVar3 = (undefined8 *)(**(code **)(*param_1 + 0x30))(param_1,0x38,8);
  }
  puVar3[6] = 0;
  puVar3[2] = 0;
  puVar3[3] = 0;
  *(undefined1 *)((long)puVar3 + 0x1e) = 0xff;
  *puVar3 = &DAT_71038ff360;
  puVar3[1] = 0;
  puVar3[4] = 0;
  puVar3[5] = 0;
  return;
}



void FUN_71011fb41c(long *param_1)

{
  uint uVar1;
  long lVar2;
  undefined8 in_x6;
  undefined8 in_x7;
  long lVar3;
  char *local_38;
  byte local_14 [4];
  
  local_38 = "ActorHandleList";
  FUN_710101275c(param_1,(long *)&local_38,param_1 + 5,1,(long *)0x0);
  local_14[0] = 0;
  local_38 = "Position";
  lVar3 = *(long *)(param_1[1] + 0x10);
  lVar2 = (**(code **)(*param_1 + 0xa0))(param_1);
  uVar1 = FUN_7102963610(lVar3,(long *)&local_38,lVar2 + 0x30,param_1,local_14,(undefined1 *)0x0,
                         in_x6,in_x7);
  FUN_7102962d38((long)param_1,(ulong *)(param_1 + 6),uVar1,(uint)local_14[0]);
  return;
}



void FUN_71011fb4c4(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if ((DAT_710406a810 & 1) == 0) {
    iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a810);
    if (iVar1 != 0) {
      DAT_710406a808 = DAT_7103a60348 + 0x10;
      thunk_EXT_FUN_02e95df0(&DAT_710406a810);
    }
  }
  if (param_2 != &DAT_710406a808) {
    FUN_710101133c(param_1,param_2);
    return;
  }
  return;
}



undefined8 * FUN_71011fb550(void)

{
  int iVar1;
  
  if (((DAT_710406a810 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a810), iVar1 != 0))
  {
    DAT_710406a808 = DAT_7103a60348 + 0x10;
    thunk_EXT_FUN_02e95df0(&DAT_710406a810);
  }
  return &DAT_710406a808;
}



void FUN_71011fb5ac(long *param_1)

{
  long *plVar1;
  
  *param_1 = DAT_7103a72c80 + 0x10;
  if ((long *)param_1[2] != (long *)0x0) {
    (**(code **)(*(long *)param_1[2] + 8))();
  }
  if (DAT_7105a06420 != 0) {
    plVar1 = FUN_71024ef490(DAT_7105a06420,param_1);
    if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071011fb610. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
      return;
    }
    return;
  }
  FUN_71005fbbd0((long)param_1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_71011fb650(void)

{
  int iVar1;
  
  DAT_710406a800 = (undefined8 *)0x0;
  DAT_710406a7e8 = 0x2e77e4c;
  DAT_710406a7f0 = FUN_71011fb148;
  DAT_710406a7f8 = (undefined8 *)0x0;
  if (((DAT_710405c890 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710405c890), iVar1 != 0))
  {
    DAT_710405c878 = &DAT_710405c878;
    DAT_710405c880 = &DAT_710405c878;
    _DAT_710405c888 = 0xffffffff00000000;
    thunk_EXT_FUN_02e95df0(DAT_7103a5fe28);
  }
  DAT_710406a7f8 = DAT_710405c878;
  DAT_710405c88c = 0x10;
  DAT_710405c878 = &DAT_710406a7f8;
  DAT_710406a800 = &DAT_710405c878;
  if (DAT_710406a7f8 != (undefined8 *)0x0) {
    DAT_710406a7f8[1] = &DAT_710406a7f8;
  }
  _DAT_710405c888 = CONCAT44(DAT_710405c88c,DAT_710405c888 + 1);
  return;
}



void FUN_71011fb708(long *param_1)

{
  long lVar1;
  long lVar2;
  undefined8 *puVar3;
  
  lVar1 = DAT_7105a06420;
  if (DAT_7105a06420 == 0) {
    puVar3 = (undefined8 *)FUN_71005fbcb0(8,0x48);
  }
  else {
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar3 = (undefined8 *)(lVar1 + 8);
      if (lVar2 != 0) {
        puVar3 = (undefined8 *)(lVar2 + 0x88);
      }
      param_1 = (long *)*puVar3;
    }
    puVar3 = (undefined8 *)(**(code **)(*param_1 + 0x30))(param_1,0x48,8);
  }
  puVar3[2] = 0;
  puVar3[3] = 0;
  *(undefined1 *)((long)puVar3 + 0x1e) = 0xff;
  puVar3[8] = 0;
  *puVar3 = &DAT_71038ff498;
  puVar3[1] = 0;
  puVar3[4] = 0;
  puVar3[5] = 0;
  puVar3[6] = 0;
  puVar3[7] = 0;
  return;
}



void FUN_71011fba10(long *param_1)

{
  uint uVar1;
  long lVar2;
  undefined8 *puVar3;
  undefined8 in_x5;
  undefined8 in_x6;
  ulong uVar4;
  undefined8 in_x7;
  undefined8 uVar5;
  long lVar6;
  char *local_40;
  uint local_38;
  ushort local_34 [2];
  ushort local_18 [2];
  uint local_14;
  
  local_40 = "IsOnce";
  FUN_7101012e40(param_1,(long *)&local_40,param_1 + 5,1,0,in_x5,in_x6,in_x7);
  local_40 = "ActorHandle";
  FUN_710101275c(param_1,(long *)&local_40,param_1 + 6,1,(long *)0x0);
  local_14 = 0;
  local_40 = "Position";
  local_18[0] = 0xffff;
  local_34[0] = 0xffff;
  lVar6 = *(long *)(param_1[1] + 0x10);
  local_38 = 0;
  lVar2 = (**(code **)(*param_1 + 0xa0))(param_1);
  puVar3 = FUN_71011f0f70(lVar6,(long *)&local_40,lVar2 + 0x30,local_18,local_34,&local_14,
                          (long)param_1,(undefined1 *)0x0,&local_38);
  uVar4 = (ulong)local_34[0];
  uVar5 = 0;
  FUN_71011f1930((long)param_1,(long *)&local_40,(ulong *)(param_1 + 7),0,(ulong)local_14,
                 (ulong)local_18[0],uVar4,0,(ulong)puVar3,local_38);
  local_14 = local_14 & 0xffffff00;
  local_40 = "Direction";
  lVar6 = *(long *)(param_1[1] + 0x10);
  lVar2 = (**(code **)(*param_1 + 0xa0))(param_1);
  uVar1 = FUN_7102963610(lVar6,(long *)&local_40,lVar2 + 0x30,param_1,(byte *)&local_14,
                         (undefined1 *)0x0,uVar4,uVar5);
  FUN_7102962d38((long)param_1,(ulong *)(param_1 + 8),uVar1,local_14 & 0xff);
  return;
}



void FUN_71011fbb70(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if ((DAT_710406a840 & 1) == 0) {
    iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a840);
    if (iVar1 != 0) {
      DAT_710406a838 = DAT_7103a60348 + 0x10;
      thunk_EXT_FUN_02e95df0(&DAT_710406a840);
    }
  }
  if (param_2 != &DAT_710406a838) {
    FUN_710101133c(param_1,param_2);
    return;
  }
  return;
}



undefined8 * FUN_71011fbbfc(void)

{
  int iVar1;
  
  if (((DAT_710406a840 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a840), iVar1 != 0))
  {
    DAT_710406a838 = DAT_7103a60348 + 0x10;
    thunk_EXT_FUN_02e95df0(&DAT_710406a840);
  }
  return &DAT_710406a838;
}



void FUN_71011fbc58(long *param_1)

{
  long *plVar1;
  
  *param_1 = DAT_7103a72c80 + 0x10;
  if ((long *)param_1[2] != (long *)0x0) {
    (**(code **)(*(long *)param_1[2] + 8))();
  }
  if (DAT_7105a06420 != 0) {
    plVar1 = FUN_71024ef490(DAT_7105a06420,param_1);
    if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071011fbcbc. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
      return;
    }
    return;
  }
  FUN_71005fbbd0((long)param_1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_71011fbd00(void)

{
  int iVar1;
  
  DAT_710406a830 = (undefined8 *)0x0;
  DAT_710406a818 = 0x8a15232e;
  DAT_710406a820 = FUN_71011fb708;
  DAT_710406a828 = (undefined8 *)0x0;
  if (((DAT_710405c890 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710405c890), iVar1 != 0))
  {
    DAT_710405c878 = &DAT_710405c878;
    DAT_710405c880 = &DAT_710405c878;
    _DAT_710405c888 = 0xffffffff00000000;
    thunk_EXT_FUN_02e95df0(DAT_7103a5fe28);
  }
  DAT_710406a828 = DAT_710405c878;
  DAT_710405c88c = 0x10;
  DAT_710405c878 = &DAT_710406a828;
  DAT_710406a830 = &DAT_710405c878;
  if (DAT_710406a828 != (undefined8 *)0x0) {
    DAT_710406a828[1] = &DAT_710406a828;
  }
  _DAT_710405c888 = CONCAT44(DAT_710405c88c,DAT_710405c888 + 1);
  return;
}



void FUN_71011fbdb8(long *param_1)

{
  long lVar1;
  long lVar2;
  undefined8 *puVar3;
  
  lVar1 = DAT_7105a06420;
  if (DAT_7105a06420 == 0) {
    puVar3 = (undefined8 *)FUN_71005fbcb0(8,0x58);
  }
  else {
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar3 = (undefined8 *)(lVar1 + 8);
      if (lVar2 != 0) {
        puVar3 = (undefined8 *)(lVar2 + 0x88);
      }
      param_1 = (long *)*puVar3;
    }
    puVar3 = (undefined8 *)(**(code **)(*param_1 + 0x30))(param_1,0x58,8);
  }
  puVar3[10] = 0;
  puVar3[2] = 0;
  puVar3[3] = 0;
  *(undefined1 *)((long)puVar3 + 0x1e) = 0xff;
  *puVar3 = &DAT_71038ff5d0;
  puVar3[1] = 0;
  puVar3[4] = 0;
  puVar3[5] = 0x3f8000003f800000;
  puVar3[6] = 0;
  puVar3[7] = 0;
  puVar3[8] = 0;
  puVar3[9] = 0;
  return;
}



void FUN_71011fc120(long *param_1)

{
  char *pcVar1;
  long lVar2;
  undefined4 *puVar3;
  uint uVar4;
  uint uVar5;
  undefined8 uVar6;
  ulong uVar7;
  ulong uVar8;
  ulong uVar9;
  undefined8 uVar10;
  ulong uVar11;
  long lVar12;
  long lVar13;
  uint local_160;
  ushort local_15c [2];
  ushort local_158 [2];
  uint local_154;
  char *local_150;
  undefined4 local_148;
  char local_144 [255];
  undefined1 local_45;
  
  local_154 = 0;
  local_150 = "M0";
  local_158[0] = 0xffff;
  local_15c[0] = 0xffff;
  lVar13 = *(long *)(param_1[1] + 0x10);
  local_160 = 0;
  lVar2 = (**(code **)(*param_1 + 0xa0))();
  puVar3 = FUN_710101cf70(lVar13,(long *)&local_150,lVar2 + 0x30,local_158,local_15c,&local_154,
                          (long)param_1,(undefined1 *)0x0,&local_160);
  FUN_710101d1b0((long)param_1,(long *)&local_150,(ulong *)(param_1 + 7),0,(ulong)local_154,
                 (ulong)local_158[0],(ulong)local_15c[0],0,(ulong)puVar3,local_160);
  local_154 = 0;
  local_150 = "M1";
  local_158[0] = 0xffff;
  local_15c[0] = 0xffff;
  lVar13 = *(long *)(param_1[1] + 0x10);
  local_160 = 0;
  lVar2 = (**(code **)(*param_1 + 0xa0))(param_1);
  puVar3 = FUN_710101cf70(lVar13,(long *)&local_150,lVar2 + 0x30,local_158,local_15c,&local_154,
                          (long)param_1,(undefined1 *)0x0,&local_160);
  FUN_710101d1b0((long)param_1,(long *)&local_150,(ulong *)(param_1 + 8),0,(ulong)local_154,
                 (ulong)local_158[0],(ulong)local_15c[0],0,(ulong)puVar3,local_160);
  local_154 = 0;
  local_150 = "SecTillEnd";
  local_158[0] = 0xffff;
  local_15c[0] = 0xffff;
  lVar13 = *(long *)(param_1[1] + 0x10);
  local_160 = 0;
  lVar2 = (**(code **)(*param_1 + 0xa0))(param_1);
  puVar3 = FUN_710101cf70(lVar13,(long *)&local_150,lVar2 + 0x30,local_158,local_15c,&local_154,
                          (long)param_1,(undefined1 *)0x0,&local_160);
  uVar7 = (ulong)local_154;
  uVar9 = (ulong)local_15c[0];
  uVar6 = 0;
  uVar10 = 0;
  uVar8 = (ulong)local_158[0];
  FUN_710101d1b0((long)param_1,(long *)&local_150,(ulong *)(param_1 + 9),0,uVar7,uVar8,uVar9,0,
                 (ulong)puVar3,local_160);
  lVar13 = *(long *)(param_1[1] + 0x10);
  lVar2 = (**(code **)(*param_1 + 0xa0))(param_1);
  if (0 < (int)*(uint *)(lVar2 + 0x5c)) {
    uVar11 = 0;
    lVar12 = *(long *)(lVar13 + 0x10);
    do {
      uVar5 = *(uint *)(lVar12 + *(int *)(*(long *)(lVar13 + 0x28) + 0x14) +
                        (long)*(int *)(lVar2 + 0x58) * 4 + uVar11 * 4);
      pcVar1 = (char *)(lVar12 + *(int *)(lVar12 + 0x24) + ((ulong)uVar5 & 0x7fffffff));
      if ((pcVar1 == "Ratio") ||
         ((((*pcVar1 == 'R' && (pcVar1[1] == 'a')) && (pcVar1[2] == 't')) &&
          (((pcVar1[3] == 'i' && (pcVar1[4] == 'o')) && (pcVar1[5] == '\0')))))) {
        uVar5 = uVar5 >> 0x1f;
        uVar4 = (*(int *)(lVar2 + 0x3c) + *(int *)(lVar2 + 0x4c) + (int)uVar11) * 4;
        goto LAB_71011fc404;
      }
      uVar11 = uVar11 + 1;
    } while (*(uint *)(lVar2 + 0x5c) != uVar11);
  }
  local_150 = local_144;
  local_45 = 0;
  local_148 = 0x100;
  lVar2 = *(long *)(lVar13 + 0x10);
  local_144[0] = '\0';
  FUN_7100bc08f0((long *)&local_150,"%s.ain",
                 lVar2 + *(int *)(lVar2 + 0x24) + (long)*(int *)(lVar2 + 8),uVar6,uVar7,uVar8,uVar9,
                 uVar10);
  uVar5 = 0;
  uVar4 = 0xffffffff;
LAB_71011fc404:
  FUN_71010c54c0((long)param_1,(ulong *)(param_1 + 10),uVar4,uVar5);
  return;
}



void FUN_71011fc428(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if ((DAT_710406a870 & 1) == 0) {
    iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a870);
    if (iVar1 != 0) {
      DAT_710406a868 = DAT_7103a60348 + 0x10;
      thunk_EXT_FUN_02e95df0(&DAT_710406a870);
    }
  }
  if (param_2 != &DAT_710406a868) {
    FUN_710101133c(param_1,param_2);
    return;
  }
  return;
}



undefined8 * FUN_71011fc4b4(void)

{
  int iVar1;
  
  if (((DAT_710406a870 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a870), iVar1 != 0))
  {
    DAT_710406a868 = DAT_7103a60348 + 0x10;
    thunk_EXT_FUN_02e95df0(&DAT_710406a870);
  }
  return &DAT_710406a868;
}



void FUN_71011fc510(long *param_1)

{
  long *plVar1;
  
  *param_1 = DAT_7103a72c80 + 0x10;
  if ((long *)param_1[2] != (long *)0x0) {
    (**(code **)(*(long *)param_1[2] + 8))();
  }
  if (DAT_7105a06420 != 0) {
    plVar1 = FUN_71024ef490(DAT_7105a06420,param_1);
    if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071011fc574. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
      return;
    }
    return;
  }
  FUN_71005fbbd0((long)param_1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_71011fc5b0(void)

{
  int iVar1;
  
  DAT_710406a860 = (undefined8 *)0x0;
  DAT_710406a848 = 0x802b041e;
  DAT_710406a850 = FUN_71011fbdb8;
  DAT_710406a858 = (undefined8 *)0x0;
  if (((DAT_710405c890 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710405c890), iVar1 != 0))
  {
    DAT_710405c878 = &DAT_710405c878;
    DAT_710405c880 = &DAT_710405c878;
    _DAT_710405c888 = 0xffffffff00000000;
    thunk_EXT_FUN_02e95df0(DAT_7103a5fe28);
  }
  DAT_710406a858 = DAT_710405c878;
  DAT_710405c88c = 0x10;
  DAT_710405c878 = &DAT_710406a858;
  DAT_710406a860 = &DAT_710405c878;
  if (DAT_710406a858 != (undefined8 *)0x0) {
    DAT_710406a858[1] = &DAT_710406a858;
  }
  _DAT_710405c888 = CONCAT44(DAT_710405c88c,DAT_710405c888 + 1);
  return;
}



void FUN_71011fc668(long *param_1)

{
  long lVar1;
  long lVar2;
  undefined8 *puVar3;
  
  lVar1 = DAT_7105a06420;
  if (DAT_7105a06420 == 0) {
    puVar3 = (undefined8 *)FUN_71005fbcb0(8,0x58);
  }
  else {
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar3 = (undefined8 *)(lVar1 + 8);
      if (lVar2 != 0) {
        puVar3 = (undefined8 *)(lVar2 + 0x88);
      }
      param_1 = (long *)*puVar3;
    }
    puVar3 = (undefined8 *)(**(code **)(*param_1 + 0x30))(param_1,0x58,8);
  }
  puVar3[4] = 0;
  puVar3[2] = 0;
  puVar3[3] = 0;
  *(undefined1 *)((long)puVar3 + 0x1e) = 0xff;
  *(undefined8 *)((long)puVar3 + 0x2c) = 0;
  *(undefined8 *)((long)puVar3 + 0x34) = 0;
  *(undefined8 *)((long)puVar3 + 0x3c) = 0;
  *(undefined8 *)((long)puVar3 + 0x44) = 0;
  *(undefined8 *)((long)puVar3 + 0x4c) = 0;
  *(undefined4 *)((long)puVar3 + 0x54) = 0;
  *puVar3 = &DAT_71038ff708;
  puVar3[1] = 0;
  *(undefined4 *)(puVar3 + 5) = 0x3f000000;
  return;
}



void FUN_71011fcc4c(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if ((DAT_710406a8a0 & 1) == 0) {
    iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a8a0);
    if (iVar1 != 0) {
      DAT_710406a898 = DAT_7103a60348 + 0x10;
      thunk_EXT_FUN_02e95df0(&DAT_710406a8a0);
    }
  }
  if (param_2 != &DAT_710406a898) {
    FUN_710101133c(param_1,param_2);
    return;
  }
  return;
}



undefined8 * FUN_71011fccd8(void)

{
  int iVar1;
  
  if (((DAT_710406a8a0 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a8a0), iVar1 != 0))
  {
    DAT_710406a898 = DAT_7103a60348 + 0x10;
    thunk_EXT_FUN_02e95df0(&DAT_710406a8a0);
  }
  return &DAT_710406a898;
}



void FUN_71011fcd34(long *param_1)

{
  long *plVar1;
  
  *param_1 = DAT_7103a72c80 + 0x10;
  if ((long *)param_1[2] != (long *)0x0) {
    (**(code **)(*(long *)param_1[2] + 8))();
  }
  if (DAT_7105a06420 != 0) {
    plVar1 = FUN_71024ef490(DAT_7105a06420,param_1);
    if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071011fcd98. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
      return;
    }
    return;
  }
  FUN_71005fbbd0((long)param_1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_71011fcdd0(void)

{
  int iVar1;
  
  DAT_710406a890 = (undefined8 *)0x0;
  DAT_710406a878 = 0xaace278b;
  DAT_710406a880 = FUN_71011fc668;
  DAT_710406a888 = (undefined8 *)0x0;
  if (((DAT_710405c890 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710405c890), iVar1 != 0))
  {
    DAT_710405c878 = &DAT_710405c878;
    DAT_710405c880 = &DAT_710405c878;
    _DAT_710405c888 = 0xffffffff00000000;
    thunk_EXT_FUN_02e95df0(DAT_7103a5fe28);
  }
  DAT_710406a888 = DAT_710405c878;
  DAT_710405c88c = 0x10;
  DAT_710405c878 = &DAT_710406a888;
  DAT_710406a890 = &DAT_710405c878;
  if (DAT_710406a888 != (undefined8 *)0x0) {
    DAT_710406a888[1] = &DAT_710406a888;
  }
  _DAT_710405c888 = CONCAT44(DAT_710405c88c,DAT_710405c888 + 1);
  return;
}



void FUN_71011fce88(long *param_1)

{
  long lVar1;
  long lVar2;
  undefined8 *puVar3;
  
  lVar1 = DAT_7105a06420;
  if (DAT_7105a06420 == 0) {
    puVar3 = (undefined8 *)FUN_71005fbcb0(8,0x48);
  }
  else {
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar3 = (undefined8 *)(lVar1 + 8);
      if (lVar2 != 0) {
        puVar3 = (undefined8 *)(lVar2 + 0x88);
      }
      param_1 = (long *)*puVar3;
    }
    puVar3 = (undefined8 *)(**(code **)(*param_1 + 0x30))(param_1,0x48,8);
  }
  puVar3[4] = 0;
  puVar3[2] = 0;
  puVar3[3] = 0;
  *(undefined1 *)((long)puVar3 + 0x1e) = 0xff;
  *(undefined8 *)((long)puVar3 + 0x2c) = 0;
  *(undefined8 *)((long)puVar3 + 0x34) = 0;
  *(undefined8 *)((long)puVar3 + 0x3c) = 0;
  *(undefined4 *)((long)puVar3 + 0x44) = 0;
  *puVar3 = &DAT_71038ff840;
  puVar3[1] = 0;
  *(undefined4 *)(puVar3 + 5) = 0x3f000000;
  return;
}



void FUN_71011fd1e0(long *param_1)

{
  char *pcVar1;
  long lVar2;
  undefined4 *puVar3;
  uint uVar4;
  uint uVar5;
  undefined8 uVar6;
  ulong uVar7;
  ulong uVar8;
  ulong uVar9;
  undefined8 uVar10;
  ulong uVar11;
  long lVar12;
  long lVar13;
  uint local_160;
  ushort local_15c [2];
  ushort local_158 [2];
  uint local_154;
  char *local_150;
  undefined4 local_148;
  char local_144 [255];
  undefined1 local_45;
  
  local_154 = 0;
  local_150 = "CurveBias";
  local_158[0] = 0xffff;
  local_15c[0] = 0xffff;
  lVar13 = *(long *)(param_1[1] + 0x10);
  local_160 = 0;
  lVar2 = (**(code **)(*param_1 + 0xa0))();
  puVar3 = FUN_710101cf70(lVar13,(long *)&local_150,lVar2 + 0x30,local_158,local_15c,&local_154,
                          (long)param_1,(undefined1 *)0x0,&local_160);
  FUN_710101d1b0((long)param_1,(long *)&local_150,(ulong *)(param_1 + 6),0,(ulong)local_154,
                 (ulong)local_158[0],(ulong)local_15c[0],0,(ulong)puVar3,local_160);
  local_154 = 0;
  local_150 = "SecTillEnd";
  local_158[0] = 0xffff;
  local_15c[0] = 0xffff;
  lVar13 = *(long *)(param_1[1] + 0x10);
  local_160 = 0;
  lVar2 = (**(code **)(*param_1 + 0xa0))(param_1);
  puVar3 = FUN_710101cf70(lVar13,(long *)&local_150,lVar2 + 0x30,local_158,local_15c,&local_154,
                          (long)param_1,(undefined1 *)0x0,&local_160);
  uVar7 = (ulong)local_154;
  uVar9 = (ulong)local_15c[0];
  uVar6 = 0;
  uVar10 = 0;
  uVar8 = (ulong)local_158[0];
  FUN_710101d1b0((long)param_1,(long *)&local_150,(ulong *)(param_1 + 7),0,uVar7,uVar8,uVar9,0,
                 (ulong)puVar3,local_160);
  lVar13 = *(long *)(param_1[1] + 0x10);
  lVar2 = (**(code **)(*param_1 + 0xa0))(param_1);
  if (0 < (int)*(uint *)(lVar2 + 0x5c)) {
    uVar11 = 0;
    lVar12 = *(long *)(lVar13 + 0x10);
    do {
      uVar5 = *(uint *)(lVar12 + *(int *)(*(long *)(lVar13 + 0x28) + 0x14) +
                        (long)*(int *)(lVar2 + 0x58) * 4 + uVar11 * 4);
      pcVar1 = (char *)(lVar12 + *(int *)(lVar12 + 0x24) + ((ulong)uVar5 & 0x7fffffff));
      if ((pcVar1 == "Ratio") ||
         ((((*pcVar1 == 'R' && (pcVar1[1] == 'a')) && (pcVar1[2] == 't')) &&
          (((pcVar1[3] == 'i' && (pcVar1[4] == 'o')) && (pcVar1[5] == '\0')))))) {
        uVar5 = uVar5 >> 0x1f;
        uVar4 = (*(int *)(lVar2 + 0x3c) + *(int *)(lVar2 + 0x4c) + (int)uVar11) * 4;
        goto LAB_71011fd434;
      }
      uVar11 = uVar11 + 1;
    } while (*(uint *)(lVar2 + 0x5c) != uVar11);
  }
  local_150 = local_144;
  local_45 = 0;
  local_148 = 0x100;
  lVar2 = *(long *)(lVar13 + 0x10);
  local_144[0] = '\0';
  FUN_7100bc08f0((long *)&local_150,"%s.ain",
                 lVar2 + *(int *)(lVar2 + 0x24) + (long)*(int *)(lVar2 + 8),uVar6,uVar7,uVar8,uVar9,
                 uVar10);
  uVar5 = 0;
  uVar4 = 0xffffffff;
LAB_71011fd434:
  FUN_71010c54c0((long)param_1,(ulong *)(param_1 + 8),uVar4,uVar5);
  return;
}



void FUN_71011fd458(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if ((DAT_710406a8d0 & 1) == 0) {
    iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a8d0);
    if (iVar1 != 0) {
      DAT_710406a8c8 = DAT_7103a60348 + 0x10;
      thunk_EXT_FUN_02e95df0(&DAT_710406a8d0);
    }
  }
  if (param_2 != &DAT_710406a8c8) {
    FUN_710101133c(param_1,param_2);
    return;
  }
  return;
}



undefined8 * FUN_71011fd4e4(void)

{
  int iVar1;
  
  if (((DAT_710406a8d0 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a8d0), iVar1 != 0))
  {
    DAT_710406a8c8 = DAT_7103a60348 + 0x10;
    thunk_EXT_FUN_02e95df0(&DAT_710406a8d0);
  }
  return &DAT_710406a8c8;
}



void FUN_71011fd540(long *param_1)

{
  long *plVar1;
  
  *param_1 = DAT_7103a72c80 + 0x10;
  if ((long *)param_1[2] != (long *)0x0) {
    (**(code **)(*(long *)param_1[2] + 8))();
  }
  if (DAT_7105a06420 != 0) {
    plVar1 = FUN_71024ef490(DAT_7105a06420,param_1);
    if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071011fd5a4. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
      return;
    }
    return;
  }
  FUN_71005fbbd0((long)param_1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_71011fd5e0(void)

{
  int iVar1;
  
  DAT_710406a8c0 = (undefined8 *)0x0;
  DAT_710406a8a8 = 0x6053eebc;
  DAT_710406a8b0 = FUN_71011fce88;
  DAT_710406a8b8 = (undefined8 *)0x0;
  if (((DAT_710405c890 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710405c890), iVar1 != 0))
  {
    DAT_710405c878 = &DAT_710405c878;
    DAT_710405c880 = &DAT_710405c878;
    _DAT_710405c888 = 0xffffffff00000000;
    thunk_EXT_FUN_02e95df0(DAT_7103a5fe28);
  }
  DAT_710406a8b8 = DAT_710405c878;
  DAT_710405c88c = 0x10;
  DAT_710405c878 = &DAT_710406a8b8;
  DAT_710406a8c0 = &DAT_710405c878;
  if (DAT_710406a8b8 != (undefined8 *)0x0) {
    DAT_710406a8b8[1] = &DAT_710406a8b8;
  }
  _DAT_710405c888 = CONCAT44(DAT_710405c88c,DAT_710405c888 + 1);
  return;
}



void FUN_71011fd698(long *param_1)

{
  long lVar1;
  long lVar2;
  undefined8 *puVar3;
  
  lVar1 = DAT_7105a06420;
  if (DAT_7105a06420 == 0) {
    puVar3 = (undefined8 *)FUN_71005fbcb0(8,0x58);
  }
  else {
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar3 = (undefined8 *)(lVar1 + 8);
      if (lVar2 != 0) {
        puVar3 = (undefined8 *)(lVar2 + 0x88);
      }
      param_1 = (long *)*puVar3;
    }
    puVar3 = (undefined8 *)(**(code **)(*param_1 + 0x30))(param_1,0x58,8);
  }
  puVar3[4] = 0;
  puVar3[2] = 0;
  puVar3[3] = 0;
  *(undefined1 *)((long)puVar3 + 0x1e) = 0xff;
  *(undefined8 *)((long)puVar3 + 0x2c) = 0;
  *(undefined8 *)((long)puVar3 + 0x34) = 0;
  *(undefined8 *)((long)puVar3 + 0x3c) = 0;
  *(undefined8 *)((long)puVar3 + 0x44) = 0;
  *(undefined8 *)((long)puVar3 + 0x4c) = 0;
  *(undefined4 *)((long)puVar3 + 0x54) = 0;
  *puVar3 = &DAT_71038ff978;
  puVar3[1] = 0;
  *(undefined4 *)(puVar3 + 5) = 0x3f000000;
  return;
}



void FUN_71011fda54(long *param_1)

{
  uint uVar1;
  long lVar2;
  undefined4 *puVar3;
  undefined8 *puVar4;
  ulong uVar5;
  undefined8 uVar6;
  long lVar7;
  char *local_50;
  uint local_48;
  ushort local_44 [2];
  ushort local_28 [2];
  uint local_24;
  
  local_24 = 0;
  local_50 = "CurveBias";
  local_28[0] = 0xffff;
  local_44[0] = 0xffff;
  lVar7 = *(long *)(param_1[1] + 0x10);
  local_48 = 0;
  lVar2 = (**(code **)(*param_1 + 0xa0))();
  puVar3 = FUN_710101cf70(lVar7,(long *)&local_50,lVar2 + 0x30,local_28,local_44,&local_24,
                          (long)param_1,(undefined1 *)0x0,&local_48);
  FUN_710101d1b0((long)param_1,(long *)&local_50,(ulong *)(param_1 + 6),0,(ulong)local_24,
                 (ulong)local_28[0],(ulong)local_44[0],0,(ulong)puVar3,local_48);
  local_24 = 0;
  local_50 = "ValBegin";
  local_28[0] = 0xffff;
  local_44[0] = 0xffff;
  lVar7 = *(long *)(param_1[1] + 0x10);
  local_48 = 0;
  lVar2 = (**(code **)(*param_1 + 0xa0))(param_1);
  puVar4 = FUN_71011f0f70(lVar7,(long *)&local_50,lVar2 + 0x30,local_28,local_44,&local_24,
                          (long)param_1,(undefined1 *)0x0,&local_48);
  FUN_71011f1930((long)param_1,(long *)&local_50,(ulong *)(param_1 + 7),0,(ulong)local_24,
                 (ulong)local_28[0],(ulong)local_44[0],0,(ulong)puVar4,local_48);
  local_24 = 0;
  local_50 = "ValEnd";
  local_28[0] = 0xffff;
  local_44[0] = 0xffff;
  lVar7 = *(long *)(param_1[1] + 0x10);
  local_48 = 0;
  lVar2 = (**(code **)(*param_1 + 0xa0))(param_1);
  puVar4 = FUN_71011f0f70(lVar7,(long *)&local_50,lVar2 + 0x30,local_28,local_44,&local_24,
                          (long)param_1,(undefined1 *)0x0,&local_48);
  FUN_71011f1930((long)param_1,(long *)&local_50,(ulong *)(param_1 + 8),0,(ulong)local_24,
                 (ulong)local_28[0],(ulong)local_44[0],0,(ulong)puVar4,local_48);
  local_24 = 0;
  local_50 = "SecTillEnd";
  local_28[0] = 0xffff;
  local_44[0] = 0xffff;
  lVar7 = *(long *)(param_1[1] + 0x10);
  local_48 = 0;
  lVar2 = (**(code **)(*param_1 + 0xa0))(param_1);
  puVar3 = FUN_710101cf70(lVar7,(long *)&local_50,lVar2 + 0x30,local_28,local_44,&local_24,
                          (long)param_1,(undefined1 *)0x0,&local_48);
  uVar5 = (ulong)local_44[0];
  uVar6 = 0;
  FUN_710101d1b0((long)param_1,(long *)&local_50,(ulong *)(param_1 + 9),0,(ulong)local_24,
                 (ulong)local_28[0],uVar5,0,(ulong)puVar3,local_48);
  local_24 = local_24 & 0xffffff00;
  local_50 = "Vector3";
  lVar7 = *(long *)(param_1[1] + 0x10);
  lVar2 = (**(code **)(*param_1 + 0xa0))(param_1);
  uVar1 = FUN_7102963610(lVar7,(long *)&local_50,lVar2 + 0x30,param_1,(byte *)&local_24,
                         (undefined1 *)0x0,uVar5,uVar6);
  FUN_7102962d38((long)param_1,(ulong *)(param_1 + 10),uVar1,local_24 & 0xff);
  return;
}



void FUN_71011fdd14(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if ((DAT_710406a900 & 1) == 0) {
    iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a900);
    if (iVar1 != 0) {
      DAT_710406a8f8 = DAT_7103a60348 + 0x10;
      thunk_EXT_FUN_02e95df0(&DAT_710406a900);
    }
  }
  if (param_2 != &DAT_710406a8f8) {
    FUN_710101133c(param_1,param_2);
    return;
  }
  return;
}



undefined8 * FUN_71011fdda0(void)

{
  int iVar1;
  
  if (((DAT_710406a900 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a900), iVar1 != 0))
  {
    DAT_710406a8f8 = DAT_7103a60348 + 0x10;
    thunk_EXT_FUN_02e95df0(&DAT_710406a900);
  }
  return &DAT_710406a8f8;
}



void FUN_71011fddfc(long *param_1)

{
  long *plVar1;
  
  *param_1 = DAT_7103a72c80 + 0x10;
  if ((long *)param_1[2] != (long *)0x0) {
    (**(code **)(*(long *)param_1[2] + 8))();
  }
  if (DAT_7105a06420 != 0) {
    plVar1 = FUN_71024ef490(DAT_7105a06420,param_1);
    if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071011fde60. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
      return;
    }
    return;
  }
  FUN_71005fbbd0((long)param_1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_71011fdea0(void)

{
  int iVar1;
  
  DAT_710406a8f0 = (undefined8 *)0x0;
  DAT_710406a8d8 = 0xbdb150c5;
  DAT_710406a8e0 = FUN_71011fd698;
  DAT_710406a8e8 = (undefined8 *)0x0;
  if (((DAT_710405c890 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710405c890), iVar1 != 0))
  {
    DAT_710405c878 = &DAT_710405c878;
    DAT_710405c880 = &DAT_710405c878;
    _DAT_710405c888 = 0xffffffff00000000;
    thunk_EXT_FUN_02e95df0(DAT_7103a5fe28);
  }
  DAT_710406a8e8 = DAT_710405c878;
  DAT_710405c88c = 0x10;
  DAT_710405c878 = &DAT_710406a8e8;
  DAT_710406a8f0 = &DAT_710405c878;
  if (DAT_710406a8e8 != (undefined8 *)0x0) {
    DAT_710406a8e8[1] = &DAT_710406a8e8;
  }
  _DAT_710405c888 = CONCAT44(DAT_710405c88c,DAT_710405c888 + 1);
  return;
}



void FUN_71011fdf58(long *param_1)

{
  long lVar1;
  long lVar2;
  undefined8 *puVar3;
  
  lVar1 = DAT_7105a06420;
  if (DAT_7105a06420 == 0) {
    puVar3 = (undefined8 *)FUN_71005fbcb0(8,0x38);
  }
  else {
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar3 = (undefined8 *)(lVar1 + 8);
      if (lVar2 != 0) {
        puVar3 = (undefined8 *)(lVar2 + 0x88);
      }
      param_1 = (long *)*puVar3;
    }
    puVar3 = (undefined8 *)(**(code **)(*param_1 + 0x30))(param_1,0x38,8);
  }
  puVar3[6] = 0;
  puVar3[2] = 0;
  puVar3[3] = 0;
  *(undefined1 *)((long)puVar3 + 0x1e) = 0xff;
  *puVar3 = &DAT_71038ffab0;
  puVar3[1] = 0;
  puVar3[4] = 0;
  puVar3[5] = 0;
  return;
}



ulong FUN_71011fdff0(undefined1 param_1 [16],undefined1 param_2 [16],undefined8 param_3,
                    long *param_4)

{
  float *pfVar1;
  undefined1 auVar2 [16];
  uint uVar3;
  long lVar4;
  ulong extraout_x0;
  ulong uVar5;
  undefined4 uVar6;
  ulong uVar7;
  long lVar8;
  undefined4 extraout_s0;
  undefined4 extraout_var;
  undefined8 extraout_var_00;
  undefined4 uVar9;
  undefined4 uVar10;
  undefined8 local_80;
  undefined8 local_78;
  undefined8 local_70;
  float local_68;
  undefined1 local_64 [63];
  undefined1 local_25;
  
  uVar10 = param_2._4_4_;
  uVar9 = param_2._0_4_;
  lVar4 = FUN_7101483ed0();
  if (lVar4 == 0) {
    lVar8 = *(long *)(*(long *)(param_4[1] + 8) + 0x1d8);
    (**(code **)(*param_4 + 0x90))(param_4);
    lVar4 = *(long *)(*(long *)(param_4[1] + 0x10) + 0x48) +
            (ulong)*(ushort *)((long)param_4 + 0x1c) * 0x3c;
    local_70 = local_64;
    local_80 = *(undefined8 *)(lVar4 + 0x2c);
    local_78 = *(undefined8 *)(lVar4 + 0x34);
    local_25 = 0;
    local_64[0] = 0;
    local_68 = 8.96831e-44;
    uVar3 = FUN_7100f700b0(&local_70,0x7103176cba,(uint *)&local_80);
    uVar5 = (ulong)uVar3;
    for (lVar4 = *(long *)(lVar8 + 0x30); lVar4 != lVar8 + 0x28; lVar4 = *(long *)(lVar4 + 8)) {
      *(uint *)(*(long *)(lVar4 + 0x10) + 0x20) = *(uint *)(*(long *)(lVar4 + 0x10) + 0x20) | 4;
    }
    if ((*(uint *)(lVar8 + 0x20) >> 2 & 1) == 0) {
      *(uint *)(lVar8 + 0x20) = *(uint *)(lVar8 + 0x20) | 4;
    }
  }
  else {
    local_68 = 0.0;
    local_70 = (undefined1 *)0x0;
    uVar6 = 0;
    uVar3 = *(int *)(param_4[5] & 0xfffffffffffffffc) - 3;
    if (uVar3 < 0xd) {
      uVar6 = (undefined4)*(undefined8 *)(&DAT_71032ad6f0 + (long)(int)uVar3 * 8);
    }
    auVar2._4_4_ = extraout_var;
    auVar2._0_4_ = extraout_s0;
    auVar2._8_8_ = extraout_var_00;
    FUN_710146dac0(auVar2,CONCAT44(uVar10,uVar9),param_3,*(long *)(lVar4 + 0x68),(float *)&local_70,
                   uVar6);
    uVar5 = extraout_x0;
    if ((((((uint)param_4[6] >> 1 & 1) != 0) &&
         (pfVar1 = (float *)(param_4[6] & 0xfffffffffffffffc), pfVar1 != (float *)0x0)) &&
        ((*pfVar1 != (float)local_70 || ((pfVar1[1] != local_70._4_4_ || (pfVar1[2] != local_68)))))
        ) && (uVar5 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a094a8 + 0x54)), (int)uVar5 < 0
             )) {
      uVar5 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a094a8 + 0x54),0x80000001);
    }
    uVar7 = param_4[6];
    *(float *)((long *)(uVar7 & 0xfffffffffffffffc) + 1) = local_68;
    *(long *)(uVar7 & 0xfffffffffffffffc) = (long)local_70;
  }
  return uVar5;
}



void FUN_71011fe194(long *param_1)

{
  uint uVar1;
  long lVar2;
  undefined4 *puVar3;
  ulong uVar4;
  undefined8 uVar5;
  long lVar6;
  char *local_40;
  uint local_38;
  ushort local_34 [2];
  ushort local_18 [2];
  uint local_14;
  
  local_14 = 0;
  local_40 = "MiiTouchCameraState";
  local_18[0] = 0xffff;
  local_34[0] = 0xffff;
  lVar6 = *(long *)(param_1[1] + 0x10);
  local_38 = 0;
  lVar2 = (**(code **)(*param_1 + 0xa0))();
  puVar3 = FUN_7101011c30(lVar6,(long *)&local_40,(int *)(lVar2 + 0x30),local_18,local_34,&local_14,
                          (long)param_1,(undefined1 *)0x0,&local_38);
  uVar4 = (ulong)local_34[0];
  uVar5 = 0;
  FUN_7101011e70((long)param_1,(long *)&local_40,(ulong *)(param_1 + 5),0,(ulong)local_14,
                 (ulong)local_18[0],uVar4,0,(ulong)puVar3,local_38);
  local_14 = local_14 & 0xffffff00;
  local_40 = "Position";
  lVar6 = *(long *)(param_1[1] + 0x10);
  lVar2 = (**(code **)(*param_1 + 0xa0))(param_1);
  uVar1 = FUN_7102963610(lVar6,(long *)&local_40,lVar2 + 0x30,param_1,(byte *)&local_14,
                         (undefined1 *)0x0,uVar4,uVar5);
  FUN_7102962d38((long)param_1,(ulong *)(param_1 + 6),uVar1,local_14 & 0xff);
  return;
}



void FUN_71011fe2a8(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if ((DAT_710406a930 & 1) == 0) {
    iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a930);
    if (iVar1 != 0) {
      DAT_710406a928 = DAT_7103a60348 + 0x10;
      thunk_EXT_FUN_02e95df0(&DAT_710406a930);
    }
  }
  if (param_2 != &DAT_710406a928) {
    FUN_710101133c(param_1,param_2);
    return;
  }
  return;
}



undefined8 * FUN_71011fe334(void)

{
  int iVar1;
  
  if (((DAT_710406a930 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a930), iVar1 != 0))
  {
    DAT_710406a928 = DAT_7103a60348 + 0x10;
    thunk_EXT_FUN_02e95df0(&DAT_710406a930);
  }
  return &DAT_710406a928;
}



void FUN_71011fe390(long *param_1)

{
  long *plVar1;
  
  *param_1 = DAT_7103a72c80 + 0x10;
  if ((long *)param_1[2] != (long *)0x0) {
    (**(code **)(*(long *)param_1[2] + 8))();
  }
  if (DAT_7105a06420 != 0) {
    plVar1 = FUN_71024ef490(DAT_7105a06420,param_1);
    if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071011fe3f4. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
      return;
    }
    return;
  }
  FUN_71005fbbd0((long)param_1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_71011fe430(void)

{
  int iVar1;
  
  DAT_710406a920 = (undefined8 *)0x0;
  DAT_710406a908 = 0xa685f631;
  DAT_710406a910 = FUN_71011fdf58;
  DAT_710406a918 = (undefined8 *)0x0;
  if (((DAT_710405c890 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710405c890), iVar1 != 0))
  {
    DAT_710405c878 = &DAT_710405c878;
    DAT_710405c880 = &DAT_710405c878;
    _DAT_710405c888 = 0xffffffff00000000;
    thunk_EXT_FUN_02e95df0(DAT_7103a5fe28);
  }
  DAT_710406a918 = DAT_710405c878;
  DAT_710405c88c = 0x10;
  DAT_710405c878 = &DAT_710406a918;
  DAT_710406a920 = &DAT_710405c878;
  if (DAT_710406a918 != (undefined8 *)0x0) {
    DAT_710406a918[1] = &DAT_710406a918;
  }
  _DAT_710405c888 = CONCAT44(DAT_710405c88c,DAT_710405c888 + 1);
  return;
}



void FUN_71011fe4e8(long *param_1)

{
  long lVar1;
  long lVar2;
  undefined8 *puVar3;
  
  lVar1 = DAT_7105a06420;
  if (DAT_7105a06420 == 0) {
    puVar3 = (undefined8 *)FUN_71005fbcb0(8,0x78);
  }
  else {
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar3 = (undefined8 *)(lVar1 + 8);
      if (lVar2 != 0) {
        puVar3 = (undefined8 *)(lVar2 + 0x88);
      }
      param_1 = (long *)*puVar3;
    }
    puVar3 = (undefined8 *)(**(code **)(*param_1 + 0x30))(param_1,0x78,8);
  }
  puVar3[0xe] = 0;
  puVar3[2] = 0;
  puVar3[3] = 0;
  *(undefined1 *)((long)puVar3 + 0x1e) = 0xff;
  puVar3[8] = 0;
  puVar3[9] = 0;
  *(undefined8 *)((long)puVar3 + 0x45) = 0;
  *puVar3 = &DAT_71038ffbe8;
  puVar3[1] = 0;
  puVar3[10] = 0;
  puVar3[0xb] = 0;
  puVar3[0xc] = 0;
  puVar3[0xd] = 0;
  puVar3[4] = 0;
  puVar3[5] = 0;
  puVar3[6] = 0;
  puVar3[7] = 0;
  return;
}



void FUN_71011fe974(long *param_1)

{
  uint uVar1;
  long lVar2;
  undefined8 *puVar3;
  undefined4 *puVar4;
  ulong uVar5;
  undefined8 uVar6;
  long lVar7;
  char *local_50;
  uint local_48;
  ushort local_44 [2];
  ushort local_28 [2];
  uint local_24;
  
  local_24 = 0;
  local_50 = "Pos0";
  local_28[0] = 0xffff;
  local_44[0] = 0xffff;
  lVar7 = *(long *)(param_1[1] + 0x10);
  local_48 = 0;
  lVar2 = (**(code **)(*param_1 + 0xa0))();
  puVar3 = FUN_71011f0f70(lVar7,(long *)&local_50,lVar2 + 0x30,local_28,local_44,&local_24,
                          (long)param_1,(undefined1 *)0x0,&local_48);
  FUN_71011f1930((long)param_1,(long *)&local_50,(ulong *)(param_1 + 10),0,(ulong)local_24,
                 (ulong)local_28[0],(ulong)local_44[0],0,(ulong)puVar3,local_48);
  local_24 = 0;
  local_50 = "Pos1";
  local_28[0] = 0xffff;
  local_44[0] = 0xffff;
  lVar7 = *(long *)(param_1[1] + 0x10);
  local_48 = 0;
  lVar2 = (**(code **)(*param_1 + 0xa0))(param_1);
  puVar3 = FUN_71011f0f70(lVar7,(long *)&local_50,lVar2 + 0x30,local_28,local_44,&local_24,
                          (long)param_1,(undefined1 *)0x0,&local_48);
  FUN_71011f1930((long)param_1,(long *)&local_50,(ulong *)(param_1 + 0xb),0,(ulong)local_24,
                 (ulong)local_28[0],(ulong)local_44[0],0,(ulong)puVar3,local_48);
  local_24 = 0;
  local_50 = "VertexY";
  local_28[0] = 0xffff;
  local_44[0] = 0xffff;
  lVar7 = *(long *)(param_1[1] + 0x10);
  local_48 = 0;
  lVar2 = (**(code **)(*param_1 + 0xa0))(param_1);
  puVar4 = FUN_710101cf70(lVar7,(long *)&local_50,lVar2 + 0x30,local_28,local_44,&local_24,
                          (long)param_1,(undefined1 *)0x0,&local_48);
  FUN_710101d1b0((long)param_1,(long *)&local_50,(ulong *)(param_1 + 0xc),0,(ulong)local_24,
                 (ulong)local_28[0],(ulong)local_44[0],0,(ulong)puVar4,local_48);
  local_24 = 0;
  local_50 = "Ratio";
  local_28[0] = 0xffff;
  local_44[0] = 0xffff;
  lVar7 = *(long *)(param_1[1] + 0x10);
  local_48 = 0;
  lVar2 = (**(code **)(*param_1 + 0xa0))(param_1);
  puVar4 = FUN_710101cf70(lVar7,(long *)&local_50,lVar2 + 0x30,local_28,local_44,&local_24,
                          (long)param_1,(undefined1 *)0x0,&local_48);
  uVar5 = (ulong)local_44[0];
  uVar6 = 0;
  FUN_710101d1b0((long)param_1,(long *)&local_50,(ulong *)(param_1 + 0xd),0,(ulong)local_24,
                 (ulong)local_28[0],uVar5,0,(ulong)puVar4,local_48);
  local_24 = local_24 & 0xffffff00;
  local_50 = "PosOut";
  lVar7 = *(long *)(param_1[1] + 0x10);
  lVar2 = (**(code **)(*param_1 + 0xa0))(param_1);
  uVar1 = FUN_7102963610(lVar7,(long *)&local_50,lVar2 + 0x30,param_1,(byte *)&local_24,
                         (undefined1 *)0x0,uVar5,uVar6);
  FUN_7102962d38((long)param_1,(ulong *)(param_1 + 0xe),uVar1,local_24 & 0xff);
  return;
}



void FUN_71011fec34(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if ((DAT_710406a960 & 1) == 0) {
    iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a960);
    if (iVar1 != 0) {
      DAT_710406a958 = DAT_7103a60348 + 0x10;
      thunk_EXT_FUN_02e95df0(&DAT_710406a960);
    }
  }
  if (param_2 != &DAT_710406a958) {
    FUN_710101133c(param_1,param_2);
    return;
  }
  return;
}



undefined8 * FUN_71011fecc0(void)

{
  int iVar1;
  
  if (((DAT_710406a960 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a960), iVar1 != 0))
  {
    DAT_710406a958 = DAT_7103a60348 + 0x10;
    thunk_EXT_FUN_02e95df0(&DAT_710406a960);
  }
  return &DAT_710406a958;
}



void FUN_71011fed1c(long *param_1)

{
  long *plVar1;
  
  *param_1 = DAT_7103a72c80 + 0x10;
  if ((long *)param_1[2] != (long *)0x0) {
    (**(code **)(*(long *)param_1[2] + 8))();
  }
  if (DAT_7105a06420 != 0) {
    plVar1 = FUN_71024ef490(DAT_7105a06420,param_1);
    if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071011fed80. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
      return;
    }
    return;
  }
  FUN_71005fbbd0((long)param_1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_71011fedc0(void)

{
  int iVar1;
  
  DAT_710406a950 = (undefined8 *)0x0;
  DAT_710406a938 = 0xd4adf93d;
  DAT_710406a940 = FUN_71011fe4e8;
  DAT_710406a948 = (undefined8 *)0x0;
  if (((DAT_710405c890 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710405c890), iVar1 != 0))
  {
    DAT_710405c878 = &DAT_710405c878;
    DAT_710405c880 = &DAT_710405c878;
    _DAT_710405c888 = 0xffffffff00000000;
    thunk_EXT_FUN_02e95df0(DAT_7103a5fe28);
  }
  DAT_710406a948 = DAT_710405c878;
  DAT_710405c88c = 0x10;
  DAT_710405c878 = &DAT_710406a948;
  DAT_710406a950 = &DAT_710405c878;
  if (DAT_710406a948 != (undefined8 *)0x0) {
    DAT_710406a948[1] = &DAT_710406a948;
  }
  _DAT_710405c888 = CONCAT44(DAT_710405c88c,DAT_710405c888 + 1);
  return;
}



void FUN_71011fee78(long *param_1)

{
  long lVar1;
  long lVar2;
  undefined8 *puVar3;
  
  lVar1 = DAT_7105a06420;
  if (DAT_7105a06420 == 0) {
    puVar3 = (undefined8 *)FUN_71005fbcb0(8,0x50);
  }
  else {
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar3 = (undefined8 *)(lVar1 + 8);
      if (lVar2 != 0) {
        puVar3 = (undefined8 *)(lVar2 + 0x88);
      }
      param_1 = (long *)*puVar3;
    }
    puVar3 = (undefined8 *)(**(code **)(*param_1 + 0x30))(param_1,0x50,8);
  }
  puVar3[2] = 0;
  puVar3[3] = 0;
  *(undefined1 *)((long)puVar3 + 0x1e) = 0xff;
  *puVar3 = &DAT_71038ffd20;
  puVar3[1] = 0;
  puVar3[4] = 0;
  puVar3[5] = 0;
  puVar3[6] = 0;
  puVar3[7] = 0;
  puVar3[8] = 0;
  puVar3[9] = 0;
  return;
}



void FUN_71011ff4e4(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if ((DAT_710406a990 & 1) == 0) {
    iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a990);
    if (iVar1 != 0) {
      DAT_710406a988 = DAT_7103a60348 + 0x10;
      thunk_EXT_FUN_02e95df0(&DAT_710406a990);
    }
  }
  if (param_2 != &DAT_710406a988) {
    FUN_710101133c(param_1,param_2);
    return;
  }
  return;
}



undefined8 * FUN_71011ff570(void)

{
  int iVar1;
  
  if (((DAT_710406a990 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a990), iVar1 != 0))
  {
    DAT_710406a988 = DAT_7103a60348 + 0x10;
    thunk_EXT_FUN_02e95df0(&DAT_710406a990);
  }
  return &DAT_710406a988;
}



void FUN_71011ff5cc(long *param_1)

{
  long *plVar1;
  
  *param_1 = DAT_7103a72c80 + 0x10;
  if ((long *)param_1[2] != (long *)0x0) {
    (**(code **)(*(long *)param_1[2] + 8))();
  }
  if (DAT_7105a06420 != 0) {
    plVar1 = FUN_71024ef490(DAT_7105a06420,param_1);
    if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071011ff630. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
      return;
    }
    return;
  }
  FUN_71005fbbd0((long)param_1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_71011ff670(void)

{
  int iVar1;
  
  DAT_710406a980 = (undefined8 *)0x0;
  DAT_710406a968 = 0x4affd72c;
  DAT_710406a970 = FUN_71011fee78;
  DAT_710406a978 = (undefined8 *)0x0;
  if (((DAT_710405c890 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710405c890), iVar1 != 0))
  {
    DAT_710405c878 = &DAT_710405c878;
    DAT_710405c880 = &DAT_710405c878;
    _DAT_710405c888 = 0xffffffff00000000;
    thunk_EXT_FUN_02e95df0(DAT_7103a5fe28);
  }
  DAT_710406a978 = DAT_710405c878;
  DAT_710405c88c = 0x10;
  DAT_710405c878 = &DAT_710406a978;
  DAT_710406a980 = &DAT_710405c878;
  if (DAT_710406a978 != (undefined8 *)0x0) {
    DAT_710406a978[1] = &DAT_710406a978;
  }
  _DAT_710405c888 = CONCAT44(DAT_710405c88c,DAT_710405c888 + 1);
  return;
}



void FUN_71011ff728(long *param_1)

{
  long lVar1;
  long lVar2;
  undefined8 *puVar3;
  
  lVar1 = DAT_7105a06420;
  if (DAT_7105a06420 == 0) {
    puVar3 = (undefined8 *)FUN_71005fbcb0(8,0x48);
  }
  else {
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar3 = (undefined8 *)(lVar1 + 8);
      if (lVar2 != 0) {
        puVar3 = (undefined8 *)(lVar2 + 0x88);
      }
      param_1 = (long *)*puVar3;
    }
    puVar3 = (undefined8 *)(**(code **)(*param_1 + 0x30))(param_1,0x48,8);
  }
  puVar3[2] = 0;
  puVar3[3] = 0;
  *(undefined1 *)((long)puVar3 + 0x1e) = 0xff;
  puVar3[8] = 0;
  *puVar3 = &DAT_71038ffe58;
  puVar3[1] = 0;
  puVar3[4] = 0;
  puVar3[5] = 0;
  puVar3[6] = 0;
  puVar3[7] = 0;
  return;
}



void FUN_71011ff910(long *param_1)

{
  char *pcVar1;
  long lVar2;
  undefined4 *puVar3;
  uint uVar4;
  uint uVar5;
  undefined8 uVar6;
  ulong uVar7;
  ulong uVar8;
  ulong uVar9;
  undefined8 uVar10;
  ulong uVar11;
  long lVar12;
  long lVar13;
  uint local_160;
  ushort local_15c [2];
  ushort local_158 [2];
  uint local_154;
  char *local_150;
  undefined4 local_148;
  char local_144 [255];
  undefined1 local_45;
  
  local_154 = 0;
  local_150 = "Val0";
  local_158[0] = 0xffff;
  local_15c[0] = 0xffff;
  lVar13 = *(long *)(param_1[1] + 0x10);
  local_160 = 0;
  lVar2 = (**(code **)(*param_1 + 0xa0))();
  puVar3 = FUN_710101cf70(lVar13,(long *)&local_150,lVar2 + 0x30,local_158,local_15c,&local_154,
                          (long)param_1,(undefined1 *)0x0,&local_160);
  FUN_710101d1b0((long)param_1,(long *)&local_150,(ulong *)(param_1 + 5),0,(ulong)local_154,
                 (ulong)local_158[0],(ulong)local_15c[0],0,(ulong)puVar3,local_160);
  local_154 = 0;
  local_150 = "Val1";
  local_158[0] = 0xffff;
  local_15c[0] = 0xffff;
  lVar13 = *(long *)(param_1[1] + 0x10);
  local_160 = 0;
  lVar2 = (**(code **)(*param_1 + 0xa0))(param_1);
  puVar3 = FUN_710101cf70(lVar13,(long *)&local_150,lVar2 + 0x30,local_158,local_15c,&local_154,
                          (long)param_1,(undefined1 *)0x0,&local_160);
  FUN_710101d1b0((long)param_1,(long *)&local_150,(ulong *)(param_1 + 6),0,(ulong)local_154,
                 (ulong)local_158[0],(ulong)local_15c[0],0,(ulong)puVar3,local_160);
  local_154 = 0;
  local_150 = "Ratio";
  local_158[0] = 0xffff;
  local_15c[0] = 0xffff;
  lVar13 = *(long *)(param_1[1] + 0x10);
  local_160 = 0;
  lVar2 = (**(code **)(*param_1 + 0xa0))(param_1);
  puVar3 = FUN_710101cf70(lVar13,(long *)&local_150,lVar2 + 0x30,local_158,local_15c,&local_154,
                          (long)param_1,(undefined1 *)0x0,&local_160);
  uVar7 = (ulong)local_154;
  uVar9 = (ulong)local_15c[0];
  uVar6 = 0;
  uVar10 = 0;
  uVar8 = (ulong)local_158[0];
  FUN_710101d1b0((long)param_1,(long *)&local_150,(ulong *)(param_1 + 7),0,uVar7,uVar8,uVar9,0,
                 (ulong)puVar3,local_160);
  lVar13 = *(long *)(param_1[1] + 0x10);
  lVar2 = (**(code **)(*param_1 + 0xa0))(param_1);
  if (0 < (int)*(uint *)(lVar2 + 0x5c)) {
    uVar11 = 0;
    lVar12 = *(long *)(lVar13 + 0x10);
    do {
      uVar5 = *(uint *)(lVar12 + *(int *)(*(long *)(lVar13 + 0x28) + 0x14) +
                        (long)*(int *)(lVar2 + 0x58) * 4 + uVar11 * 4);
      pcVar1 = (char *)(lVar12 + *(int *)(lVar12 + 0x24) + ((ulong)uVar5 & 0x7fffffff));
      if ((pcVar1 == "ValRatio") ||
         ((((((*pcVar1 == 'V' && (pcVar1[1] == 'a')) && (pcVar1[2] == 'l')) &&
            ((pcVar1[3] == 'R' && (pcVar1[4] == 'a')))) &&
           ((pcVar1[5] == 't' && ((pcVar1[6] == 'i' && (pcVar1[7] == 'o')))))) &&
          (pcVar1[8] == '\0')))) {
        uVar5 = uVar5 >> 0x1f;
        uVar4 = (*(int *)(lVar2 + 0x3c) + *(int *)(lVar2 + 0x4c) + (int)uVar11) * 4;
        goto LAB_71011ffc18;
      }
      uVar11 = uVar11 + 1;
    } while (*(uint *)(lVar2 + 0x5c) != uVar11);
  }
  local_150 = local_144;
  local_45 = 0;
  local_148 = 0x100;
  lVar2 = *(long *)(lVar13 + 0x10);
  local_144[0] = '\0';
  FUN_7100bc08f0((long *)&local_150,"%s.ain",
                 lVar2 + *(int *)(lVar2 + 0x24) + (long)*(int *)(lVar2 + 8),uVar6,uVar7,uVar8,uVar9,
                 uVar10);
  uVar5 = 0;
  uVar4 = 0xffffffff;
LAB_71011ffc18:
  FUN_71010c54c0((long)param_1,(ulong *)(param_1 + 8),uVar4,uVar5);
  return;
}



void FUN_71011ffc3c(undefined8 param_1,long *param_2)

{
  int iVar1;
  
  if ((DAT_710406a9c0 & 1) == 0) {
    iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a9c0);
    if (iVar1 != 0) {
      DAT_710406a9b8 = DAT_7103a60348 + 0x10;
      thunk_EXT_FUN_02e95df0(&DAT_710406a9c0);
    }
  }
  if (param_2 != &DAT_710406a9b8) {
    FUN_710101133c(param_1,param_2);
    return;
  }
  return;
}



undefined8 * FUN_71011ffcc8(void)

{
  int iVar1;
  
  if (((DAT_710406a9c0 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710406a9c0), iVar1 != 0))
  {
    DAT_710406a9b8 = DAT_7103a60348 + 0x10;
    thunk_EXT_FUN_02e95df0(&DAT_710406a9c0);
  }
  return &DAT_710406a9b8;
}



void FUN_71011ffd24(long *param_1)

{
  long *plVar1;
  
  *param_1 = DAT_7103a72c80 + 0x10;
  if ((long *)param_1[2] != (long *)0x0) {
    (**(code **)(*(long *)param_1[2] + 8))();
  }
  if (DAT_7105a06420 != 0) {
    plVar1 = FUN_71024ef490(DAT_7105a06420,param_1);
    if (plVar1 != (long *)0x0) {
                    // WARNING: Could not recover jumptable at 0x0071011ffd88. Too many branches
                    // WARNING: Treating indirect jump as call
      (**(code **)(*plVar1 + 0x38))(plVar1,param_1);
      return;
    }
    return;
  }
  FUN_71005fbbd0((long)param_1);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_71011ffdc0(void)

{
  int iVar1;
  
  DAT_710406a9b0 = (undefined8 *)0x0;
  DAT_710406a998 = 0x9fc7955d;
  DAT_710406a9a0 = FUN_71011ff728;
  DAT_710406a9a8 = (undefined8 *)0x0;
  if (((DAT_710405c890 & 1) == 0) && (iVar1 = thunk_EXT_FUN_02e95df0(&DAT_710405c890), iVar1 != 0))
  {
    DAT_710405c878 = &DAT_710405c878;
    DAT_710405c880 = &DAT_710405c878;
    _DAT_710405c888 = 0xffffffff00000000;
    thunk_EXT_FUN_02e95df0(DAT_7103a5fe28);
  }
  DAT_710406a9a8 = DAT_710405c878;
  DAT_710405c88c = 0x10;
  DAT_710405c878 = &DAT_710406a9a8;
  DAT_710406a9b0 = &DAT_710405c878;
  if (DAT_710406a9a8 != (undefined8 *)0x0) {
    DAT_710406a9a8[1] = &DAT_710406a9a8;
  }
  _DAT_710405c888 = CONCAT44(DAT_710405c88c,DAT_710405c888 + 1);
  return;
}



void FUN_71011ffe78(long *param_1)

{
  long lVar1;
  long lVar2;
  undefined8 *puVar3;
  
  lVar1 = DAT_7105a06420;
  if (DAT_7105a06420 == 0) {
    puVar3 = (undefined8 *)FUN_71005fbcb0(8,0x48);
  }
  else {
    if (param_1 == (long *)0x0) {
      lVar2 = thunk_EXT_FUN_02e95df0(*(undefined4 *)(DAT_7105a06570 + 0x68));
      puVar3 = (undefined8 *)(lVar1 + 8);
      if (lVar2 != 0) {
        puVar3 = (undefined8 *)(lVar2 + 0x88);
      }
      param_1 = (long *)*puVar3;
    }
    puVar3 = (undefined8 *)(**(code **)(*param_1 + 0x30))(param_1,0x48,8);
  }
  puVar3[2] = 0;
  puVar3[3] = 0;
  *(undefined1 *)((long)puVar3 + 0x1e) = 0xff;
  puVar3[8] = 0;
  *puVar3 = &DAT_71038fff90;
  puVar3[1] = 0;
  puVar3[4] = 0;
  puVar3[5] = 0;
  puVar3[6] = 0;
  puVar3[7] = 0;
  return;
}
