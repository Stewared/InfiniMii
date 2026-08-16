


void FUN_7100ba6fc4(float *param_1,float *param_2)

{
  char cVar1;
  char cVar2;
  bool bVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  float fVar8;
  float fVar9;
  float local_c [3];
  
  if (*(char *)(param_1 + 4) == '\0') {
    cVar1 = *(char *)((long)param_1 + 0x11);
    cVar2 = *(char *)((long)param_1 + 0x12);
    fVar6 = param_1[3];
    fVar4 = param_1[1];
    fVar5 = param_1[2];
  }
  else {
    fVar4 = param_1[1];
    fVar5 = param_1[2];
    cVar1 = *(char *)((long)param_1 + 0x11);
    cVar2 = *(char *)((long)param_1 + 0x12);
    fVar6 = param_1[3];
    fVar7 = *param_1;
    bVar3 = false;
    if (((((fVar4 == 0.0 && cVar1 != '\0') && fVar5 == 1.4013e-45) && cVar2 != '\0') &&
         fVar6 == 2.8026e-45) && (bVar3 = false, !NAN(fVar7))) {
      bVar3 = fVar7 == 1.0;
    }
    if (bVar3) {
      return;
    }
    if ((((fVar4 == 0.0 && cVar1 != '\0') && fVar5 == 1.4013e-45) && cVar2 != '\0') &&
        fVar6 == 2.8026e-45) {
      if (fVar7 == 1.0) {
        return;
      }
      goto LAB_7100ba7090;
    }
  }
  local_c[0] = *param_2;
  local_c[1] = param_2[1];
  fVar7 = param_2[2];
  fVar8 = local_c[0];
  if (*(char *)(param_1 + 4) != '\0') {
    fVar8 = -local_c[0];
  }
  fVar9 = local_c[1];
  if (cVar1 != '\0') {
    fVar9 = -local_c[1];
  }
  local_c[2] = fVar7;
  local_c[(uint)fVar4] = fVar8;
  if (cVar2 != '\0') {
    fVar7 = -fVar7;
  }
  local_c[(uint)fVar5] = fVar9;
  local_c[(uint)fVar6] = fVar7;
  *(ulong *)param_2 = CONCAT44(local_c[1],local_c[0]);
  param_2[2] = local_c[2];
  fVar7 = *param_1;
  if (fVar7 == 1.0) {
    return;
  }
LAB_7100ba7090:
  *param_2 = fVar7 * *param_2;
  param_2[1] = *param_1 * param_2[1];
  param_2[2] = *param_1 * param_2[2];
  return;
}



void FUN_7100ba70bc(long param_1,float *param_2)

{
  uint uVar1;
  uint uVar2;
  char cVar3;
  char cVar4;
  uint uVar5;
  float fVar6;
  float fVar7;
  float fVar8;
  float local_c [3];
  
  if (*(char *)(param_1 + 0x10) == '\0') {
    cVar3 = *(char *)(param_1 + 0x11);
    cVar4 = *(char *)(param_1 + 0x12);
    uVar5 = *(uint *)(param_1 + 0xc);
    uVar1 = *(uint *)(param_1 + 4);
    uVar2 = *(uint *)(param_1 + 8);
  }
  else {
    cVar3 = *(char *)(param_1 + 0x11);
    uVar1 = *(uint *)(param_1 + 4);
    uVar2 = *(uint *)(param_1 + 8);
    cVar4 = *(char *)(param_1 + 0x12);
    uVar5 = *(uint *)(param_1 + 0xc);
    if ((((uVar1 == 0) && (cVar3 != '\0')) && (uVar2 == 1)) && ((cVar4 != '\0' && (uVar5 == 2)))) {
      return;
    }
  }
  local_c[0] = *param_2;
  local_c[1] = param_2[1];
  fVar8 = param_2[2];
  fVar6 = local_c[0];
  if (*(char *)(param_1 + 0x10) != '\0') {
    fVar6 = -local_c[0];
  }
  fVar7 = local_c[1];
  if (cVar3 != '\0') {
    fVar7 = -local_c[1];
  }
  local_c[2] = fVar8;
  local_c[uVar1] = fVar6;
  if (cVar4 != '\0') {
    fVar8 = -fVar8;
  }
  local_c[uVar2] = fVar7;
  local_c[uVar5] = fVar8;
  *(ulong *)param_2 = CONCAT44(local_c[1],local_c[0]);
  param_2[2] = local_c[2];
  return;
}



void FUN_7100ba7164(long param_1)

{
  *(float *)(param_1 + 4) = -*(float *)(param_1 + 4);
  *(float *)(param_1 + 0x10) = -*(float *)(param_1 + 0x10);
  *(float *)(param_1 + 0x1c) = -*(float *)(param_1 + 0x1c);
  *(float *)(param_1 + 0x28) = -*(float *)(param_1 + 0x28);
  return;
}



void FUN_7100ba7198(undefined8 *param_1)

{
  FUN_71005fc110(param_1);
  FUN_71005fc110(param_1 + 9);
  FUN_71005fc110(param_1 + 0x12);
  return;
}



void FUN_7100ba71c4(void)

{
  ret_71005FC128();
  ret_71005FC128();
  ret_71005FC128();
  return;
}



void FUN_7100ba71f4(undefined1 *param_1,undefined8 *param_2,undefined8 *param_3,long param_4)

{
  long lVar1;
  uint local_40 [4];
  
  local_40[0] = 0;
  local_40[1] = 0;
  local_40[2] = 0;
  local_40[3] = 0;
  FUN_71005fbcfc((undefined8 *)local_40);
  local_40[0] = 0x20;
  local_40[1] = 4;
  FUN_7100ba7550(param_1,param_3,param_2,local_40);
  lVar1 = branch_7100BA77A0_0x71005fc254((long)param_1);
  FUN_7100ba7b90(lVar1,param_4);
  FUN_7100ba7b90(lVar1 + 8,param_4 + 0xc);
  FUN_7100ba7b90(lVar1 + 0x10,param_4 + 0x18);
  FUN_7100ba7b90(lVar1 + 0x18,param_4 + 0x24);
  FUN_7100ba77b0((long)param_1);
  return;
}



void FUN_7100ba729c(long param_1,undefined8 *param_2,undefined8 *param_3,uint *param_4)

{
  undefined1 *puVar1;
  ushort *puVar2;
  uint local_40 [4];
  
  local_40[0] = 0;
  local_40[1] = 0;
  local_40[2] = 0;
  local_40[3] = 0;
  FUN_71005fbcfc((undefined8 *)local_40);
  puVar1 = (undefined1 *)(param_1 + 0x48);
  local_40[0] = 0x10;
  local_40[1] = 4;
  FUN_7100ba7550(puVar1,param_3,param_2,local_40);
  puVar2 = (ushort *)branch_7100BA77A0_0x71005fc254((long)puVar1);
  FUN_7100ba7ba0(puVar2,param_4,8);
  FUN_7100ba7ba0(puVar2 + 2,param_4 + 2,8);
  FUN_7100ba7ba0(puVar2 + 4,param_4 + 4,8);
  FUN_7100ba7ba0(puVar2 + 6,param_4 + 6,8);
  FUN_7100ba77b0((long)puVar1);
  return;
}



void FUN_7100ba7358(long param_1,undefined8 *param_2,undefined8 *param_3,undefined8 param_4)

{
  undefined1 *puVar1;
  undefined8 uVar2;
  ulong local_40 [2];
  
  local_40[0] = 0;
  local_40[1] = 0;
  FUN_71005fbcfc(local_40);
  puVar1 = (undefined1 *)(param_1 + 0x90);
  local_40[0] = 0x80000000c;
  FUN_7100ba7550(puVar1,param_3,param_2,(uint *)local_40);
  uVar2 = branch_7100BA77A0_0x71005fc254((long)puVar1);
  thunk_EXT_FUN_02e95df0(uVar2,param_4,local_40[0] & 0xffffffff);
  FUN_7100ba77b0((long)puVar1);
  return;
}



void FUN_7100ba73e0(char *param_1)

{
  if (*param_1 != '\0') {
    FUN_71005fc21c(param_1);
  }
  if (param_1[0x48] != '\0') {
    FUN_71005fc21c(param_1 + 0x48);
  }
  if (param_1[0x90] != '\0') {
    FUN_71005fc21c(param_1 + 0x90);
    return;
  }
  return;
}
