


void FUN_7100604508(undefined1 *param_1,undefined8 param_2,byte *param_3)

{
  int iVar1;
  undefined4 uVar2;
  undefined8 uVar3;
  
  *(undefined8 *)(param_1 + 8) = *(undefined8 *)(*(long *)(param_3 + 0x18) + 8);
  *(undefined1 **)(param_1 + 0x10) = param_1 + 0x18;
  (*DAT_7103ff3c88)();
  (*(code *)*DAT_7103a64b08)(*(undefined8 *)(param_1 + 0x10),*(undefined2 *)(param_3 + 2),1);
  (*(code *)*DAT_7103a64b00)
            (*(undefined8 *)(param_1 + 0x10),*(undefined4 *)(param_3 + 8),
             *(undefined4 *)(param_3 + 0xc));
  uVar3 = *(undefined8 *)(param_1 + 0x10);
  iVar1 = FUN_7100601450(*(int *)(param_3 + 4));
  (*(code *)*DAT_7103a702e8)(uVar3,iVar1);
  uVar3 = *(undefined8 *)(param_1 + 0x10);
  uVar2 = FUN_7100601510((ulong)*param_3);
  (*(code *)*DAT_7103a70300)(uVar3,uVar2);
  *param_1 = 1;
  param_1[1] = param_1[1] & 0xfe;
  return;
}



void FUN_71006045e0(undefined1 *param_1)

{
  *param_1 = 0;
  *(undefined8 *)(param_1 + 8) = 0;
  *(undefined8 *)(param_1 + 0x10) = 0;
  return;
}



void FUN_71006045ec(undefined8 *param_1)

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
