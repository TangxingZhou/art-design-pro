<template>
  <ElDialog
    v-model="dialogVisible"
    title="重置密码"
    width="480px"
    align-center
    destroy-on-close
    :close-on-click-modal="false"
  >
    <ElForm ref="formRef" :model="formData" :rules="rules" label-width="100px">
      <ElFormItem :label="`${entityLabel}名称`">
        <ElInput :model-value="entityName" disabled />
      </ElFormItem>
      <ElFormItem label="新密码" prop="password">
        <ElInput
          v-model="formData.password"
          type="password"
          maxlength="16"
          show-password
          placeholder="请输入新密码"
        />
        <div class="form-tip">8至16个字符，必须包含大写字母、小写字母和数字</div>
      </ElFormItem>
    </ElForm>

    <template #footer>
      <ElButton @click="dialogVisible = false">取消</ElButton>
      <ElButton type="primary" :loading="submitting" @click="handleSubmit">确定</ElButton>
    </template>
  </ElDialog>
</template>

<script setup lang="ts">
  import type { FormInstance, FormRules } from 'element-plus'

  interface Props {
    visible: boolean
    entityName?: string
    entityLabel?: string
    submitting?: boolean
  }

  interface Emits {
    (e: 'update:visible', value: boolean): void
    (e: 'submit', password: string): void
  }

  const props = withDefaults(defineProps<Props>(), {
    entityName: '',
    entityLabel: '渠道',
    submitting: false
  })
  const emit = defineEmits<Emits>()

  const formRef = ref<FormInstance>()
  const formData = reactive({ password: '' })
  const dialogVisible = computed({
    get: () => props.visible,
    set: (value) => emit('update:visible', value)
  })

  const rules: FormRules = {
    password: [
      { required: true, message: '请输入新密码', trigger: 'blur' },
      { min: 8, max: 16, message: '密码长度必须为8至16个字符', trigger: 'blur' },
      {
        pattern: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,16}$/,
        message: '密码必须包含大写字母、小写字母和数字',
        trigger: 'blur'
      }
    ]
  }

  const handleSubmit = async () => {
    const valid = await formRef.value?.validate().catch(() => false)
    if (!valid) return

    emit('submit', formData.password)
  }

  watch(
    () => props.visible,
    (visible) => {
      if (!visible) return

      formData.password = ''
      nextTick(() => formRef.value?.clearValidate())
    }
  )
</script>

<style scoped lang="scss">
  .form-tip {
    margin-top: 4px;
    font-size: 12px;
    line-height: 18px;
    color: var(--el-text-color-secondary);
  }
</style>
