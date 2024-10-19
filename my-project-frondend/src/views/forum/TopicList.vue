<script setup>

import LightCard from "@/views/components/LightCard.vue";
import {Calendar, CollectionTag} from "@element-plus/icons-vue";
</script>

<template>
    <div style="display: flex; margin: 20px auto; gap: 20px; max-width: 900px">
        <div style="flex: 1;">
            <light-card></light-card>
        </div>
        <div style="width: 280px">
            <div style="position: sticky; top: 20px">
                <light-card>
                    <div style="font-weight: bold">
                        <el-icon><CollectionTag/></el-icon>
                        论坛公告
                    </div>
                    <el-divider style="margin: 10px 0"/>
                    <div style="font-size: 14px;color: grey; margin: 10px">
                        牛逼论坛
                    </div>
                </light-card>
                <light-card style="margin-top: 10px">
                    <div style="font-weight: bold">
                        <el-icon><Calendar/></el-icon>
                        天气信息
                    </div>
                    <el-divider style="margin: 10px 0"/>
                </light-card>
            </div>
        </div>
    </div>
</template>

<style scoped>

</style>