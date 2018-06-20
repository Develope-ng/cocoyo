<template>
    <v-content class="main-content base_content">
        <v-container grid-list-xl>
            <v-layout row justify-center>
                <v-flex md4>
                    <Card style="text-align: center">
                        <Alert type="warning" style="line-height:28px;margin-bottom: 30px;">
                            添加请说明来意,可以交换友链,谢谢!
                            <img class="emoji" align="absmiddle" data-original="https://dn-phphub.qbox.me/assets/images/emoji/smile.png" src="https://dn-phphub.qbox.me/assets/images/emoji/smile.png" style="display: inline;">
                        </Alert>
                        <img src="/images/weixin.jpg" class="image-bg">
                    </Card>
                </v-flex>
                <v-flex md4>
                    <Card style="text-align: center">
                        <Alert type="warning" style="line-height:28px;margin-bottom: 30px;">
                            以下是个人小程序，有兴趣的可以关注！
                            <img class="emoji" align="absmiddle" data-original="https://dn-phphub.qbox.me/assets/images/emoji/kissing_heart.png" src="https://dn-phphub.qbox.me/assets/images/emoji/kissing_heart.png" style="display: inline;">
                        </Alert>
                        <img src="/images/wx_program.jpg" class="image-bg">
                    </Card>
                </v-flex>
            </v-layout>
        </v-container>
    </v-content>
</template>

<script>
    export default {
        name: "contact"
    }
</script>

<style scoped>
    .emoji{
        width: 1.4em;
        height: 1.4em;
        display: inline-block;
        margin-bottom: 0;
        margin-top: -5px;
        margin-left: 5px;
    }
    .image-bg{
        border: 2px solid #e4e4e4;
        border-radius: 4px;
        margin-bottom: 18px;
        height:300px
    }
</style>