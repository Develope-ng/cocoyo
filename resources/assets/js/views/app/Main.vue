<template>
    <v-app>
        <navbar></navbar>

        <router-view></router-view>

        <footer-bar></footer-bar>
        <BackTop :height="100" :bottom="30">
            <v-btn fab dark small color="red" >
                <Icon style="font-size:16px" type="chevron-up"></Icon>
            </v-btn>
        </BackTop>
    </v-app>
</template>

<script>
    import Navbar from '@/components/Navbar'
    import FooterBar from '@/components/Footer'

    export default {
        components: {
            Navbar,
            FooterBar
        },
        data() {
            return {

            }
        },

    }
</script>

<style scoped>
    .top{
        padding: 10px;
        background: rgba(0, 153, 229, .7);
        color: #fff;
        text-align: center;
        border-radius: 2px;
    }
</style>
