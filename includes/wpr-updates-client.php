<?php
/**
 * WPR Updates Client SDK 1.1.1 (compatibility patch), WordPress >= 5.8, PHP >= 7.4.
 * Public metadata updates with 12-18h jittered cache and ETag/304.
 * Explicitly opt-in anonymous usage telemetry, never auto-enabled.
 */
if ( ! defined( 'ABSPATH' ) ) { exit; }
if ( ! class_exists( 'WPR_Updates_Client_V2', false ) ) {
final class WPR_Updates_Client_V2 {
    const CONSENT_OPTION = 'wpr_updates_optin_stats_v2';
    const CRON = 'wpr_upd_sdk_v2_heartbeat';
    private static $registered = array();
    private static $booted = false;

    public static function register( $main_file, array $config ) {
        if ( ! function_exists('plugin_basename') || !function_exists('add_filter') ) { return false; }
        $slug = isset($config['slug']) ? (string)$config['slug'] : '';
        $server = isset($config['server']) ? untrailingslashit((string)$config['server']) : 'https://xn----ctbgf6biedka.xn--p1ai';
        $host = wp_parse_url($server,PHP_URL_HOST);
        if ( !preg_match('/^[a-z0-9]+(?:-[a-z0-9]+)*$/D',$slug) || 'https' !== wp_parse_url($server,PHP_URL_SCHEME) || !$host ) { return false; }
        $basename = plugin_basename($main_file);
        if ( isset(self::$registered[$basename]) ) { return true; }
        $cfg = array('slug'=>$slug,'server'=>$server,'host'=>$host,'basename'=>$basename,'file'=>$main_file,
            'telemetry'=>!array_key_exists('telemetry',$config) || (bool)$config['telemetry']);
        self::$registered[$basename] = $cfg;
        if ( !self::$booted ) {
            self::$booted = true;
            add_action(self::CRON,array(__CLASS__,'heartbeat'));
            add_action('admin_menu',array(__CLASS__,'add_settings'));
            add_action('admin_post_wpr_updates_telemetry_v2',array(__CLASS__,'save_settings'));
            if ( get_option(self::CONSENT_OPTION,false) && !wp_next_scheduled(self::CRON) ) {
                wp_schedule_event(time()+wp_rand(3600,7200),'daily',self::CRON);
            }
        }
        add_filter('update_plugins_'.$host, static function($update,$plugin_data,$plugin_file,$locales) use ($cfg) {
            if ( $plugin_file !== $cfg['basename'] || !self::header_matches((string)($plugin_data['UpdateURI']??''),$cfg) ) {return $update;}
            $info = self::request($cfg);
            if ( !is_array($info) || empty($info['version']) || empty($plugin_data['Version']) ||
                empty($info['download_url']) || !self::safe_download($info['download_url'],$cfg) ) {return false;}
            return array(
                'id' => $plugin_data['UpdateURI'], 'slug'=>$cfg['slug'], 'version'=>$info['version'],
                'url'=>!empty($info['homepage'])?$info['homepage']:$cfg['server'].'/plugins/'.$cfg['slug'].'/',
                'package'=>$info['download_url'], 'tested'=>$info['tested']??'',
                'requires'=>$info['requires']??'', 'requires_php'=>$info['requires_php']??'',
                // WordPress decides whether to auto-update. No forced autoupdate.
            );
        }, 10, 4);
        // Core hides the auto-update toggle for third-party plugins unless the
        // update_plugins transient has response/no_update for their basename.
        // An offline or not-yet-configured hub must not hide the manual toggle.
        // This only marks update SUPPORT. It never invents an available update.
        $mark_supported = static function($state) use ($cfg) {
            if (!is_object($state)) {return $state;}
            if (isset($state->response[$cfg['basename']]) || isset($state->no_update[$cfg['basename']])) {return $state;}
            $header=get_file_data($cfg['file'],array('Version'=>'Version','UpdateURI'=>'Update URI'),'plugin');
            $version=(string)($header['Version']??'');
            $uri=(string)($header['UpdateURI']??'');
            if (!$version || !self::header_matches($uri,$cfg)) {return $state;}
            if (!isset($state->no_update) || !is_array($state->no_update)) {$state->no_update=array();}
            $state->no_update[$cfg['basename']] = (object)array(
                'id'=>$uri,'plugin'=>$cfg['basename'],'slug'=>$cfg['slug'],
                'version'=>$version,'new_version'=>$version,
                'url'=>$cfg['server'].'/plugins/'.$cfg['slug'].'/'
            );
            return $state;
        };
        add_filter('site_transient_update_plugins',$mark_supported,20);
        add_filter('pre_set_site_transient_update_plugins',$mark_supported,20);
        add_filter('plugins_api',static function($result,$action,$args) use ($cfg) {
            if ('plugin_information'!==$action || !is_object($args) || ($args->slug??'')!==$cfg['slug']) {return $result;}
            if ( !function_exists('get_plugins') ) {require_once ABSPATH.'wp-admin/includes/plugin.php';}
            $installed=get_plugins();
            if ( empty($installed[$cfg['basename']]) || !self::header_matches((string)($installed[$cfg['basename']]['UpdateURI']??''),$cfg) ) {return $result;}
            $info=self::request($cfg);
            if ( !is_array($info) ) {return $result;}
            return (object)array('name'=>$info['name']??$cfg['slug'],'slug'=>$cfg['slug'],'version'=>$info['version'],
                'author'=>'WPR','homepage'=>$info['homepage']??'','requires'=>$info['requires']??'',
                'tested'=>$info['tested']??'','requires_php'=>$info['requires_php']??'',
                'download_link'=>$info['download_url'],'sections'=>(array)($info['sections']??array()));
        },15,3);
        return true;
    }
    private static function header_matches($uri,$cfg) {
        $u=wp_parse_url($uri);
        return is_array($u) && ($u['scheme']??'')==='https' && strtolower($u['host']??'')===strtolower($cfg['host']) &&
            (bool)preg_match('#/plugins/'.preg_quote($cfg['slug'],'#').'/?$#D',$u['path']??'');
    }
    private static function safe_download($url,$cfg) {
        $u=wp_parse_url($url);
        return is_array($u) && ($u['scheme']??'')==='https' && strtolower($u['host']??'')===strtolower($cfg['host']) &&
            0===strpos($u['path']??'', '/wp-json/wpr-updates/v1/download/'.$cfg['slug'].'/');
    }
    private static function cache_key($cfg) {
        return 'wpr_upd_cache_v2_'.substr(md5($cfg['server'].'|'.$cfg['slug']),0,20);
    }
    private static function jitter($cfg) {
        // Deterministic stagger; no random revalidation burst or identifying token in requests.
        return (12 + (hexdec(substr(md5($cfg['basename'].'|'.home_url('/')),0,2)) % 7)) * HOUR_IN_SECONDS;
    }
    private static function request($cfg) {
        $key=self::cache_key($cfg);
        $old=get_option($key,array());
        $now=time();
        if ( is_array($old) && !empty($old['next_check']) && (int)$old['next_check']>$now ) {
            return isset($old['data']) && is_array($old['data']) ? $old['data'] : false;
        }
        $lock='wpr_upd_lock_v2_'.substr(md5($key),0,20);
        if ( get_transient($lock) ) {return isset($old['data']) && is_array($old['data']) ? $old['data'] : false;}
        set_transient($lock,1,60);
        $headers=array('Accept'=>'application/json');
        if ( !empty($old['etag']) ) {$headers['If-None-Match']=$old['etag'];}
        $url=$cfg['server'].'/wp-json/wpr-updates/v1/plugins/'.rawurlencode($cfg['slug']);
        $res=wp_safe_remote_get($url,array('timeout'=>6,'redirection'=>0,'sslverify'=>true,
            'user-agent'=>'WPR-Update-Client/1.1','headers'=>$headers));
        $code=is_wp_error($res)?0:wp_remote_retrieve_response_code($res);
        $new=is_array($old)?$old:array();
        if (304===$code && array_key_exists('data',$new)) {
            $new['next_check']=$now+self::jitter($cfg);
        } elseif (200===$code) {
            $body=wp_remote_retrieve_body($res);
            $data=is_string($body) && strlen($body)<262144?json_decode($body,true):null;
            if ( self::valid_response($data,$cfg) ) {
                $new=array('data'=>$data,'etag'=>(string)wp_remote_retrieve_header($res,'etag'),
                    'good_at'=>$now,'next_check'=>$now+self::jitter($cfg));
            } else {
                $new['next_check']=$now+30*MINUTE_IN_SECONDS;
            }
        } elseif (404===$code) {
            $new=array('data'=>null,'etag'=>'','next_check'=>$now+self::jitter($cfg));
        } else {
            // Fall back to last known metadata for up to seven days during outages.
            if ( !empty($new['good_at']) && $new['good_at']+7*DAY_IN_SECONDS<$now ) {unset($new['data']);}
            $new['next_check']=$now+30*MINUTE_IN_SECONDS;
        }
        update_option($key,$new,false);
        delete_transient($lock);
        return isset($new['data']) && is_array($new['data'])?$new['data']:false;
    }
    private static function valid_response($d,$cfg) {
        return is_array($d) && ($d['schema']??null)===1 && ($d['slug']??'')===$cfg['slug'] &&
            !empty($d['version']) && is_string($d['version']) &&
            (bool)preg_match('/^[0-9]+(?:\.[0-9]+)*(?:[-.][0-9A-Za-z][0-9A-Za-z.-]*)?$/D',$d['version']) &&
            !empty($d['download_url']) && self::safe_download($d['download_url'],$cfg);
    }
    public static function add_settings() {
        add_options_page('Статистика WPR','Статистика WPR','manage_options','wpr-updates-statistics',array(__CLASS__,'settings_page'));
    }
    public static function settings_page() {
        if (!current_user_can('manage_options')) {return;}
        $on=(bool)get_option(self::CONSENT_OPTION,false);
        echo '<div class="wrap"><h1>Статистика установок WPR</h1>';
        echo '<p>По умолчанию статистика <strong>выключена</strong>. После включения плагины WPR отправляют на сервер обновлений раз в 7 дней псевдонимный случайный ID установки, slug и номер версии. Адрес сайта, IP, имя администратора, посещаемость и персональные данные в запрос не включаются. Веб-сервер и прокси могут вести собственные стандартные HTTP-логи.</p>';
        echo '<p>Отключение остановит отправку данных; SDK попытается удалить прежние записи на сервере. Иначе неактивные записи очищаются через 90 дней.</p>';
        echo '<form action="'.esc_url(admin_url('admin-post.php')).'" method="post">';
        wp_nonce_field('wpr_updates_telemetry_v2');
        echo '<input type="hidden" name="action" value="wpr_updates_telemetry_v2">';
        echo '<label><input type="checkbox" name="consent" value="yes" '.checked($on,true,false).'> Разрешить анонимную статистику установок</label>';
        submit_button('Сохранить настройки');
        echo '</form><p><small>Данные считаются на сервере WPR Update Hub и доступны только его администратору.</small></p></div>';
    }
    public static function save_settings() {
        if (!current_user_can('manage_options')) {wp_die('Forbidden');}
        check_admin_referer('wpr_updates_telemetry_v2');
        $on=isset($_POST['consent']) && 'yes'===$_POST['consent'];
        $before=(bool)get_option(self::CONSENT_OPTION,false);
        if ($before && !$on) {self::forget_all();}
        update_option(self::CONSENT_OPTION,$on,false);
        if ($on && !$before) { wp_schedule_single_event(time()+wp_rand(60,900),self::CRON); }
        wp_safe_redirect(admin_url('options-general.php?page=wpr-updates-statistics&updated=1'));
        exit;
    }
    private static function ids() {
        $ids=get_option('wpr_updates_install_ids_v2',array());
        return is_array($ids)?$ids:array();
    }
    private static function send($cfg,$event,$id,$version='') {
        $url=$cfg['server'].'/wp-json/wpr-updates/v1/installs/'.rawurlencode($cfg['slug']);
        $body=array('schema'=>1,'event'=>$event,'slug'=>$cfg['slug'],'install_id'=>$id);
        if ('heartbeat'===$event) {$body['version']=$version;}
        $r=wp_safe_remote_post($url,array('timeout'=>5,'redirection'=>0,'sslverify'=>true,
            'user-agent'=>'WPR-Update-Client/1.1','headers'=>array('Content-Type'=>'application/json'),
            'body'=>wp_json_encode($body)));
        return !is_wp_error($r) && 200===wp_remote_retrieve_response_code($r);
    }
    public static function heartbeat() {
        if (!get_option(self::CONSENT_OPTION,false)) {return;}
        $ids=self::ids();
        $last=get_option('wpr_updates_heartbeat_at_v2',array());
        if (!is_array($last)) {$last=array();}
        $now=time();
        foreach (self::$registered as $cfg) {
            if (!$cfg['telemetry']) {continue;}
            $slug=$cfg['slug'];
            if (!empty($last[$slug]) && $last[$slug]>$now-7*DAY_IN_SECONDS) {continue;}
            if(empty($ids[$slug])) {$ids[$slug]=wp_generate_uuid4();}
            $data=get_file_data($cfg['file'],array('Version'=>'Version'));
            $version=isset($data['Version'])?$data['Version']:'';
            if (!preg_match('/^[0-9]+(?:\.[0-9]+)*(?:[-.][0-9A-Za-z][0-9A-Za-z.-]*)?$/D',$version)) {continue;}
            if (self::send($cfg,'heartbeat',$ids[$slug],$version)) {$last[$slug]=$now;}
        }
        update_option('wpr_updates_install_ids_v2',$ids,false);
        update_option('wpr_updates_heartbeat_at_v2',$last,false);
    }
    private static function forget_all() {
        $ids=self::ids();
        foreach (self::$registered as $cfg) {
            if (!empty($ids[$cfg['slug']])) {self::send($cfg,'forget',$ids[$cfg['slug']]);}
        }
        delete_option('wpr_updates_install_ids_v2');
        delete_option('wpr_updates_heartbeat_at_v2');
    }
}
}
