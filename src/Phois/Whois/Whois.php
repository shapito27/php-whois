<?php

namespace Phois\Whois;

use InvalidArgumentException;
use RuntimeException;

/**
 * Class Whois
 * @package Phois\Whois
 */
class Whois
{
    /** @var string  */
    private $domain;

    /** @var string  */
    private $TLDs;

    /** @var string  */
    private $subDomain;

    /** @var array  */
    private $servers;

    /** @var string */
    private $whoisInfo;

    /** @var int  */
    private $timeout = 20;

    //socket options
    /** @var int */
    private $socketPort = 43;
    /** @var int */
    private $socketErrorNo;
    /** @var string */
    private $socketError;

    /**
     * @param string $domain full domain name (no subdomain and without trailing dot)
     */
    public function __construct(string $domain)
    {
        $this->domain = strtolower($domain);
        // check $domain syntax and split full domain name on subdomain and TLDs
        if (
            preg_match('/^([\p{L}\d\-]+)\.((?:[\p{L}\d\-]+\.?)+)$/ui', $this->domain, $matches)
            || preg_match('/^(xn--[\p{L}\d\-]+)\.(xn--(?:[a-z\d-]+\.?1?)+)$/ui', $this->domain, $matches)
        ) {
            $this->subDomain = $matches[1];
            $this->TLDs = $matches[2];
        } else {
            throw new InvalidArgumentException("Invalid $domain syntax");
        }

        // setup whois servers array from json file
        $this->servers = json_decode(file_get_contents( __DIR__.'/whois.servers.json' ), true);
        
        if (!$this->isValid()){
        	throw new InvalidArgumentException("Domain name isn't valid!");
        }
    }

    /**
     * @return string
     */
    public function info(): string
    {
        if ($this->whoisInfo !== '')
            return $this->whoisInfo;

        if ($this->isValid()) {
            $whois_server = $this->servers[$this->TLDs][0];

            // If TLDs have been found
            if ($whois_server !== '') {

                // if whois server serve reply over HTTP protocol instead of WHOIS protocol
                if (preg_match("/^https?:\/\//i", $whois_server)) {

                    // curl session to get whois response
                    $ch = curl_init();
                    $url = $whois_server . $this->subDomain . '.' . $this->TLDs;
                    curl_setopt($ch, CURLOPT_URL, $url);
                    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 0);
                    curl_setopt($ch, CURLOPT_TIMEOUT, $this->timeout);
                    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
                    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
                    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);

                    $data = curl_exec($ch);

                    if (curl_error($ch)) {
                        return "Connection error!";
                    }

                    $string = strip_tags($data);

                    curl_close($ch);

                } else {
                    // check whois server exist
                    if (gethostbyname($whois_server) === $whois_server) {
                        return "Whois server not exist error!";
                    }

                    // Getting whois information
                    $fp = fsockopen($whois_server, $this->socketPort, $this->socketErrorNo, $this->socketError, $this->timeout);
                    if (!$fp) {
                        return "Connection error! ".$this->socketErrorNo.":".$this->socketError;
                    }
                    stream_set_blocking($fp, true);
                    stream_set_timeout($fp, $this->timeout);
                    $info = stream_get_meta_data($fp);

                    $dom = $this->subDomain . '.' . $this->TLDs;
                    fputs($fp, "$dom\r\n");

                    // Getting string
                    $string = '';

                    // Checking whois server for .com and .net
                    if ($this->TLDs === 'com' || $this->TLDs === 'net') {
                        while ( (!feof($fp)) && (!$info['timed_out']) ) {
                            $line = trim(fgets($fp, 128));

                            $string .= $line;

                            $lineArr = explode (":", $line);

                            if (strtolower($lineArr[0]) === 'whois server') {
                                $whois_server = trim($lineArr[1]);
                            }
                            $info = stream_get_meta_data($fp);
                        }
                        // Getting whois information
                        $fp = fsockopen($whois_server, $this->socketPort, $this->socketErrorNo, $this->socketError, $this->timeout);
                        if (!$fp) {
                            return "Connection error! ".$this->socketErrorNo.":".$this->socketError;
                        }

                        stream_set_blocking($fp, TRUE);
                        stream_set_timeout($fp,$this->timeout);
                        $info = stream_get_meta_data($fp);

                        $dom = $this->subDomain . '.' . $this->TLDs;
                        fputs($fp, "$dom\r\n");

                        // Getting string
                        $string = '';

                        while (!feof($fp)) {
                            $string .= fgets($fp, 128);
                        }

                        // Checking for other tld's
                    } else {
                        while ( (!feof($fp)) && (!$info['timed_out']) ) {
                            $string .= fgets($fp, 128);
                            $info = stream_get_meta_data($fp);
                        }
                    }
                    fclose($fp);
                }

                $string_encoding = mb_detect_encoding($string, "UTF-8, ISO-8859-1, ISO-8859-15", true);
                $string_utf8 = mb_convert_encoding($string, "UTF-8", $string_encoding);

                $this->whoisInfo = htmlspecialchars($string_utf8, ENT_COMPAT, "UTF-8", true);

                return $this->whoisInfo;
            }

            return "No whois server for this tld in list!";
        }

        return "Domain name isn't valid!";
    }

    /**
     * @return \stdClass
     */
    public function data()
    {
      $result = new \stdClass();
      $result->status = 0;
      $result->message = 'error';
      $result->data = [];
      try {
        $info = $this->info();

        $not_found_string = FALSE;
        if (isset($this->servers[$this->TLDs][1])) {
           $not_found_string = $this->servers[$this->TLDs][1];
        }

        // Check if this domain is not found (available for registration).
        if ($not_found_string) {
          if (strpos($info, $not_found_string) !== false) {
            $result->status = 2;
            $result->message = 'not_found';
          }
        }

        // Make sure the status is still the default value, and the not_found
        // string value are exists before extracting the data from info.
        if (($result->status == 0) && ($not_found_string)) {
          $exploded_info = explode("\n", $info);
          $data = [];
          foreach ($exploded_info as $lineNumber => $line) {
            if (strpos($line, 'Creation Date:') !== false) {
              $data['creation_date'] = trim(str_replace('Creation Date:', '', $line));
            }

            if (strpos($line, 'Registry Expiry Date:') !== false) {
              $data['expiration_date'] = trim(str_replace('Registry Expiry Date:', '', $line));
            }

            if (strpos($line, 'Updated Date:') !== false) {
              $data['update_date'] = trim(str_replace('Updated Date:', '', $line));
            }

            if (strpos($line, 'Registry Domain ID:') !== false) {
              $data['registry_domain_id'] = trim(str_replace('Registry Domain ID:', '', $line));
            }

            if (strpos($line, 'Registrar:') !== false) {
              if (!isset($data['registrar'])) {
                $data['registrar'] = [];
              }
              $data['registrar']['name'] = trim(str_replace('Registrar:', '', $line));
            }

            if (strpos($line, 'Registrar IANA ID:') !== false) {
              if (!isset($data['registrar'])) {
                $data['registrar'] = [];
              }
              $data['registrar']['id'] = trim(str_replace('Registrar IANA ID:', '', $line));
            }

            if (strpos($line, 'Name Server:') !== false) {
              if (!isset($data['name_servers'])) {
                $data['name_servers'] = [];
              }
              $data['name_servers'][] = trim(str_replace('Name Server:', '', $line));
            }
          }

          // If there are data, we will count this as registered.
          if (count($data) > 0) {
            $result->status = 1;
            $result->message = 'found';
            $result->data = $data;
          }
        }

      } catch (RuntimeException $e) {
        $result->status = -1;
        $result->message = 'exception';
      }

      return $result;
    }

    /**
     * @return bool
     */
    public function isServerDefined(): bool
    {
        return isset($this->servers[$this->TLDs]);
    }

    /**
     * @return string
     */
    public function htmlInfo(): string
    {
        return nl2br($this->info());
    }

    /**
     * @return string full domain name
     */
    public function getDomain()
    {
        return $this->domain;
    }

    /**
     * @return string top level domains separated by dot
     */
    public function getTLDs()
    {
        return $this->TLDs;
    }

    /**
     * @return string return subdomain (low level domain)
     */
    public function getSubDomain()
    {
        return $this->subDomain;
    }
    
	/**
     * @return boolean, true for domain avaliable, false for domain registered
     */
    public function isAvailable()
    {
        if ($this->whoisInfo == '') {
            $whois_string = $this->info();
        } else {
            $whois_string = $this->whoisInfo;
        }
        $not_found_string = '';
        if (isset($this->servers[$this->TLDs][1])) {
           $not_found_string = $this->servers[$this->TLDs][1];
        }

        $whois_string2 = @preg_replace('/' . $this->domain . '/', '', $whois_string);
        $whois_string = @preg_replace("/\s+/", ' ', $whois_string);

        $array = explode (":", $not_found_string);
        if ($array[0] === "MAXCHARS") {
            return strlen($whois_string2) <= $array[1];
        }

        if (preg_match("/" . $not_found_string . "/i", $whois_string)) {
            return true;
        }

        return false;
    }

    /**
     * @return bool
     */
    public function isValid(): bool
    {
        if (
            isset($this->servers[$this->TLDs][0])
            && strlen($this->servers[$this->TLDs][0]) > 6
        ) {
            $tmp_domain = strtolower($this->subDomain);
            if (
                preg_match("/^[a-z0-9\-]{1,}$/", $tmp_domain)
                && !preg_match("/^-|-$/", $tmp_domain) //&& !preg_match("/--/", $tmp_domain)
            ) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return int
     */
    public function getTimeout(): int
    {
        return $this->timeout;
    }

    /**
     * @param  int  $timeout
     */
    public function setTimeout(int $timeout): void
    {
        $this->timeout = $timeout;
    }
}
