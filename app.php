<?php
  // The global $_POST variable allows you to access the data sent with the POST method by name
  // To access the data sent with the GET method, you can use $_GET
  $option = htmlspecialchars($_POST['option']);
  $keyword  = htmlspecialchars($_POST['keyword']);
  $message  = htmlspecialchars($_POST['message']);

  $encode_option = "1";
  $decode_option = "2";

  $alphabet = [
    '0' => 'a',
    '1' => 'b',
    '2' => 'c',
    '3' => 'd',
    '4' => 'e',
    '5' => 'f',
    '6' => 'g',
    '7' => 'h',
    '8' => 'i',
    '9' => 'j',
    '10' => 'k',
    '11' => 'l',
    '12' => 'm',
    '13' => 'n',
    '14' => 'o',
    '15' => 'p',
    '16' => 'q',
    '17' => 'r',
    '18' => 's',
    '19' => 't',
    '20' => 'u',
    '21' => 'v',
    '22' => 'w',
    '23' => 'x',
    '24' => 'y',
    '25' => 'z'];

  if (strcmp($option, $encode_option) !== 0 && strcmp($option, $decode_option) !== 0) {
    exit ("Las opciones validas son " . $encode_option . " (cifrar) y " . $decode_option . " (descifrar).");
  }

  // Comprueba que la clave solo contenga letras en minuscula
  if (!preg_match("/^[a-z]+$/", $keyword)) {
    exit("En la clave no se permiten letras mayusculas, caracteres numericos, caracteres de espacio en blanco (tabulador, salto de línea, etc.), caracteres de puntuacion ni caracteres especiales (tilde, dieresis, arroba, etc.). Solo se permiten letras minusculas. La letra ñ no esta permitida.");
  }

  if (empty($message)) {
    exit("El mensaje no debe estar vacio.");
  }

  // Comprueba que el mensaje de entrada solo contenga letras en minuscula y espacios en blanco
  if (!preg_match("/^[a-z\s]+$/", $message)) {
    exit("No se permiten letras mayusculas, caracteres numericos, caracteres de puntuacion ni caracteres especiales (tilde, dieresis, arroba, etc.). Solo se permiten letras minusculas y espacios en blanco. La letra ñ no esta permitida.");
  }

  // Si la opcion ingresada es 1, se ejecuta el cifrado Vigenere
  if (strcmp($option, $encode_option) == 0) {
    // La funcion trim() elimina los espacios en blanco del principio y el final de un string
    encode($alphabet, $keyword, trim($message));
  }

  // Si la opcion ingresada es 2, se ejecuta el descifrado Vigenere
  if (strcmp($option, $decode_option) == 0) {
    // La funcion trim() elimina los espacios en blanco del principio y el final de un string
    decode($alphabet, $keyword, trim($message));
  }

  /**
  * Realiza el cifrado Vigenere del mensaje de entrada
  *
  * @param array $alphabet
  * @param string $keyword palabra clave
  * @param string $message mensaje de entrada
  */
  function encode($alphabet, $keyword, $message) {
    $array_message = getCharsArray($message);
    $array_keyword = getCharsArray($keyword);

    $alphabet_size = count($alphabet);
    $array_keyword_size = count($array_keyword);
    $index_char_message;
    $keyword_char_index;
    $keyword_char;
    $encrypted_message;

    // Variable utilizada para recorrer el arreglo de la palabra clave
    $keyword_position = 0;

    foreach ($array_message as $key => $current_char) {

      /* Si el caracter actualmente recorrido del mensaje no es un espacio,
      calcula el caracter de cifrado */
      if ($current_char !== " ") {
        // Obtiene el indice, en el alfabeto, de un caracter no cifrado del mensaje
        $index_char_message = getIndex($alphabet, $current_char);

        $keyword_char = $array_keyword[$keyword_position];
        $keyword_char_index = getIndex($alphabet, $keyword_char);

        /* Luego de obtener el valor de la posicion en el alfabeto de un caracter de la palabra clave,
        se incrementa en uno el valor de keyword_position para que en el siguiente ciclo se utilice el
        siguiente caracter de la palabra clave para cifrar el mensaje de entrada */
        $keyword_position = ($keyword_position + 1) % $array_keyword_size;

        /* Calcula el valor de la posicion del caracter de cifrado
        correspondiente al caracter actualmente recorrido */
        $index_char_message = ($index_char_message + $keyword_char_index) % $alphabet_size;

        // Agrega el caracter cifrado al resultado
        $encrypted_message .= $alphabet[$index_char_message];
      }

      /* Si el caracter actualmente recorrido del mensaje es un espacio,
      agrega un espacio al resultado */
      if ($current_char == " ") {
        $encrypted_message .= " ";
      }

    }

    echo $encrypted_message;
  }

  /**
  * Realiza el descifrado Vigenere del mensaje de entrada
  *
  * @param array $alphabet
  * @param integer $keyword palabra clave
  * @param string $message mensaje de entrada
  */
  function decode($alphabet, $keyword, $message) {
    $array_message = getCharsArray($message);
    $array_keyword = getCharsArray($keyword);

    $alphabet_size = count($alphabet);
    $array_keyword_size = count($array_keyword);
    $index_char_message;
    $keyword_char_index;
    $keyword_char;
    $decrypted_message;

    // Variable utilizada para recorrer el arreglo de la palabra clave
    $keyword_position = 0;

    foreach ($array_message as $key => $current_char) {

      /* Si el caracter actualmente recorrido del mensaje no es un espacio,
      calcula el caracter de descifrado */
      if ($current_char !== " ") {
        // Obtiene el indice, en el alfabeto, de un caracter cifrado del mensaje de entrada
        $index_char_message = getIndex($alphabet, $current_char);

        $keyword_char = $array_keyword[$keyword_position];
        $keyword_char_index = getIndex($alphabet, $keyword_char);

        /* Luego de obtener el valor de la posicion en el alfabeto de un caracter de la palabra clave,
        se incrementa en uno el valor de keyword_position para que en el siguiente ciclo se utilice el
        siguiente caracter de la palabra clave para descifrar el mensaje de entrada */
        $keyword_position = ($keyword_position + 1) % $array_keyword_size;

        /* Calcula el valor de la posicion del caracter de descifrado
        correspondiente al caracter actualmente recorrido */
        if ($index_char_message - $keyword_char_index < 0) {
          $index_char_message = $alphabet_size + ($index_char_message - $keyword_char_index);
        } else {
          $index_char_message = ($index_char_message - $keyword_char_index) % $alphabet_size;
        }

        // Agrega el caracter descifrado al resultado
        $decrypted_message .= $alphabet[$index_char_message];
      }

      /* Si el caracter actualmente recorrido es un espacio, agrega un espacio
      al resultado */
      if ($current_char == " ") {
        $decrypted_message .= " ";
      }

    }

    echo $decrypted_message;
  }

  /**
  * Obtiene el valor que tiene la posicion de un caracter en el alfabeto
  *
  * @param array $alphabet
  * @param char $char_message un caracter del mensaje de entrada
  * @return integer el valor que tiene la posicion de un caracter del mensaje
  * de entrada en el alfabeto
  */
  function getIndex($alphabet, $char_message) {

    while ($current_char = current($alphabet)) {

      /* Si el caracter de la posicon actual del alfabeto es igual al caracter del mensaje, retorna
      el valor que tiene la posicion del caracter dentro del alfabeto */
      if ($current_char == $char_message) {
        return key($alphabet);
      }

      next($alphabet);
    }

  }

  /**
  * Convierte una cadena de caracteres (string) en un arreglo
  *
  * @param string $given_string
  * @return array que contiene todos los caracteres de un string dado
  */
  function getCharsArray($given_string) {
    return str_split($given_string);
  }

?>
