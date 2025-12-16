// ESP32 PROBE REPLAY & SPAM - By Teno
// Thonhy, no te enojes como programo
// ===== Configuración ===== //
const uint8_t canales[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}; // TODOS los canales WiFi
const bool agregarEspacios = true; // Hace que todos los SSIDs tengan 32 caracteres para mejor performance (heredado del esp32 beacon spam)
const unsigned long intervaloReboot = 600000; // 10 minutos en milisegundos (10 * 60 * 1000)
const int maxRedesDetectadas = 50; // Máximo número de SSIDs a detectar
const int duplicadosPorRed = 2; // Número de SSID duplicados por cada red detectada
const unsigned long tiempoEscuchaProbes = 60000; // 60 segundos (1 minuto) escuchando probe requests
const unsigned long intervaloParpadeoEscucha = 150; // Parpadeo rápido durante escucha para diferenciar

// Configuración del LED onboard (ajustar según la placa ESP32)
#define LED_ONBOARD 2 // GPIO2 para la mayoría de placas ESP32

// Estructura para almacenar SSIDs de probe requests
typedef struct {
  char ssid[33]; // SSID + null terminator
  bool esWPA2;   // Tipo de cifrado (asumimos WPA2 por defecto)
  int cantidadDetectada; // Veces que se detectó este SSID
} RedWiFi;

// Array para almacenar redes detectadas
RedWiFi redesDetectadas[maxRedesDetectadas];
int totalRedesDetectadas = 0;
bool escuchaCompletada = false;
bool emisionActiva = false;

#include "WiFi.h"

extern "C" {
#include "esp_wifi.h"
#include "esp_wifi_types.h"
  esp_err_t esp_wifi_set_channel(uint8_t primary, wifi_second_chan_t second);
  esp_err_t esp_wifi_80211_tx(wifi_interface_t ifx, const void *buffer, int len, bool en_sys_seq);
}

// Variables de ejecución
char SSIDvacio[32]; // Buffer para SSID vacío (32 espacios)
uint8_t indiceCanal = 0; // Índice para recorrer los canales
uint8_t direccionMAC[6]; // Dirección MAC del emisor
uint8_t canalWifi = 1; // Canal WiFi actual
uint32_t tiempoActual = 0; // Timestamp actual
uint32_t tamañoPaquete = 0; // Tamaño del paquete beacon
uint32_t contadorPaquetes = 0; // Contador de paquetes enviados
uint32_t tiempoAtaque = 0; // Último tiempo de envío masivo
uint32_t tiempoVelocidad = 0; // Último tiempo de cálculo de velocidad
uint32_t tiempoInicio = 0; // Tiempo de inicio del programa
uint32_t ultimoReboot = 0; // Último tiempo de reboot sanitario
uint32_t inicioEscucha = 0; // Tiempo de inicio de escucha
uint32_t ultimoParpadeo = 0; // Último tiempo de parpadeo del LED
bool estadoLED = false; // Estado actual del LED

// Estructura del paquete beacon WiFi
uint8_t paqueteBeacon[109] = {
  /*  0 - 3  */ 0x80, 0x00, 0x00, 0x00, // Tipo/Subtipo: trama de gestión beacon
  /*  4 - 9  */ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destino: broadcast (difusión)
  /* 10 - 15 */ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // Dirección MAC fuente
  /* 16 - 21 */ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // Dirección MAC fuente (repetida)

  // Parámetros fijos
  /* 22 - 23 */ 0x00, 0x00, // Número de fragmento y secuencia (lo maneja el SDK)
  /* 24 - 31 */ 0x83, 0x51, 0xf7, 0x8f, 0x0f, 0x00, 0x00, 0x00, // Timestamp
  /* 32 - 33 */ 0xe8, 0x03, // Intervalo: 0xe8, 0x03 => cada 1 segundo
  /* 34 - 35 */ 0x31, 0x00, // Información de capacidades

  // Parámetros etiquetados

  // Parámetros del SSID
  /* 36 - 37 */ 0x00, 0x20, // Etiqueta: Longitud del SSID, Longitud: 32
  /* 38 - 69 */ 0x20, 0x20, 0x20, 0x20,
  0x20, 0x20, 0x20, 0x20,
  0x20, 0x20, 0x20, 0x20,
  0x20, 0x20, 0x20, 0x20,
  0x20, 0x20, 0x20, 0x20,
  0x20, 0x20, 0x20, 0x20,
  0x20, 0x20, 0x20, 0x20,
  0x20, 0x20, 0x20, 0x20, // SSID (inicialmente espacios)

  // Tasas soportadas
  /* 70 - 71 */ 0x01, 0x08, // Etiqueta: Tasas soportadas, Longitud: 8
  /* 72 */ 0x82, // 1(B)
  /* 73 */ 0x84, // 2(B)
  /* 74 */ 0x8b, // 5.5(B)
  /* 75 */ 0x96, // 11(B)
  /* 76 */ 0x24, // 18
  /* 77 */ 0x30, // 24
  /* 78 */ 0x48, // 36
  /* 79 */ 0x6c, // 54

  // Canal actual
  /* 80 - 81 */ 0x03, 0x01, // Conjunto de canales, longitud
  /* 82 */      0x01,       // Canal actual

  // Información RSN (Seguridad)
  /*  83 -  84 */ 0x30, 0x18,
  /*  85 -  86 */ 0x01, 0x00,
  /*  87 -  90 */ 0x00, 0x0f, 0xac, 0x02,
  /*  91 -  92 */ 0x02, 0x00,
  /*  93 - 100 */ 0x00, 0x0f, 0xac, 0x04, 0x00, 0x0f, 0xac, 0x04,
  /* 101 - 102 */ 0x01, 0x00,
  /* 103 - 106 */ 0x00, 0x0f, 0xac, 0x02,
  /* 107 - 108 */ 0x00, 0x00
};

// Función para agregar SSID detectado desde probe requests
void agregarSSIDDetectado(const char* ssid) {
  // Verificar si el SSID ya existe en el array
  for (int i = 0; i < totalRedesDetectadas; i++) {
    if (strcmp(redesDetectadas[i].ssid, ssid) == 0) {
      redesDetectadas[i].cantidadDetectada++;
      return;
    }
  }
  
  // Si no existe, agregarlo
  if (totalRedesDetectadas < maxRedesDetectadas) {
    strncpy(redesDetectadas[totalRedesDetectadas].ssid, ssid, 32);
    redesDetectadas[totalRedesDetectadas].ssid[32] = '\0';
    redesDetectadas[totalRedesDetectadas].esWPA2 = true; // Asumimos WPA2 por defecto
    redesDetectadas[totalRedesDetectadas].cantidadDetectada = 1;
    totalRedesDetectadas++;
    
    Serial.print("🔍 SSID detectado: ");
    Serial.println(ssid);
  }
}

// Estructura para el encabezado MAC
typedef struct {
  uint16_t frame_ctrl;
  uint16_t duration;
  uint8_t da[6];  // Dirección destino
  uint8_t sa[6];  // Dirección fuente  
  uint8_t bssid[6];
  uint16_t seq_ctrl;
} wifi_mac_hdr_t;

// Callback para modo promiscuo - captura probe requests
void wifi_sniffer_packet_handler(void* buff, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT) return;

  wifi_promiscuous_pkt_t* ppkt = (wifi_promiscuous_pkt_t*)buff;
  wifi_mac_hdr_t* hdr = (wifi_mac_hdr_t*)ppkt->payload;
  
  // Verificar si es un probe request (tipo 0x00, subtipo 0x04)
  uint8_t frame_type = (hdr->frame_ctrl & 0x000F) >> 2;
  uint8_t frame_subtype = (hdr->frame_ctrl & 0x00F0) >> 4;
  
  if (frame_type == 0x00 && frame_subtype == 0x04) { // Probe request
    // El SSID está en el payload después del encabezado MAC
    uint8_t* frame_body = ppkt->payload + sizeof(wifi_mac_hdr_t);
    int frame_length = ppkt->rx_ctrl.sig_len - sizeof(wifi_mac_hdr_t);
    
    // Buscar el elemento SSID en el frame (tag 0x00)
    int offset = 0;
    while (offset + 1 < frame_length) {
      if (frame_body[offset] == 0x00) { // Tag SSID
        uint8_t ssid_length = frame_body[offset + 1];
        
        // Validar longitud del SSID
        if (ssid_length > 0 && ssid_length <= 32 && (offset + 2 + ssid_length) <= frame_length) {
          char ssid[33];
          memcpy(ssid, &frame_body[offset + 2], ssid_length);
          ssid[ssid_length] = '\0';
          
          // Agregar SSID a la lista
          agregarSSIDDetectado(ssid);
        }
        break;
      }
      offset++;
    }
  }
}

// Función para iniciar escucha de probe requests
void iniciarEscuchaProbes() {
  Serial.println();
  Serial.println("🎯 INICIANDO ESCUCHA DE PROBE REQUESTS");
  Serial.println("======================================");
  Serial.println();
  Serial.print("⏰ Tiempo de escucha: ");
  Serial.print(tiempoEscuchaProbes / 1000);
  Serial.println(" segundos");
  Serial.print("📶 Canales a escanear: ");
  Serial.println(sizeof(canales));
  Serial.println("🔍 Cambiando de canal cada 2 segundos...");
  
  // Configurar WiFi en modo estación y habilitar modo promiscuo
  WiFi.mode(WIFI_STA);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);
  
  inicioEscucha = millis();
  escuchaCompletada = false;
  emisionActiva = false;
  ultimoParpadeo = millis();
}

// Función para finalizar escucha e iniciar emisión
void finalizarEscuchaEIniciarEmision() {
  Serial.println();
  Serial.println("✅ ESCUCHA COMPLETADA");
  Serial.println("====================");
  Serial.print("📊 Total de SSIDs únicos detectados: ");
  Serial.println(totalRedesDetectadas);
  
  // Mostrar resumen de SSIDs detectados
  if (totalRedesDetectadas > 0) {
    Serial.println();
    Serial.println("📋 SSIDs DETECTADOS:");
    Serial.println("-------------------");
    for (int i = 0; i < totalRedesDetectadas; i++) {
      Serial.print("   ");
      Serial.print(i + 1);
      Serial.print(". ");
      Serial.print(redesDetectadas[i].ssid);
      Serial.print(" (detectado ");
      Serial.print(redesDetectadas[i].cantidadDetectada);
      Serial.println(" veces)");
    }
  } else {
    Serial.println();
    Serial.println("❌ No se detectaron probe requests");
    Serial.println("💡 Posibles causas:");
    Serial.println("   - No hay dispositivos WiFi activos cerca");
    Serial.println("   - Los dispositivos no están buscando redes");
    Serial.println("   - Los SSIDs están ocultos");
  }
  
  // Desactivar modo promiscuo
  esp_wifi_set_promiscuous(false);
  
  // Cambiar a modo de emisión
  WiFi.mode(WIFI_MODE_STA);
  emisionActiva = true;
  
  // Apagar LED al finalizar escucha
  digitalWrite(LED_ONBOARD, LOW);
  
  Serial.println();
  Serial.println("🎯 INICIANDO EMISIÓN DE SSIDs DETECTADOS");
  Serial.println("========================================");
  Serial.print("🔢 Cada SSID será emitido ");
  Serial.print(duplicadosPorRed);
  Serial.println(" veces");
  Serial.print("📡 Total de emisiones por ciclo: ");
  Serial.println(totalRedesDetectadas * duplicadosPorRed);
}

// Función para cambiar al siguiente canal
void cambiarCanal() {
  if (sizeof(canales) > 1) {
    uint8_t canal = canales[indiceCanal];
    indiceCanal++;
    if (indiceCanal >= sizeof(canales)) indiceCanal = 0;

    if (canal != canalWifi && canal >= 1 && canal <= 14) {
      canalWifi = canal;
      esp_wifi_set_channel(canalWifi, WIFI_SECOND_CHAN_NONE);
    }
  }
}

// Función para generar dirección MAC aleatoria
void generarMACaleatoria() {
  for (int i = 0; i < 6; i++)
    direccionMAC[i] = random(256);
}

// Función para controlar el LED onboard
void controlarLED(bool encender) {
  digitalWrite(LED_ONBOARD, encender ? HIGH : LOW);
  estadoLED = encender;
}

// Función para hacer parpadear el LED rápidamente durante escucha
void parpadearLEDRapido() {
  if (tiempoActual - ultimoParpadeo >= intervaloParpadeoEscucha) {
    controlarLED(!estadoLED);
    ultimoParpadeo = tiempoActual;
  }
}

// Función para el reboot sanitario automático
void ejecutarRebootSanitario() {
  Serial.println();
  Serial.println("╔══════════════════════════════════════╗");
  Serial.println("║    INICIANDO REBOOT SANITARIO        ║");
  Serial.println("║                                      ║");
  Serial.println("║  Motivo: Mantenimiento preventivo    ║");
  Serial.println("║  Tiempo de actividad: 10 minutos     ║");
  Serial.println("║                                      ║");
  Serial.println("║  Reiniciando en 3 segundos...        ║");
  Serial.println("╚══════════════════════════════════════╝");
  
  // Contador regresivo para el reboot
  for(int i = 3; i > 0; i--) {
    Serial.print("Reinicio en ");
    Serial.print(i);
    Serial.println(" segundos...");
    delay(1000);
  }
  
  Serial.println("✅ Ejecutando reboot sanitario...");
  delay(500);
  
  // Reiniciar el ESP32
  ESP.restart();
}

void setup() {
  // Configurar el LED onboard
  pinMode(LED_ONBOARD, OUTPUT);
  controlarLED(false); // Apagar LED al inicio
  
  // Registrar el tiempo de inicio
  tiempoInicio = millis();
  ultimoReboot = tiempoInicio;
  
  // Inicializar el SSID vacío con espacios
  for (int i = 0; i < 32; i++)
    SSIDvacio[i] = ' ';
  
  // Inicializar el generador de números aleatorios
  randomSeed(1);

  // Configurar el puerto serie para monitoreo
  Serial.begin(115200);
  
  // Mensaje de inicio
  Serial.println("╔═════════════════════════════════════╗");
  Serial.println("║    ESP32 PROBE REPLAY & SPAM        ║");
  Serial.println("║     BY Teno                         ║");
  Serial.println("║                                     ║");
  Serial.println("║  Características:                   ║");
  Serial.println("║  • Tiempo de escucha configurable   ║");
  Serial.println("║  • TODOS los canales WiFi (1-14)    ║");
  Serial.println("║  • Parpadeo rápido durante escucha  ║");
  Serial.println("║  • Emite SSIDs que buscan clientes  ║");
  Serial.println("║  • Multiplicación de cada SSID      ║");
  Serial.println("║  • Reboot sanitario cada 10 min     ║");
  Serial.println("╚═════════════════════════════════════╝");
  
  // Iniciar escucha de probe requests
  iniciarEscuchaProbes();
  
  // Generar dirección MAC aleatoria inicial
  generarMACaleatoria();
}

void loop() {
  // Obtener el tiempo actual para control de timing
  tiempoActual = millis();

  // Verificar si es necesario ejecutar el reboot sanitario
  if (tiempoActual - ultimoReboot >= intervaloReboot) {
    ejecutarRebootSanitario();
  }

  // Fase 1: Escucha de probe requests
  if (!escuchaCompletada) {
    // Parpadeo RÁPIDO del LED durante la escucha
    parpadearLEDRapido();
    
    // Cambiar de canal periódicamente durante la escucha
    if (tiempoActual - tiempoAtaque > 2000) { // Cambiar canal cada 2 segundos
      tiempoAtaque = tiempoActual;
      cambiarCanal();
      
      // Mostrar progreso de escucha
      unsigned long tiempoTranscurrido = tiempoActual - inicioEscucha;
      unsigned long segundosRestantes = (tiempoEscuchaProbes - tiempoTranscurrido) / 1000;
      unsigned long segundosTranscurridos = tiempoTranscurrido / 1000;
      
      Serial.print("🔍 Canal ");
      if (canalWifi < 10) Serial.print(" "); // Alineación
      Serial.print(canalWifi);
      Serial.print(" | Tiempo: ");
      if (segundosTranscurridos < 10) Serial.print("0");
      Serial.print(segundosTranscurridos);
      Serial.print("/");
      Serial.print(tiempoEscuchaProbes / 1000);
      Serial.print("s | SSIDs: ");
      Serial.println(totalRedesDetectadas);
    }
    
    // Verificar si el tiempo de escucha ha terminado
    if (tiempoActual - inicioEscucha >= tiempoEscuchaProbes) {
      escuchaCompletada = true;
      finalizarEscuchaEIniciarEmision();
    }
    
    return; // No hacer nada más durante la fase de escucha
  }

  // Fase 2: Emisión de SSIDs detectados
  if (emisionActiva && totalRedesDetectadas > 0) {
    // Enviar paquetes beacon cada 100 milisegundos
    if (tiempoActual - tiempoAtaque > 100) {
      tiempoAtaque = tiempoActual;

      // Parpadeo normal del LED durante emisión
      if (tiempoActual - ultimoParpadeo >= 500) { // 500ms para parpadeo normal
        controlarLED(!estadoLED);
        ultimoParpadeo = tiempoActual;
      }

      // Cambiar al siguiente canal para evitar saturación
      cambiarCanal();

      // Procesar y enviar todos los SSIDs detectados, DUPLICANDO cada uno
      for (int i = 0; i < totalRedesDetectadas; i++) {
        // Para cada red, emitir múltiples duplicados
        for (int duplicado = 0; duplicado < duplicadosPorRed; duplicado++) {
          
          // Obtener información de la red actual
          char* ssid = redesDetectadas[i].ssid;
          bool esWPA2 = redesDetectadas[i].esWPA2;
          uint8_t longitudSSID = strlen(ssid);

          // Configurar dirección MAC única para esta red y duplicado
          direccionMAC[5] = (i * duplicadosPorRed) + duplicado + 1;

          // Copiar dirección MAC al paquete beacon
          memcpy(&paqueteBeacon[10], direccionMAC, 6);
          memcpy(&paqueteBeacon[16], direccionMAC, 6);

          // Limpiar el campo SSID del paquete
          memcpy(&paqueteBeacon[38], SSIDvacio, 32);

          // Copiar el SSID actual al paquete beacon
          memcpy(&paqueteBeacon[38], ssid, longitudSSID);

          // Configurar el tipo de cifrado en el paquete (siempre WPA2)
          paqueteBeacon[34] = 0x31; // WPA2 habilitado
          tamañoPaquete = sizeof(paqueteBeacon);

          // Configurar el canal actual en el paquete
          paqueteBeacon[82] = canalWifi;

          // Enviar el paquete beacon
          if (agregarEspacios) {
            // Enviar 3 veces el mismo paquete para mayor confiabilidad
            for (int repeticion = 0; repeticion < 3; repeticion++) {
              contadorPaquetes += esp_wifi_80211_tx(WIFI_IF_STA, paqueteBeacon, tamañoPaquete, false) == ESP_OK;
              delay(1);
            }
          } else {
            // Método alternativo para SSIDs de longitud variable
            uint16_t tamañoPaqueteTemporal = (109 - 32) + longitudSSID;
            uint8_t* paqueteTemporal = new uint8_t[tamañoPaqueteTemporal];
            
            memcpy(&paqueteTemporal[0], &paqueteBeacon[0], 37 + longitudSSID);
            paqueteTemporal[37] = longitudSSID;
            memcpy(&paqueteTemporal[38 + longitudSSID], &paqueteBeacon[70], 39);

            // Enviar el paquete temporal
            for (int repeticion = 0; repeticion < 3; repeticion++) {
              contadorPaquetes += esp_wifi_80211_tx(WIFI_IF_STA, paqueteTemporal, tamañoPaqueteTemporal, false) == ESP_OK;
              delay(1);
            }

            // Liberar la memoria del paquete temporal
            delete[] paqueteTemporal;
          }
        }
      }
    }

    // Mostrar estadísticas de velocidad cada segundo
    if (tiempoActual - tiempoVelocidad > 1000) {
      tiempoVelocidad = tiempoActual;
      
      // Calcular tiempo restante para el próximo reboot
      unsigned long tiempoRestante = intervaloReboot - (tiempoActual - ultimoReboot);
      unsigned long minutosRestantes = tiempoRestante / 60000;
      unsigned long segundosRestantes = (tiempoRestante % 60000) / 1000;
      
      Serial.print("📊 Paquetes/seg: ");
      Serial.print(contadorPaquetes);
      Serial.print(" | 📶 SSIDs detectados: ");
      Serial.print(totalRedesDetectadas);
      Serial.print(" | 🎯 Emisiones: ");
      Serial.print(totalRedesDetectadas * duplicadosPorRed);
      Serial.print(" | ⏳ Reboot en: ");
      Serial.print(minutosRestantes);
      Serial.print("m ");
      Serial.print(segundosRestantes);
      Serial.println("s");
      
      contadorPaquetes = 0;
    }
  } else if (emisionActiva && totalRedesDetectadas == 0) {
    // Si no se detectaron SSIDs pero la emisión está activa
    if (tiempoActual - tiempoVelocidad > 5000) {
      tiempoVelocidad = tiempoActual;
      Serial.println("💤 Esperando probe requests... (reinicia para nuevo escaneo)");
    }
  }
}
