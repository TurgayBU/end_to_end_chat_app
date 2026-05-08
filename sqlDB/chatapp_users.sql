-- MySQL dump 10.13  Distrib 8.0.41, for macos15 (arm64)
--
-- Host: 127.0.0.1    Database: chatapp
-- ------------------------------------------------------
-- Server version	8.4.4

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `users` (
  `user_id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(50) NOT NULL,
  `email` varchar(100) NOT NULL,
  `name` varchar(50) DEFAULT NULL,
  `surname` varchar(50) DEFAULT NULL,
  `public_key` text NOT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `last_login` timestamp NULL DEFAULT NULL,
  `is_active` tinyint(1) DEFAULT '1',
  PRIMARY KEY (`user_id`),
  UNIQUE KEY `username` (`username`),
  UNIQUE KEY `email` (`email`),
  KEY `idx_email` (`email`),
  KEY `idx_username` (`username`)
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `users`
--

LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
INSERT INTO `users` VALUES (4,'berat_ermis','berat_ermis@gmail.com','Berat','Ermis','-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmkmr0iV8xzcC00pdN1sH\neknZ1CAn228X2kzxvnEX5SWncvBE+tJdhWF3fyLFMgN5SOOl4XJ90YMCXYq/slvZ\nwCYg4BP6tHDEOm/LwNylYD64k/KvBDCqwmfq0ZANQ5Rc+TUruiBEtECfaWh4lJbt\nFjH6L3tpXuvIYXGI6NU5zbtmlFFts4eP4Djnd1PzievbhB0ahLnofnJe9gp2G2/8\nJtWyAvr4Jb94FKPvznHttH/TjyqYAANsn4RU4Ozjj4VpHfJRmHLes+1c5gYS/MYk\nWxiXRtPo8cvEQfp+xPaqtkjXvq3npo3eoB02Lqk9MPM5WoADUwYG4J2OB1soml/d\nHQIDAQAB\n-----END PUBLIC KEY-----','2026-03-15 13:24:53','2026-03-20 10:02:04',1),(5,'turgay_bozoglu','turgay_bozoglu@gmail.com','Turgay','Bozoglu','-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxw1eY+K8Lbburyvzx/cM\nKKeKyerp9ZUxYUv+JQmjy+23cHjopvdyA79w+KrlD/m1Ca41dPZpcga7cnji+DNg\njOF4GEvCD02LvN5TVfzpoyV9TEbWFbm1dAx3Gn+w6UP1X5/lKQa0k/EqbHp4UzHX\ng1w8FsypFXkWE25EUkeycCdgaRcLnM7AVdQBIjWJm9zFjlc0y7eplOTm5dv1LKBy\nG8RoHfA9WtsVuIiMEymsCYnp5Jv86uz5S8uU1nxM6kz559L1GC9PdoCIChHvlVyQ\n03EkuSPTCvXWEaXdmE9+HmdapMlTSc9685787F1KkPZTTe9f5JxB8epevCEdKv8f\nPwIDAQAB\n-----END PUBLIC KEY-----','2026-03-15 13:25:48','2026-03-20 08:37:38',1);
/*!40000 ALTER TABLE `users` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2026-03-22 13:23:10
