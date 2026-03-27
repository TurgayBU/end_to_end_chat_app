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
-- Table structure for table `file_info`
--

DROP TABLE IF EXISTS `file_info`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `file_info` (
  `file_id` int NOT NULL AUTO_INCREMENT,
  `file_uuid` varchar(36) NOT NULL,
  `sender_id` int NOT NULL,
  `receiver_id` int NOT NULL,
  `file_name` varchar(255) NOT NULL,
  `file_size` bigint NOT NULL,
  `encrypted_aes_key` text NOT NULL,
  `status` enum('pending','completed','failed') DEFAULT 'pending',
  `total_pieces` int NOT NULL,
  `sent_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `completed_at` timestamp NULL DEFAULT NULL,
  `download_count` int DEFAULT '0',
  `last_downloaded_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`file_id`),
  UNIQUE KEY `file_uuid` (`file_uuid`),
  KEY `idx_sender` (`sender_id`),
  KEY `idx_receiver` (`receiver_id`),
  KEY `idx_status` (`status`),
  KEY `idx_uuid` (`file_uuid`),
  CONSTRAINT `file_info_ibfk_1` FOREIGN KEY (`sender_id`) REFERENCES `users` (`user_id`) ON DELETE CASCADE,
  CONSTRAINT `file_info_ibfk_2` FOREIGN KEY (`receiver_id`) REFERENCES `users` (`user_id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=18 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `file_info`
--

LOCK TABLES `file_info` WRITE;
/*!40000 ALTER TABLE `file_info` DISABLE KEYS */;
INSERT INTO `file_info` VALUES (10,'527dfb91-86b4-4d14-9d3e-d9c4ac51f7b0',4,5,'deneme.txt',4,'k1Cql5lQ8DkOc9YRaAvDmg7e2dqN+UVe8WGz03FfQRJO75Js4qRMqTu5zTiOgC8pldlUyLafZqjI7PuOH9XYaSKR8QYw5BD+hntMSAS5XerwExaP8Br1skFqM8evVkQ3Qw5aRDoCRS3yzsA43ESew/Ch33wjEcP57jWcSuUhrobGEOcaccdqkTYY2V18bq7CokhL0SP34mVrsUzLp7W/TG5esSiVjHsS8hDmHTQX9IwAntOww0oU+oLnH5vcaaJgbpSaB3x7lwncU+KRzyn7nAqa3h+FfxC8iF4Mj5UOT3NNeNrKpZeFv4AS3feY1Yb6TK+d3vm0fpXqAVUpyD1q8Q==','completed',1,'2026-03-21 10:21:55','2026-03-21 10:21:55',1,'2026-03-21 10:22:47'),(11,'7dad151c-97fd-431c-9de6-25ee022844d7',4,5,'deneme.txt',4,'jmN0qASdhE1IUrFt2HswnFqZrUX7UN6a+v/dJLL+hYjy0VG8iRcE0i24gNTp3S1VOx6gLM2DnHHYSc99qSeFuGPIg/BK01x3cJzz1I9xazsWz3qSclBiMJnzmPMK079/ZKaCM8WjvajxdstyPFOfHssQpLbqrwPcVpOd8VZFKS3235NA23B56efUCtLzVQXpaUbgdHQYcYF1PFdxHlqGtCKEhX78/okan0tEsAd6paBeQGbAfCmjxiTq+5QVJ4BEFdTRadksWionfpfbdf93A9e1a8QdgnYYptPRSvFI0us7V3reBSktEmK+1cAvcXJQRm9XQuP/ElqjQ4UZ0E1MIw==','completed',1,'2026-03-21 10:22:59','2026-03-21 10:22:59',0,NULL),(12,'cc8ce636-88d4-4351-b2db-f08d0ca678e7',5,4,'deneme.txt',93,'OiHz0TiGAc4S70gU4rYJmaiMPhIvw+IQkNRJvFCQCwsC/0cAQwshW2ra7Uh73qGG9bafiWejTRlm62szEShzYLUcn31nLZzspvZlaSFfTP7jhe8LnQHtyp2DgGWzuSPAcrQim0YYpThuZ7qHZgXYXTlTX/48kVihjIzNZEcSQjHc4MD7NGKRReKElQK7qtGCaRP3qJA79Bb0ai4lYfiVIcyy5phV2IRfungGQLoUS1FuJjDO+44JoJlNh5FRNLqhBeYdCcMB3xb3yjNvmktigvGZrFm2TsOaW+Pu047I8zQim+xBSn6EE2K0ZfNffHjDRogZ2cQ5bfxX8d2armXeCg==','completed',1,'2026-03-21 10:29:25','2026-03-21 10:29:25',12,'2026-03-21 10:34:14'),(13,'6031b983-6a07-45cd-99f3-19079719b090',5,4,'deneme.txt',93,'Pp5R5KJpFT/b6SOce6XoSXI64TWjgGV+OhRUVxkgWnPnpFe8tqdJ1JOzBeL0uNi5s1bBb2TqWbzMubxmQq4rw2p/N0z56qml52DoYTr5o+LUpmg5ShRBXUNvjJHO+cJfyj8El4c30nRBPbknweFKyJiWwTpbhZz4g6LxW0/OOKKuhoyDosJ0E1hbEmeXHYYEJHj8yjXnSn2ssTvAArWnk73jFWSU0f+oTiwUcZwZpzroWBDAyEFh7JmJ3oOqYQzephi0J8TbmyQR9y9PUZis+RCAnvfV1hZFp8rs/ojpIbBlz3lSXmADDKHQDWdd3NMQnHatFIFbEdK4J7AurOuSjQ==','completed',1,'2026-03-21 10:35:12','2026-03-21 10:35:12',10,'2026-03-21 10:37:39'),(14,'c1ad9952-8e25-4dae-8ca0-afb401b818f5',4,5,'deneme.txt',93,'S6WWoQZPkKI5A+PBRde+PL+zUvyRe0/wmXSmff93lpc/EMhjWWgVqgCDlSMpmB3foP71tVHStL/Eu6cXiYSk/pqTDGfZtxDfWSyILZi9GY+7Fc79XiCAHwL3AMw9uAEfRSngkFh+KrzEpwE8h2Z8ttoSdP9f8czLJD7/RO3wvVjKv5DVsV/wzwI+slDKpaq0Tb+HNM3MzkIgyXSH0GSr6gwoV/wFO5+MFBbTIckobu3gf5YRWW5tLfgFc9yvSFgUPcGhNg+9siods4VmLOxsMLpE8KTw+vtwmAmqiQotT01GsD2HZIuRVsCfxG0XSkW1soPzsF13P5E/3JwHdpT9mA==','completed',1,'2026-03-21 10:47:12','2026-03-21 10:47:12',1,'2026-03-21 10:47:16'),(15,'24538523-f8e0-4548-a516-34891314c767',5,4,'CV.pdf',278382,'F/FzQu7xAyCPAmnTF5hgZ7Q6bwwZGQfPxeUabzmgyfZQ0MbYNcFihgFgdTJxH+OTQFoKwjmW0PFGVAaNC85bM+JEpj52deyrVAyuexwe7a5OG2UGvzJQUo9ubaOWR/hYAfAJVwVJ+O2vtOiJWJpov1w5T39XWarXFbtHkFU8ThpkW13C4GbLypfxayyRPqL7aWKylLPA7O0OOgmvuYTTCKscy03HR0ClXbFIN3Oyymgsho1xaCFr95ubh7YLUaL5oslevzbnPV/g/SnDlLzMRM43zdg1BnahPjN3lgLUaG3/MZQJRikVA2263x2JSTwcU2DX18cp1RYpCHYT3db8LQ==','completed',1,'2026-03-21 10:47:31','2026-03-21 10:47:32',1,'2026-03-21 10:47:35'),(16,'812c8823-f388-4328-a2ff-890f4461172f',4,5,'C.Netwok_2nd_Sheet.pdf',763862,'ZqwwOaZR+fdZCqfbgXk/A1JAz53esO6ccpJmcHbSUmCroMqs2Xx5qMa7ms/CW489UPZm05fYQWFtGuExX3JPSnFCnw8Jqx3qERW6GESjIh7e3sWWPJe4ZK6wviBbP9Tc+6mOtTTGdzwIZPIB0/3GINvm+uLC6/FBvsJ52CsN3KO4bMgqlTH9e3N539pv9+2jps+U8oMEiQWXHAmKhrP8Kgjf2ZwR7Sx7O+s7jXfGCSC9O17vA+zxedX0MqYIQkcgnKees0HnUEwS/3pfZdwoA79nh1STC/vupUBiJZLWDjIKKVwxSTVrbFJdOKPKXthuMAoJXcqNEohleV/AFvt2XQ==','completed',1,'2026-03-21 10:48:02','2026-03-21 10:48:02',1,'2026-03-21 10:48:08'),(17,'e484fc47-8626-4e44-b67c-b27967490038',5,4,'1 Intro.ppt',820224,'j3MTCdN1w5ZaTuhPwDxWH/lksRguA3ccVBFXIrZ+8PRK4kKWmjz/e1vBauEBujy1bD8jqS1aPOE5fymendTcnzbjbw9cenAwnT8qLv1ccZ9FJnNyOFZki4CRhk62jDeZBYxYppSnYHEhrLFa6WwSbmmDCLWnXkCNDQzRJaROnPTqkdFZ3Qiz1pZAr89uYSHwG1eK6Ez7yhX8864HBXBR9DTVhwqv+8xy+NrgH37SPfIS73mwBbjG+sj3kOe2q+QVdUNO3b5r9wv+o5Ix9rT36thtAjml/vxNHokmZMpkizlF/MxWUZrV5aq5/1J7u91uMun3jSSKf5ZBL/RfVWhGGg==','completed',1,'2026-03-21 10:48:30','2026-03-21 10:48:30',1,'2026-03-21 10:48:34');
/*!40000 ALTER TABLE `file_info` ENABLE KEYS */;
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
