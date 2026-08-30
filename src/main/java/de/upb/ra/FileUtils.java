package de.upb.ra;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;

import java.io.File;
import java.io.IOException;
import java.util.Map;

@Slf4j
public class FileUtils {
    public static void writeToJsonFile(File file, Object content) throws IOException {
        ObjectMapper objectMapper = new ObjectMapper();

        try {
            objectMapper.writeValue(file, content);
            log.info("Object has been written to the file: {}", file);
        } catch (IOException e) {
            log.error(e.getMessage());
        }
    }
}
