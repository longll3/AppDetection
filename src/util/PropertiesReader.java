package util;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Properties;

public class PropertiesReader {

    private static PropertiesReader reader = new PropertiesReader();
    private Properties properties;

    private PropertiesReader() {
        properties = new Properties();
        InputStream inStream = ClassLoader.getSystemResourceAsStream("config.properties");//获取配置文件输入流
        try {
            properties.load(new InputStreamReader((inStream), "UTF-8"));//载入输入流
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static PropertiesReader getPropertiesReader() {
        return reader;
    }

    public String getProperty(String key) {
        return properties.getProperty(key);
    }





}
