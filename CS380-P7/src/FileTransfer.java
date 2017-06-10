import java.net.*;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.io.*;
import java.util.*;
import java.util.zip.CRC32;
import javax.crypto.*;
import javax.crypto.spec.*;

/**
 * @author cesar
 *
 */
public final class FileTransfer{
	public static void main(String[] args) throws Exception{
		
		Cipher rsaCipher = Cipher.getInstance("RSA");
		Cipher aesCipher = Cipher.getInstance("AES");
		CRC32 crc = new CRC32();

		switch(args[0]){

			case "makekeys":
				try{
					KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
					gen.initialize(2048);
					KeyPair keyPair = gen.genKeyPair();
					PrivateKey privateKey = keyPair.getPrivate();
					PublicKey publicKey = keyPair.getPublic();
					try(ObjectOutputStream toPubFile = new ObjectOutputStream(
						new FileOutputStream(new File("public.bin")))){
						toPubFile.writeObject(publicKey);
					}
					try(ObjectOutputStream toPrvFile = new ObjectOutputStream(
						new FileOutputStream(new File("private.bin")))){
						toPrvFile.writeObject(privateKey);
					}
					catch(Exception e){
						e.printStackTrace(System.err);
					}
				}
				catch(Exception e){
					e.printStackTrace();
				}
				break;

			
			case "server":
				String prvKeyFile = args[1];
				int sPort = Integer.parseInt(args[2]);
				
				long fSize = 0;
				int expected = 0;
				Message message;
				int temp = 1;
				int numOfChunks = -1;

				try(ServerSocket serverSocket = new ServerSocket(sPort)){
					while(true){

						Socket client = serverSocket.accept();

						ObjectInputStream ois = new ObjectInputStream(client.getInputStream());
						ObjectOutputStream oos = new ObjectOutputStream(client.getOutputStream());

					label:	while(temp == 1){

							message = (Message)ois.readObject();

							Enum type = message.getType();

							if(type.equals(MessageType.DISCONNECT)){
								client.close();
								temp = 0;
							}

							else if(type.equals(MessageType.START)){
								StartMessage sm = (StartMessage)message;
								fSize = sm.getSize();
								byte[] encryptedKey = sm.getEncryptedKey();

				
								@SuppressWarnings("resource")
								ObjectInputStream prvFile = new ObjectInputStream(new FileInputStream(prvKeyFile));
								PrivateKey pKey = (PrivateKey)prvFile.readObject();
								
								try{
									rsaCipher.init(Cipher.DECRYPT_MODE,pKey);
									byte[] decSecretKey = rsaCipher.doFinal(encryptedKey);
									
									oos.writeObject(new AckMessage(0));
									SecretKey skey = new SecretKeySpec(decSecretKey,0 ,decSecretKey.length, "AES");
									Key key = (Key)skey;


									ObjectOutputStream keyFile = new ObjectOutputStream(new FileOutputStream(new File("key.bin")));
									keyFile.writeObject(key);
									
								}

								catch(Exception e){
									e.printStackTrace();
									AckMessage ack = new AckMessage(-1);
									oos.writeObject(ack);
								}
							}//close start

							else if(type.equals(MessageType.STOP)){
								AckMessage stop = new AckMessage(-1);
								oos.writeObject(stop);
							}//close stop

							else if(type.equals(MessageType.CHUNK)){
								Chunk ch = (Chunk)message;
								int chunkseq = ch.getSeq();

								if(chunkseq == expected){
									byte[] chData = ch.getData();

									@SuppressWarnings("resource")
									ObjectInputStream getKey = new ObjectInputStream(new FileInputStream("key.bin"));
									Key key = (Key)getKey.readObject();


						            aesCipher.init(Cipher.DECRYPT_MODE,key);
									byte[] decrChunk = rsaCipher.doFinal(chData);

									crc.update(decrChunk);
					            	long checksum = crc.getValue();


					            	if((int)checksum == ch.getCrc()){
					            		
					            		//System.out.println("checksum=crc");
					            		expected++;

					            		OutputStream os;
					            		if(expected == 1){
					            			os = new FileOutputStream("test2.txt");
					            			os.write(decrChunk);
					            		}

					            		else{
					            			os = new FileOutputStream("test2.txt",true);
					            			os.write(decrChunk);
					            		}

					            		
					            		if(expected != numOfChunks){
					            			int chSize = decrChunk.length;
					            			numOfChunks = (int)Math.ceil(fSize/(double)chSize);

					            		}
					            		System.out.println("Chunk received["+ expected +"/"+ numOfChunks +"].");

					            		AckMessage sequence;
					            		if(expected < numOfChunks){
					            			//System.out.println("expected<numOfChunks");
					            			sequence = new AckMessage(expected);
					            			oos.writeObject(sequence);
					            		}
										
										else{
											System.out.println("Transfer complete.");
											System.out.println("Output path: " + "test2.txt" + "\n");
											os.close();
											
											sequence = new AckMessage(expected);
					            			oos.writeObject(sequence);
					            			numOfChunks = -1;
					            			expected = 0;
										}					            		
					            	}
								}

								else{
									AckMessage sequence = new AckMessage(expected);
									oos.writeObject(sequence);
								}
							}//close CHunk
							else{ System.out.println("Error."); }
						}
					}
				}
				catch(Exception e){
					e.printStackTrace();
				}
				break;

			case "client":
				String keyFile = args[1];
				String host = args[2];
				int port = Integer.parseInt(args[3]);
				boolean looped = true;

				
				Socket client = new Socket(host,port);
				System.out.println("Connected to server: " + host + "/" + client.getInetAddress().getHostAddress());

				KeyGenerator keyGen = KeyGenerator.getInstance("AES");
				keyGen.init(128);
				SecretKey secret = keyGen.generateKey();

				byte[] session = secret.getEncoded();

				ObjectInputStream publicFile = new ObjectInputStream(new FileInputStream(keyFile));
				PublicKey pubKey = (PublicKey)publicFile.readObject();
				
				rsaCipher.init(Cipher.ENCRYPT_MODE,pubKey);
				byte[] encryptedKey = rsaCipher.doFinal(session);
							
				Scanner kb = new Scanner(System.in);
				ObjectOutputStream oos = new ObjectOutputStream(client.getOutputStream());
				ObjectInputStream ois = new ObjectInputStream(client.getInputStream());

				while(looped){
					boolean found = false;
					InputStream is = null;

					String filename = null;
					while(!found){
						System.out.print("Enter path: ");
						filename = kb.nextLine();
						try{
							is = new FileInputStream(filename);
							found = true;
						}
						
						catch(FileNotFoundException f){
							System.out.println("Please enter valid filename.");
						}
					}


					boolean valid = false;
					int chSize = 1024;
					while(!valid){
						System.out.print("Enter chunk size[1024]: ");
						String size = kb.nextLine();
						try{
							chSize = Integer.parseInt(size);
							valid = true;
						}

						catch(Exception e){
							System.out.println("Please enter valid integer.");
						}
					}
					
					StartMessage sm = new StartMessage(filename, encryptedKey, chSize);
					
					oos.writeObject(sm);

					
					Message response = (Message)ois.readObject();
					AckMessage ack = (AckMessage)response;
					int sequence = ack.getSeq();

					if(sequence == 0){
						
						long fsize = sm.getSize();
						int numChunks = (int)Math.ceil(fsize / (double)chSize);


						System.out.println("Sending: " + filename + ". File size: " + fsize + ".");
						System.out.println("Sending " + numChunks + " chunks.");

						byte[] file = new byte[(int)fsize];
						
						is.read(file);
						int count = 0;
						int chunkNum = 1;


						byte[] chunkData = new byte[chSize];

						for(int i = 0; i < file.length; i++){
							chunkData[i%(chSize)] = file[i];

							if((i > 0 && i%(chSize) == (chSize-1)) || (i == file.length-1)){
								byte[] copyData;
								if(chunkNum == numChunks){
									copyData = Arrays.copyOf(chunkData,i % chSize+1);
								}

								else{
									
									copyData = Arrays.copyOf(chunkData,chunkData.length);
								}


					            crc.update(copyData);
					            long checksum = crc.getValue();


					            aesCipher.init(Cipher.ENCRYPT_MODE,secret);
								byte[] encryptedChunk = rsaCipher.doFinal(copyData);


								Chunk chunk = new Chunk(count,encryptedChunk,(int)checksum);
								oos.writeObject(chunk);
								System.out.println("Chunks completed["+ chunkNum +"/"+ numChunks +" ].");
								is.close();

				            	response = (Message) ois.readObject();
								ack = (AckMessage)response;
								sequence = ack.getSeq();

								if(sequence == (count+1)){
									count++;
									chunkNum++;
								}
								else{
									i -= chSize;
								}
							}
						}
					}

					System.out.println("\nChoose an Option:\n1) New file transfer\n2) Disconnect");
					String choice = kb.nextLine();

					if(Integer.parseInt(choice) == 1){
						System.out.println();
					}

					else{
						looped = false;
					 	DisconnectMessage dm = new DisconnectMessage();
					 	oos.writeObject(dm);
					}
				}
						
				break;

			default:
				break;

		}
	}
}