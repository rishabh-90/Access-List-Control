/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package accesscontrollists;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.*;

public class AccessControlLists {
    /**
     * @param args the command line arguments
     */
    static String ACLLine, PacketLine;
    static List<String[]> ACLList = new ArrayList<String[]>();
    static String PermissionType, srcIPAddress, destIPAddress, srcMask, destMask;
    public static void main(String[] args) {
        // TODO code application logic here
        File StanACL = new File("C:\\Users\\rishabh\\Documents\\NetBeansProjects\\AccessControlLists\\src\\accesscontrollists\\Standard.txt");
        System.out.println("Chosen Standard ACL File is: "+ StanACL.getAbsolutePath());
        File Packets = new File("C:\\Users\\rishabh\\Documents\\NetBeansProjects\\AccessControlLists\\src\\accesscontrollists\\IP.txt");
        System.out.println("Chosen Packet File is: "+ Packets.getAbsolutePath());
        File ExACL = new File("C:\\Users\\rishabh\\Documents\\NetBeansProjects\\AccessControlLists\\src\\accesscontrollists\\ExtendedL.txt");
        System.out.println("Chosen Extended ACL File is: "+ ExACL.getAbsolutePath());
        
        System.out.println("******* PERFORMING STANDARD ACL*********");
        try (BufferedReader br = new BufferedReader(new FileReader(StanACL)))
        {
            while((ACLLine = br.readLine()) != null)
            {
                if(ACLLine.contains("access-list")){
                    if(ACLLine.contains("any")){
                        ACLLine = ACLLine.replace("any", "0.0.0.0 255.255.255.255");
                    }
                    String[] ACLItems = ACLLine.split(" ");
                    PermissionType = ACLItems[2];
                    srcIPAddress = ACLItems[3];
                    srcMask = ACLItems[4];
                    String[] IPItems = srcIPAddress.split("\\.");
                    String[] MaskItems = srcMask.split("\\.");
                    String MaskedString = "";
                    for(int count = 0; count < IPItems.length; count++){
                        int MaskValue = Integer.parseInt(IPItems[count]) | Integer.parseInt(MaskItems[count]);
                        if(count != IPItems.length - 1)
                            MaskedString = MaskedString + MaskValue + ".";
                        else
                            MaskedString = MaskedString + MaskValue;
                    }
                    ACLList.add(new String[]{MaskedString, PermissionType});
                }
            }
            try(BufferedReader br1 = new BufferedReader(new FileReader(Packets))){
                while((PacketLine = br1.readLine()) != null){
                    String[] PacketItems = PacketLine.split(" ");
                    String SrcAddress = PacketItems[0];
                    String DestAddress = PacketItems[1];
                    for(String[] ACLItem: ACLList){
                        if(CheckNetAddress(SrcAddress, ACLItem[0]).equals("Matched"))
                        {
                            System.out.println(PacketLine + ",  " + ACLItem[1]);
                            break;
                        }
                    }
                }
            }
        }
        catch(Exception e){
            System.out.println(e.getMessage());
        }
        System.out.println("******* PERFORMING EXTENDED ACL*********");
        try (BufferedReader br = new BufferedReader(new FileReader(ExACL)))
        {
            while((ACLLine = br.readLine()) != null)
            {
                if(ACLLine.contains("access-list")){
                    if(ACLLine.contains("any")){
                        ACLLine = ACLLine.replace("any", "0.0.0.0 255.255.255.255");
                    }
                    String[] ACLItems = ACLLine.split(" ");
                    PermissionType = ACLItems[2];
                    srcIPAddress = ACLItems[4];
                    srcMask = ACLItems[5];
                    destIPAddress = ACLItems[6];
                    destMask = ACLItems[7];
                    String[] IPItems = srcIPAddress.split("\\.");
                    String[] MaskItems = srcMask.split("\\.");
                    String srcMaskedString = "", destMaskedString = "";
                    for(int count = 0; count < IPItems.length; count++){
                        int MaskValue = Integer.parseInt(IPItems[count]) | Integer.parseInt(MaskItems[count]);
                        if(count != IPItems.length - 1)
                            srcMaskedString = srcMaskedString + MaskValue + ".";
                        else
                            srcMaskedString = srcMaskedString + MaskValue;
                    }
                    IPItems = destIPAddress.split("\\.");
                    MaskItems = destMask.split("\\.");
                    for(int count = 0; count < IPItems.length; count++){
                        int MaskValue = Integer.parseInt(IPItems[count]) | Integer.parseInt(MaskItems[count]);
                        if(count != IPItems.length - 1)
                            destMaskedString = destMaskedString + MaskValue + ".";
                        else
                            destMaskedString = destMaskedString + MaskValue;
                    }
                    ACLList.add(new String[]{srcMaskedString, destMaskedString, PermissionType});
                }
            }
            try(BufferedReader br1 = new BufferedReader(new FileReader(Packets))){
                while((PacketLine = br1.readLine()) != null){
                    String[] PacketItems = PacketLine.split(" ");
                    String SrcAddress = PacketItems[0];
                    String DestAddress = PacketItems[1];
                    for(String[] ACLItem: ACLList){
                        if(CheckNetAddress(SrcAddress, ACLItem[0]).equals("Matched") && CheckNetAddress(DestAddress, ACLItem[1]).equals("Matched"))
                        {
                            System.out.println(PacketLine + ",  " + ACLItem[2]);
                            break;
                        }
                    }
                }
            }
            
        }
        catch(Exception e){
            System.out.println(e.getMessage());
        }
    }
    public static String CheckNetAddress(String Input, String ToBeMatched)
    {
        if(!(ToBeMatched.contains("255")))
        {
            if(Input.equals(ToBeMatched))
                return "Matched";
        }
        else
        {
            String[] inputElements = Input.split("\\.");
            String[] ToBeMatchedElements = ToBeMatched.split("\\.");
            String MaskValue = "";
            for(int count = 0; count < inputElements.length; count++){
                int res = Integer.parseInt(inputElements[count]) & Integer.parseInt(ToBeMatchedElements[count]);
                if(count != inputElements.length - 1)
                        MaskValue = MaskValue + res + ".";
                else
                {
                    MaskValue = MaskValue + res;
                }
            }
            if(MaskValue.equals(Input))
                return "Matched";
        }
        return "Unmatched";
    }
}