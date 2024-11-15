/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/GUIForms/JFrame.java to edit this template
 */
package com.mycompany.passwordmanager;
import javax.swing.*;

/**
 *
 * @author Domantas & Nojus & 
 */
public class MainGUI extends javax.swing.JFrame {

    private PasswordManager passwordManager;
    private DefaultListModel<String> accountListModel;  // Model to hold account names for display
    
    /**
     * Creates new form MainGUI
     */
    public MainGUI(PasswordManager passwordManager) {
        this.passwordManager = passwordManager;
        accountListModel = new DefaultListModel<>();
        initComponents();
        setLocationRelativeTo(null);
         loadAccounts();
    }

    private void loadAccounts() {
        accountListModel.clear();
        for (String account : passwordManager.getAllAccounts().keySet()) {
            accountListModel.addElement(account);
        }
    }
    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        addPasswordBtn = new javax.swing.JButton();
        showPasswordBtn = new javax.swing.JButton();
        removePasswordBtn = new javax.swing.JButton();
        logOutBtn = new javax.swing.JButton();
        websiteList = new javax.swing.JScrollPane();
        jList1 = new javax.swing.JList<>(accountListModel);
        btnEdit = new javax.swing.JButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

        addPasswordBtn.setText("Add Password");
        addPasswordBtn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                addPasswordBtnActionPerformed(evt);
            }
        });

        showPasswordBtn.setText("Show Password");
        showPasswordBtn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                showPasswordBtnActionPerformed(evt);
            }
        });

        removePasswordBtn.setText("Delete Password");
        removePasswordBtn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                removePasswordBtnActionPerformed(evt);
            }
        });

        logOutBtn.setText("Log Out");
        logOutBtn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                logOutBtnActionPerformed(evt);
            }
        });

        websiteList.setViewportView(jList1);

        btnEdit.setText("Edit Password");
        btnEdit.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnEditActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(28, 28, 28)
                .addComponent(logOutBtn)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap(203, Short.MAX_VALUE)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addComponent(websiteList, javax.swing.GroupLayout.PREFERRED_SIZE, 234, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(155, 155, 155))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(showPasswordBtn, javax.swing.GroupLayout.PREFERRED_SIZE, 136, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(addPasswordBtn, javax.swing.GroupLayout.PREFERRED_SIZE, 136, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(removePasswordBtn, javax.swing.GroupLayout.PREFERRED_SIZE, 136, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(btnEdit, javax.swing.GroupLayout.PREFERRED_SIZE, 136, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addGap(211, 211, 211))))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(14, 14, 14)
                .addComponent(websiteList, javax.swing.GroupLayout.PREFERRED_SIZE, 197, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(addPasswordBtn)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(showPasswordBtn)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(btnEdit)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(removePasswordBtn)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(logOutBtn)
                .addContainerGap(23, Short.MAX_VALUE))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void addPasswordBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_addPasswordBtnActionPerformed
        // TODO add your handling code here:
        String account = JOptionPane.showInputDialog(this, "Enter Account Name:");
        String password = JOptionPane.showInputDialog(this, "Enter Password:");

        if (account != null && password != null && !account.isEmpty() && !password.isEmpty()) {
            try {
                passwordManager.storePassword(account, password);
                accountListModel.addElement(account);  // Add account to list
                JOptionPane.showMessageDialog(this, "Password stored successfully!");
            } catch (Exception e) {
                JOptionPane.showMessageDialog(this, "Error storing password: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }//GEN-LAST:event_addPasswordBtnActionPerformed

    private void showPasswordBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_showPasswordBtnActionPerformed
        // TODO add your handling code here:
         String selectedAccount = jList1.getSelectedValue();
        if (selectedAccount != null) {
            try {
                String password = passwordManager.retrievePassword(selectedAccount);
                if (password != null) {
                    JOptionPane.showMessageDialog(this, "Password for " + selectedAccount + ": " + password);
                } else {
                    JOptionPane.showMessageDialog(this, "No password found for " + selectedAccount);
                }
            } catch (Exception e) {
                JOptionPane.showMessageDialog(this, "Error retrieving password: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        } else {
            JOptionPane.showMessageDialog(this, "Please select an account from the list.");
        }
    }//GEN-LAST:event_showPasswordBtnActionPerformed

    private void logOutBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_logOutBtnActionPerformed
        // TODO add your handling code here:
        this.dispose(); // Close MainGUI

        // Open the LoginGUI window
        LoginGUI loginGUI = new LoginGUI();
        loginGUI.setVisible(true);
    }//GEN-LAST:event_logOutBtnActionPerformed

    private void removePasswordBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_removePasswordBtnActionPerformed
        // TODO add your handling code here:
        String selectedAccount = jList1.getSelectedValue();
        if (selectedAccount != null) {
            int confirm = JOptionPane.showConfirmDialog(this, "Are you sure you want to delete the password for " + selectedAccount + "?", "Confirm Delete", JOptionPane.YES_NO_OPTION);
            if (confirm == JOptionPane.YES_OPTION) {
                passwordManager.removePassword(selectedAccount);
                accountListModel.removeElement(selectedAccount);
                JOptionPane.showMessageDialog(this, "Password deleted successfully!");
            }
        } else {
            JOptionPane.showMessageDialog(this, "Please select an account from the list.");
        }
    }//GEN-LAST:event_removePasswordBtnActionPerformed

    private void btnEditActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnEditActionPerformed
        // TODO add your handling code here:
        String selectedAccount = jList1.getSelectedValue();
        if(selectedAccount != null){
            try{
                String currentPassword = JOptionPane.showInputDialog(this, "Enter current password for " + selectedAccount + ":");
                
                if(currentPassword != null && !currentPassword.isEmpty()){
                    String storedPassword = passwordManager.retrievePassword(selectedAccount);
                    
                    if(storedPassword != null && storedPassword.equals(currentPassword)){
                        String newPassword = JOptionPane.showInputDialog(this, "Enter new password for " + selectedAccount + ":");
                        
                        if(newPassword != null && !newPassword.isEmpty()){
                            passwordManager.storePassword(selectedAccount, newPassword);
                            JOptionPane.showMessageDialog(this, "Password updated successfully");
                        }else{
                            JOptionPane.showMessageDialog(this, "new password cannot be empty");
                        }
                    }else{
                        JOptionPane.showMessageDialog(this, "Incorrect password. Please try again");
                    }
                } else {
                    JOptionPane.showMessageDialog(this, "Password cannot be empty");
                }
            } catch(Exception e){
                JOptionPane.showMessageDialog(this, "Error updating password: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }else{
            JOptionPane.showMessageDialog(this, "Please select an account from the list");
        }
    }//GEN-LAST:event_btnEditActionPerformed

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(MainGUI.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(MainGUI.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(MainGUI.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(MainGUI.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        
        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                try {
                    PasswordManager manager = new PasswordManager("MyMasterPassword"); // Example password
                    new MainGUI(manager).setVisible(true);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton addPasswordBtn;
    private javax.swing.JButton btnEdit;
    private javax.swing.JList<String> jList1;
    private javax.swing.JButton logOutBtn;
    private javax.swing.JButton removePasswordBtn;
    private javax.swing.JButton showPasswordBtn;
    private javax.swing.JScrollPane websiteList;
    // End of variables declaration//GEN-END:variables
}
