import { AddCustomAttributes } from "./addCustomAttributes";
import { AdminAddUserToGroup } from "./adminAddUserToGroup";
import { AdminConfirmSignUp } from "./adminConfirmSignUp";
import { AdminCreateUser } from "./adminCreateUser";
import { AdminDeleteUser } from "./adminDeleteUser";
import { AdminDeleteUserAttributes } from "./adminDeleteUserAttributes";
import { AdminDisableUser } from "./adminDisableUser";
import { AdminEnableUser } from "./adminEnableUser";
import { AdminGetUser } from "./adminGetUser";
import { AdminInitiateAuth } from "./adminInitiateAuth";
import { AdminListGroupsForUser } from "./adminListGroupsForUser";
import { AdminRemoveUserFromGroup } from "./adminRemoveUserFromGroup";
import { AdminRespondToAuthChallenge } from "./adminRespondToAuthChallenge";
import { AdminSetUserMFAPreference } from "./adminSetUserMFAPreference";
import { AdminSetUserPassword } from "./adminSetUserPassword";
import { AdminUpdateUserAttributes } from "./adminUpdateUserAttributes";
import { AdminUserGlobalSignOut } from "./adminUserGlobalSignOut";
import { AssociateSoftwareToken } from "./associateSoftwareToken";
import { ChangePassword } from "./changePassword";
import { CompleteWebAuthnRegistration } from "./completeWebAuthnRegistration";
import { ConfirmForgotPassword } from "./confirmForgotPassword";
import { ConfirmSignUp } from "./confirmSignUp";
import { CreateGroup } from "./createGroup";
import { CreateResourceServer } from "./createResourceServer";
import { CreateUserPool } from "./createUserPool";
import { CreateUserPoolClient } from "./createUserPoolClient";
import { DeleteGroup } from "./deleteGroup";
import { DeleteUser } from "./deleteUser";
import { DeleteUserAttributes } from "./deleteUserAttributes";
import { DeleteUserPool } from "./deleteUserPool";
import { DeleteUserPoolClient } from "./deleteUserPoolClient";
import { DeleteWebAuthnCredential } from "./deleteWebAuthnCredential";
import { DescribeUserPool } from "./describeUserPool";
import { DescribeUserPoolClient } from "./describeUserPoolClient";
import { ForgotPassword } from "./forgotPassword";
import { GetGroup } from "./getGroup";
import { GetUser } from "./getUser";
import { GetUserAttributeVerificationCode } from "./getUserAttributeVerificationCode";
import { GetUserPoolMfaConfig } from "./getUserPoolMfaConfig";
import { GlobalSignOut } from "./globalSignOut";
import { InitiateAuth } from "./initiateAuth";
import { ListGroups } from "./listGroups";
import { ListUserPoolClients } from "./listUserPoolClients";
import { ListUserPools } from "./listUserPools";
import { ListUsers } from "./listUsers";
import { ListUsersInGroup } from "./listUsersInGroup";
import { ListWebAuthnCredentials } from "./listWebAuthnCredentials";
import { RespondToAuthChallenge } from "./respondToAuthChallenge";
import { RevokeToken } from "./revokeToken";
import { SetUserMFAPreference } from "./setUserMFAPreference";
import { SetUserPoolMfaConfig } from "./setUserPoolMfaConfig";
import { SignUp } from "./signUp";
import { StartWebAuthnRegistration } from "./startWebAuthnRegistration";
import { UpdateGroup } from "./updateGroup";
import { UpdateUserAttributes } from "./updateUserAttributes";
import { UpdateUserPool } from "./updateUserPool";
import { UpdateUserPoolClient } from "./updateUserPoolClient";
import { VerifySoftwareToken } from "./verifySoftwareToken";
import { VerifyUserAttribute } from "./verifyUserAttribute";

export const Targets = {
  AddCustomAttributes,
  AssociateSoftwareToken,
  AdminAddUserToGroup,
  AdminConfirmSignUp,
  AdminCreateUser,
  AdminDeleteUser,
  AdminDeleteUserAttributes,
  AdminDisableUser,
  AdminEnableUser,
  AdminGetUser,
  AdminInitiateAuth,
  AdminListGroupsForUser,
  AdminRemoveUserFromGroup,
  AdminRespondToAuthChallenge,
  AdminSetUserMFAPreference,
  AdminSetUserPassword,
  AdminUpdateUserAttributes,
  AdminUserGlobalSignOut,
  ChangePassword,
  CompleteWebAuthnRegistration,
  ConfirmForgotPassword,
  ConfirmSignUp,
  CreateGroup,
  CreateResourceServer,
  CreateUserPool,
  CreateUserPoolClient,
  DeleteGroup,
  DeleteUser,
  DeleteUserAttributes,
  DeleteUserPool,
  DeleteUserPoolClient,
  DeleteWebAuthnCredential,
  DescribeUserPool,
  DescribeUserPoolClient,
  ForgotPassword,
  GetGroup,
  GetUser,
  GetUserAttributeVerificationCode,
  GetUserPoolMfaConfig,
  GlobalSignOut,
  InitiateAuth,
  ListGroups,
  ListUserPoolClients,
  ListUserPools,
  ListUsers,
  ListUsersInGroup,
  ListWebAuthnCredentials,
  RespondToAuthChallenge,
  RevokeToken,
  SetUserMFAPreference,
  SetUserPoolMfaConfig,
  SignUp,
  StartWebAuthnRegistration,
  UpdateGroup,
  UpdateUserAttributes,
  UpdateUserPool,
  UpdateUserPoolClient,
  VerifySoftwareToken,
  VerifyUserAttribute,
} as const;
